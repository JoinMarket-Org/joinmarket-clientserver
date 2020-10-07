#!/usr/bin/env python3
from future.utils import iteritems
"""A very simple command line tool to import utxos to be used
as commitments into joinmarket's commitments.json file, allowing
users to retry transactions more often without getting banned by
the anti-snooping feature employed by makers.
"""

import sys
import os
import json
import binascii
from pprint import pformat
from optparse import OptionParser

from jmclient import load_program_config, jm_single,\
    open_wallet, WalletService, add_external_commitments, update_commitments,\
    PoDLE, get_podle_commitments, get_utxo_info, validate_utxo_data, quit,\
    get_wallet_path, add_base_options, BTCEngine, BTC_P2SH_P2WPKH
from jmbase.support import EXIT_SUCCESS, EXIT_FAILURE, EXIT_ARGERROR, jmprint


def add_ext_commitments(utxo_datas):
    """Persist the PoDLE commitments for this utxo
    to the commitments.json file. The number of separate
    entries is dependent on the taker_utxo_retries entry, by
    default 3.
    """
    def generate_single_podle_sig(u, priv, i):
        """Make a podle entry for key priv at index i, using a dummy utxo value.
        This calls the underlying 'raw' code based on the class PoDLE, not the
        library 'generate_podle' which intelligently searches and updates commitments.
        """
        # Convert priv from wif; note that wallet type
        # isn't relevant since we only work with pubkeys in PoDLE:
        rawpriv, _ = BTCEngine.wif_to_privkey(priv)
        podle = PoDLE(u, rawpriv)
        r = podle.generate_podle(i)
        return (r['P'], r['P2'], r['sig'],
                r['e'], r['commit'])
    ecs = {}
    for u, priv in utxo_datas:
        ecs[u] = {}
        ecs[u]['reveal']={}
        for j in range(jm_single().config.getint("POLICY", "taker_utxo_retries")):
            P, P2, s, e, commit = generate_single_podle_sig(u, priv, j)
            if 'P' not in ecs[u]:
                ecs[u]['P']=P
            ecs[u]['reveal'][j] = {'P2':P2, 's':s, 'e':e}
        add_external_commitments(ecs)

def main():
    parser = OptionParser(
        usage=
        'usage: %prog [options] [txid:n]',
        description="Adds one or more utxos to the list that can be used to make "
                    "commitments for anti-snooping. Note that this utxo, and its "
                    "PUBkey, will be revealed to makers, so consider the privacy "
                    "implication. "
                    
                    "It may be useful to those who are having trouble making "
                    "coinjoins due to several unsuccessful attempts (especially "
                    "if your joinmarket wallet is new). "
                    
                    "'Utxo' means unspent transaction output, it must not "
                    "already be spent. "
                    "The options -w, -r and -R offer ways to load these utxos "
                    "from a file or wallet. "
                    "If you enter a single utxo without these options, you will be "
                    "prompted to enter the private key here - it must be in "
                    "WIF compressed format. "

                    "BE CAREFUL about handling private keys! "
                    "Don't do this in insecure environments. "
                    
                    "Also note this ONLY works for standard (p2pkh or p2sh-p2wpkh) utxos."
    )
    add_base_options(parser)
    parser.add_option(
        '-r',
        '--read-from-file',
        action='store',
        type='str',
        dest='in_file',
        help='name of plain text csv file containing utxos, one per line, format: '
        'txid:N, WIF-compressed-privkey'
    )
    parser.add_option(
        '-R',
        '--read-from-json',
        action='store',
        type='str',
        dest='in_json',
        help='name of json formatted file containing utxos with private keys, as '
        'output from "python wallet-tool.py -p walletname showutxos"'
        )
    parser.add_option(
        '-w',
        '--load-wallet',
        action='store',
        type='str',
        dest='loadwallet',
        help='name of wallet from which to load utxos and use as commitments.'
        )
    parser.add_option(
        '-g',
        '--gap-limit',
        action='store',
        type='int',
        dest='gaplimit',
        default = 6,
        help='Only to be used with -w; gap limit for Joinmarket wallet, default 6.'
    )
    parser.add_option(
        '-M',
        '--max-mixdepth',
        action='store',
        type='int',
        dest='maxmixdepth',
        default=5,
        help='Only to be used with -w; number of mixdepths for wallet, default 5.'
    )
    parser.add_option(
        '-d',
        '--delete-external',
        action='store_true',
        dest='delete_ext',
        help='deletes the current list of external commitment utxos',
        default=False
        )
    parser.add_option(
        '-v',
        '--validate-utxos',
        action='store_true',
        dest='validate',
        help='validate the utxos and pubkeys provided against the blockchain',
        default=False
    )
    parser.add_option(
        '-o',
        '--validate-only',
        action='store_true',
        dest='vonly',
        help='only validate the provided utxos (file or command line), not add',
        default=False
    )
    (options, args) = parser.parse_args()
    load_program_config(config_path=options.datadir)
    #TODO; sort out "commit file location" global so this script can
    #run without this hardcoding:
    utxo_data = []
    if options.delete_ext:
        other = options.in_file or options.in_json or options.loadwallet
        if len(args) > 0 or other:
            if input("You have chosen to delete commitments, other arguments "
                         "will be ignored; continue? (y/n)") != 'y':
                jmprint("Quitting", "warning")
                sys.exit(EXIT_SUCCESS)
        c, e = get_podle_commitments()
        jmprint(pformat(e), "info")
        if input(
            "You will remove the above commitments; are you sure? (y/n): ") != 'y':
            jmprint("Quitting", "warning")
            sys.exit(EXIT_SUCCESS)
        update_commitments(external_to_remove=e)
        jmprint("Commitments deleted.", "important")
        sys.exit(EXIT_SUCCESS)

    #Three options (-w, -r, -R) for loading utxo and privkey pairs from a wallet,
    #csv file or json file.
    if options.loadwallet:
        wallet_path = get_wallet_path(options.loadwallet)
        wallet = open_wallet(wallet_path, gap_limit=options.gaplimit)
        wallet_service = WalletService(wallet)
        if wallet_service.rpc_error:
            sys.exit(EXIT_FAILURE)
        while True:
            if wallet_service.sync_wallet(fast=not options.recoversync):
                break

        # minor note: adding a utxo from an external wallet for commitments, we
        # default to not allowing disabled utxos to avoid a privacy leak, so the
        # user would have to explicitly enable.
        for md, utxos in wallet_service.get_utxos_by_mixdepth(hexfmt=False).items():
            for (txid, index), utxo in utxos.items():
                txhex = binascii.hexlify(txid).decode('ascii') + ':' + str(index)
                wif = wallet_service.get_wif_path(utxo['path'])
                utxo_data.append((txhex, wif))

    elif options.in_file:
        with open(options.in_file, "rb") as f:
            utxo_info = f.readlines()
        for ul in utxo_info:
            ul = ul.rstrip()
            if ul:
                u, priv = get_utxo_info(ul)
                if not u:
                    quit(parser, "Failed to parse utxo info: " + str(ul))
                utxo_data.append((u, priv))
    elif options.in_json:
        if not os.path.isfile(options.in_json):
            jmprint("File: " + options.in_json + " not found.", "error")
            sys.exit(EXIT_FAILURE)
        with open(options.in_json, "rb") as f:
            try:
                utxo_json = json.loads(f.read())
            except:
                jmprint("Failed to read json from " + options.in_json, "error")
                sys.exit(EXIT_FAILURE)
        for u, pva in iteritems(utxo_json):
            utxo_data.append((u, pva['privkey']))
    elif len(args) == 1:
        u = args[0]
        priv = input(
            'input private key for ' + u + ', in WIF compressed format : ')
        u, priv = get_utxo_info(','.join([u, priv]))
        if not u:
            quit(parser, "Failed to parse utxo info: " + u)
        utxo_data.append((u, priv))
    else:
        quit(parser, 'Invalid syntax')
    if options.validate or options.vonly:
        sw = False if jm_single().config.get("POLICY", "segwit") == "false" else True
        if not validate_utxo_data(utxo_data, segwit=sw):
            quit(parser, "Utxos did not validate, quitting")
    if options.vonly:
        sys.exit(EXIT_ARGERROR)
    
    #We are adding utxos to the external list
    assert len(utxo_data)
    add_ext_commitments(utxo_data)

if __name__ == "__main__":
    main()
    jmprint('done', "success")
