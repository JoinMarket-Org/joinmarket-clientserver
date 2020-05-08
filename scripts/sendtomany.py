#!/usr/bin/env python3
"""A simple command line tool to create a bunch
of utxos from one (thus giving more potential commitments
for a Joinmarket user, although of course it may be useful
for other reasons).
"""

from pprint import pformat
from optparse import OptionParser
import jmbitcoin as btc
from jmbase import get_log, jmprint
from jmclient import load_program_config, estimate_tx_fee, jm_single,\
    get_p2pk_vbyte, validate_address, get_utxo_info, add_base_options,\
    validate_utxo_data, quit


log = get_log()

def sign(utxo, priv, destaddrs, segwit=True):
    """Sign a tx sending the amount amt, from utxo utxo,
    equally to each of addresses in list destaddrs,
    after fees; the purpose is to create a large
    number of utxos. If segwit=True the (single) utxo is assumed to
    be of type segwit p2sh/p2wpkh.
    """
    results = validate_utxo_data([(utxo, priv)], retrieve=True, segwit=segwit)
    if not results:
        return False
    assert results[0][0] == utxo
    amt = results[0][1]
    ins = [utxo]
    # TODO extend to other utxo types
    txtype = 'p2sh-p2wpkh' if segwit else 'p2pkh'
    estfee = estimate_tx_fee(1, len(destaddrs), txtype=txtype)
    outs = []
    share = int((amt - estfee) / len(destaddrs))
    fee = amt - share*len(destaddrs)
    assert fee >= estfee
    log.info("Using fee: " + str(fee))
    for i, addr in enumerate(destaddrs):
        outs.append({'address': addr, 'value': share})
    unsigned_tx = btc.mktx(ins, outs)
    amtforsign = amt if segwit else None
    return btc.sign(unsigned_tx, 0, btc.from_wif_privkey(
        priv, vbyte=get_p2pk_vbyte()), amount=amtforsign)
    
def main():
    parser = OptionParser(
        usage=
        'usage: %prog [options] utxo destaddr1 destaddr2 ..',
        description="For creating multiple utxos from one (for commitments in JM)."
                    "Provide a utxo in form txid:N that has some unspent coins;"
                    "Specify a list of destination addresses and the coins will"
                    "be split equally between them (after bitcoin fees)."

                    "You'll be prompted to enter the private key for the utxo"
                    "during the run; it must be in WIF compressed format."
                    "After the transaction is completed, the utxo strings for"

                    "the new outputs will be shown."
                    "Note that these utxos will not be ready for use as external"

                    "commitments in Joinmarket until 5 confirmations have passed."
                    " BE CAREFUL about handling private keys!"
                    " Don't do this in insecure environments."
                    " Works only with p2pkh ('1') or p2sh-p2wpkh (segwit '3')"
                    " utxos - set segwit=False in the POLICY section of"
                    " joinmarket.cfg for the former."
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
    parser.add_option(
        '-n',
        '--non-segwit-input',
        action='store_true',
        dest='nonsegwit',
        help='input is p2pkh ("1" address), not segwit; if not used, input is assumed to be segwit type.',
        default=False
    )
    add_base_options(parser)
    (options, args) = parser.parse_args()
    load_program_config(config_path=options.datadir)
    if len(args) < 2:
        quit(parser, 'Invalid syntax')
    u = args[0]
    priv = input(
        'input private key for ' + u + ', in WIF compressed format : ')
    u, priv = get_utxo_info(','.join([u, priv]))
    if not u:
        quit(parser, "Failed to parse utxo info: " + u)
    destaddrs = args[1:]
    for d in destaddrs:
        if not validate_address(d):
            quit(parser, "Address was not valid; wrong network?: " + d)
    txsigned = sign(u, priv, destaddrs, segwit = not options.nonsegwit)
    if not txsigned:
        log.info("Transaction signing operation failed, see debug messages for details.")
        return
    log.debug("Got signed transaction:\n" + txsigned)
    log.debug("Deserialized:")
    log.debug(pformat(btc.deserialize(txsigned)))
    if input('Would you like to push to the network? (y/n):')[0] != 'y':
        log.info("You chose not to broadcast the transaction, quitting.")
        return
    jm_single().bc_interface.pushtx(txsigned)

if __name__ == "__main__":
    main()
    jmprint('done', "success")
