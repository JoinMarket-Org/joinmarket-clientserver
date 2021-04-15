#!/usr/bin/env python3
"""A simple command line tool to create a bunch
of utxos from one (thus giving more potential commitments
for a Joinmarket user, although of course it may be useful
for other reasons).
"""

from optparse import OptionParser
import jmbitcoin as btc
from jmbase import (get_log, jmprint, bintohex, utxostr_to_utxo,
                    IndentedHelpFormatterWithNL)
from jmclient import load_program_config, estimate_tx_fee, jm_single,\
    validate_address, get_utxo_info, add_base_options,\
    validate_utxo_data, quit, BTCEngine, compute_tx_locktime

log = get_log()

def sign(utxo, priv, destaddrs, utxo_address_type):
    """Sign a tx sending the amount amt, from utxo utxo,
    equally to each of addresses in list destaddrs,
    after fees; the purpose is to create multiple utxos.
    utxo_address_type must be one of p2sh-p2wpkh/p2wpkh/p2pkh.
    """
    results = validate_utxo_data([(utxo, priv)], retrieve=True,
                                 utxo_address_type=utxo_address_type)
    if not results:
        return False
    assert results[0][0] == utxo
    amt = results[0][1]
    ins = [utxo]
    estfee = estimate_tx_fee(1, len(destaddrs), txtype=utxo_address_type)
    outs = []
    share = int((amt - estfee) / len(destaddrs))
    fee = amt - share*len(destaddrs)
    assert fee >= estfee
    log.info("Using fee: " + str(fee))
    for i, addr in enumerate(destaddrs):
        outs.append({'address': addr, 'value': share})
    tx = btc.make_shuffled_tx(ins, outs, version=2, locktime=compute_tx_locktime())
    amtforsign = amt if utxo_address_type != "p2pkh" else None
    rawpriv, _ = BTCEngine.wif_to_privkey(priv)
    if utxo_address_type == "p2wpkh":
        native = utxo_address_type
    else:
        native = False
    success, msg = btc.sign(tx, 0, rawpriv, amount=amtforsign, native=native)
    assert success, msg
    return tx

description="""For creating multiple utxos from one (for commitments in JM).
Provide a utxo in form txid:N that has some unspent coins;
Specify a list of destination addresses and the coins will
be split equally between them (after bitcoin fees).
You'll be prompted to enter the private key for the utxo
during the run; it must be in WIF compressed format.
After the transaction is completed, the utxo strings for
the new outputs will be shown.
Note that these utxos will not be ready for use as external
commitments in Joinmarket until 5 confirmations have passed.
BE CAREFUL about handling private keys!
Don't do this in insecure environments.
Works only with p2pkh ('1'), p2sh-p2wpkh (segwit '3') or
p2wpkh ('bc1') addresses.
utxos - set segwit=False in the POLICY section of
joinmarket.cfg for the former."""

def main():
    parser = OptionParser(
        usage=
        'usage: %prog [options] utxo destaddr1 destaddr2 ..',
        description=description, formatter=IndentedHelpFormatterWithNL())
    parser.add_option(
        '-t',
        '--utxo-address-type',
        action='store',
        dest='utxo_address_type',
        help=('type of address of coin being spent - one of "p2pkh", "p2wpkh", "p2sh-p2wpkh". '
        'No other scriptpubkey types (e.g. multisig) are supported. If not set, we default '
        'to what is in joinmarket.cfg.'),
        default=""
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
    success, utxo = utxostr_to_utxo(u)
    if not success:
        quit(parser, "Failed to load utxo from string: " + utxo)
    if options.utxo_address_type == "":
        if jm_single().config.get("POLICY", "segwit") == "false":
            utxo_address_type = "p2pkh"
        elif jm_single().config.get("POLICY", "native") == "false":
            utxo_address_type = "p2sh-p2wpkh"
        else:
            utxo_address_type = "p2wpkh"
    else:
        utxo_address_type = options.utxo_address_type
    txsigned = sign(utxo, priv, destaddrs, utxo_address_type)
    if not txsigned:
        log.info("Transaction signing operation failed, see debug messages for details.")
        return
    log.info("Got signed transaction:\n" + bintohex(txsigned.serialize()))
    log.info(btc.human_readable_transaction(txsigned))
    if input('Would you like to push to the network? (y/n):')[0] != 'y':
        log.info("You chose not to broadcast the transaction, quitting.")
        return
    jm_single().bc_interface.pushtx(txsigned.serialize())

if __name__ == "__main__":
    main()
    jmprint('done', "success")
