#!/usr/bin/env python3

description="""Make fake SNICKER transactions to aid discovery.

Use this script to send money to yourself in a transaction which
fits the format of SNICKER v1 (so it will have two equal sized
outputs and a change output, also obeying the other minor rules
for SNICKER).

Having done this your transaction will be picked up by blockchain
scanners looking for the SNICKER "fingerprint", allowing them
to propose coinjoins with your coins.

The transaction is generated with at least TWO utxos from your chosen
 source mixdepth/account (-m), so it must contain at least two.
The reason for using one account, not two, is to prevent violating
the principle of not co-spending from different accounts; even though
this is a simulated coinjoin, it may be deducible that it is only really
a *signalling* fake coinjoin, so it is better not to violate the principle.
"""

import sys
import random
from optparse import OptionParser
from jmbase import BytesProducer, bintohex, jmprint, hextobin, \
     EXIT_ARGERROR, EXIT_FAILURE, EXIT_SUCCESS
import jmbitcoin as btc
from jmclient import (RegtestBitcoinCoreInterface, process_shutdown,
                      jm_single, load_program_config, check_regtest, select_one_utxo,
                      estimate_tx_fee, SNICKERReceiver, add_base_options, get_wallet_path,
                      open_test_wallet_maybe, WalletService, SNICKERClientProtocolFactory,
                      start_reactor, JMPluginService)
from jmclient.support import select_greedy, NotEnoughFundsException
from jmclient.configure import get_log

log = get_log()

def main():
    parser = OptionParser(
        usage=
        'usage: %prog [options] walletname',
        description=description
    )
    add_base_options(parser)
    parser.add_option('-m',
                      '--mixdepth',
                      action='store',
                      type='int',
                      dest='mixdepth',
                      help='mixdepth/account, default 0',
                      default=0)
    parser.add_option(
        '-g',
        '--gap-limit',
        action='store',
        type='int',
        dest='gaplimit',
        default = 6,
        help='gap limit for Joinmarket wallet, default 6.'
    )
    parser.add_option(
        '-f',
        '--txfee',
        action='store',
        type='int',
        dest='txfee',
        default=-1,
        help='Bitcoin miner tx_fee to use for transaction(s). A number higher '
        'than 1000 is used as "satoshi per KB" tx fee. A number lower than that '
        'uses the dynamic fee estimation of your blockchain provider as '
        'confirmation target. This temporarily overrides the "tx_fees" setting '
        'in your joinmarket.cfg. Works the same way as described in it. Check '
        'it for examples.')
    parser.add_option('-a',
                      '--amtmixdepths',
                      action='store',
                      type='int',
                      dest='amtmixdepths',
                      help='number of mixdepths in wallet, default 5',
                      default=5)
    parser.add_option('-N',
                      '--net-transfer',
                      action='store',
                      type='int',
                      dest='net_transfer',
                      help='how many sats are sent to the "receiver", default randomised.',
                      default=-1000001)
    (options, args) = parser.parse_args()
    snicker_plugin = JMPluginService("SNICKER")
    load_program_config(config_path=options.datadir,
                        plugin_services=[snicker_plugin])
    if len(args) != 1:
        log.error("Invalid arguments, see --help")
        sys.exit(EXIT_ARGERROR)
    wallet_name = args[0]
    check_regtest()
    # If tx_fees are set manually by CLI argument, override joinmarket.cfg:
    if int(options.txfee) > 0:
        jm_single().config.set("POLICY", "tx_fees", str(options.txfee))
    max_mix_depth = max([options.mixdepth, options.amtmixdepths - 1])
    wallet_path = get_wallet_path(wallet_name, None)
    wallet = open_test_wallet_maybe(
        wallet_path, wallet_name, max_mix_depth,
        wallet_password_stdin=options.wallet_password_stdin,
        gap_limit=options.gaplimit)
    wallet_service = WalletService(wallet)
    if wallet_service.rpc_error:
        sys.exit(EXIT_FAILURE)
    snicker_plugin.start_plugin_logging(wallet_service)
    # in this script, we need the wallet synced before
    # logic processing for some paths, so do it now:
    while not wallet_service.synced:
        wallet_service.sync_wallet(fast=not options.recoversync)
    # the sync call here will now be a no-op:
    wallet_service.startService()
    fee_est = estimate_tx_fee(2, 3, txtype=wallet_service.get_txtype())

    # first, order the utxos in the mixepth by size. Then (this is the
    # simplest algorithm; we could be more sophisticated), choose the
    # *second* largest utxo as the receiver utxo; this ensures that we
    # have enough for the proposer to cover. We consume utxos greedily,
    # meaning we'll at least some of the time, be consolidating.
    utxo_dict = wallet_service.get_utxos_by_mixdepth()[options.mixdepth]
    if not len(utxo_dict) >= 2:
        log.error("Cannot create fake SNICKER tx without at least two utxos, quitting")
        sys.exit(EXIT_ARGERROR)
    # sort utxos by size
    sorted_utxos = sorted(list(utxo_dict.keys()),
                          key=lambda k: utxo_dict[k]['value'],
                          reverse=True) 
    # receiver is the second largest:
    receiver_utxo = sorted_utxos[1]
    receiver_utxo_val = utxo_dict[receiver_utxo]
    # gather the other utxos into a list to select from:
    nonreceiver_utxos = [sorted_utxos[0]] + sorted_utxos[2:]
    # get the net transfer in our fake coinjoin:
    if options.net_transfer < -1000001:
        log.error("Net transfer must be greater than negative 1M sats")
        sys.exit(EXIT_ARGERROR)
    if options.net_transfer == -1000001:
        # default; low-ish is more realistic and avoids problems
        # with dusty utxos
        options.net_transfer = random.randint(-1000, 1000)

    # select enough to cover: receiver value + fee + transfer + breathing room
    # we select relatively greedily to support consolidation, since
    # this transaction does not pretend to isolate the coins.
    try:
        available = [{'utxo': utxo, 'value': utxo_dict[utxo]["value"]}
                     for utxo in nonreceiver_utxos]
        # selection algos return [{"utxo":..,"value":..}]:
        prop_utxos = {x["utxo"] for x in select_greedy(available,
        receiver_utxo_val["value"] + fee_est + options.net_transfer + 1000)}
        prop_utxos = list(prop_utxos)
        prop_utxo_vals = [utxo_dict[prop_utxo] for prop_utxo in prop_utxos]
    except NotEnoughFundsException as e:
        log.error(repr(e))
        sys.exit(EXIT_FAILURE)

    # Due to the fake nature of this transaction, and its distinguishability
    # (not only in trivial output pattern, but also in subset-sum), there
    # is little advantage in making it use different output mixdepths, so
    # here to prevent fragmentation, everything is kept in the same mixdepth.
    receiver_addr, proposer_addr, change_addr = (wallet_service.script_to_addr(
        wallet_service.get_new_script(options.mixdepth, 1)) for _ in range(3))
    # persist index update:
    wallet_service.save_wallet()
    outputs = btc.construct_snicker_outputs(
        sum([x["value"] for x in prop_utxo_vals]),
        receiver_utxo_val["value"],
        receiver_addr,
        proposer_addr,
        change_addr,
        fee_est,
        options.net_transfer)
    tx = btc.make_shuffled_tx(prop_utxos + [receiver_utxo],
                              outputs,
                              version=2,
                              locktime=0)
    # before signing, check we satisfied the criteria, otherwise
    # this is pointless!
    if not btc.is_snicker_tx(tx):
        log.error("Code error, created non-SNICKER tx, not signing.")
        sys.exit(EXIT_FAILURE)

    # sign all inputs
    # scripts: {input_index: (output_script, amount)}
    our_inputs = {}
    for index, ins in enumerate(tx.vin):
        utxo = (ins.prevout.hash[::-1], ins.prevout.n)
        script = utxo_dict[utxo]['script']
        amount = utxo_dict[utxo]['value']
        our_inputs[index] = (script, amount)    
    success, msg = wallet_service.sign_tx(tx, our_inputs)
    if not success:
        log.error("Failed to sign transaction: " + msg)
        sys.exit(EXIT_FAILURE)
    # TODO condition on automatic brdcst or not
    if not jm_single().bc_interface.pushtx(tx.serialize()):
        # this represents an error about state (or conceivably,
        # an ultra-short window in which the spent utxo was
        # consumed in another transaction), but not really
        # an internal logic error, so we do NOT return False
        log.error("Failed to broadcast fake SNICKER coinjoin: " +\
                   bintohex(tx.GetTxid()[::-1]))
        log.info(btc.human_readable_transaction(tx))
        sys.exit(EXIT_FAILURE)
    log.info("Successfully broadcast fake SNICKER coinjoin: " +\
              bintohex(tx.GetTxid()[::-1]))

if __name__ == "__main__":
    main()
    jmprint('done', "success")
