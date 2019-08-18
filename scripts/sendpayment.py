#! /usr/bin/env python
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401

"""
A sample implementation of a single coinjoin script,
adapted from `sendpayment.py` in Joinmarket-Org/joinmarket.
For notes, see scripts/README.md; in particular, note the use
of "schedules" with the -S flag.
"""

import sys
from twisted.internet import reactor
import pprint

from jmclient import Taker, P2EPTaker, load_program_config, get_schedule,\
    JMClientProtocolFactory, start_reactor, validate_address, jm_single,\
    sync_wallet, estimate_tx_fee, direct_send,\
    open_test_wallet_maybe, get_wallet_path
from twisted.python.log import startLogging
from jmbase.support import get_log, set_logging_level, jmprint
from cli_options import get_sendpayment_parser, get_max_cj_fee_values, \
     check_regtest

log = get_log()

#CLI specific, so relocated here (not used by tumbler)
def pick_order(orders, n): #pragma: no cover
    jmprint("Considered orders:", "info")
    for i, o in enumerate(orders):
        jmprint("    %2d. %20s, CJ fee: %6s, tx fee: %6d" %
              (i, o[0]['counterparty'], str(o[0]['cjfee']), o[0]['txfee']), "info")
    pickedOrderIndex = -1
    if i == 0:
        jmprint("Only one possible pick, picking it.", "info")
        return orders[0]
    while pickedOrderIndex == -1:
        try:
            pickedOrderIndex = int(input('Pick an order between 0 and ' +
                                             str(i) + ': '))
        except ValueError:
            pickedOrderIndex = -1
            continue

        if 0 <= pickedOrderIndex < len(orders):
            return orders[pickedOrderIndex]
        pickedOrderIndex = -1

def main():
    parser = get_sendpayment_parser()
    (options, args) = parser.parse_args()
    load_program_config()
    if options.p2ep and len(args) != 3:
        parser.error("PayJoin requires exactly three arguments: "
                     "wallet, amount and destination address.")
        sys.exit(0)
    elif options.schedule == '' and len(args) != 3:
        parser.error("Joinmarket sendpayment (coinjoin) needs arguments:"
        " wallet, amount and destination address")
        sys.exit(0)

    #without schedule file option, use the arguments to create a schedule
    #of a single transaction
    sweeping = False
    if options.schedule == '':
        #note that sendpayment doesn't support fractional amounts, fractions throw
        #here.
        amount = int(args[1])
        if amount == 0:
            sweeping = True
        destaddr = args[2]
        mixdepth = options.mixdepth
        addr_valid, errormsg = validate_address(destaddr)
        if not addr_valid:
            jmprint('ERROR: Address invalid. ' + errormsg, "error")
            return
        schedule = [[options.mixdepth, amount, options.makercount,
                     destaddr, 0.0, 0]]
    else:
        if options.p2ep:
            parser.error("Schedule files are not compatible with PayJoin")
            sys.exit(0)
        result, schedule = get_schedule(options.schedule)
        if not result:
            log.error("Failed to load schedule file, quitting. Check the syntax.")
            log.error("Error was: " + str(schedule))
            sys.exit(0)
        mixdepth = 0
        for s in schedule:
            if s[1] == 0:
                sweeping = True
            #only used for checking the maximum mixdepth required
            mixdepth = max([mixdepth, s[0]])

    wallet_name = args[0]

    check_regtest()

    if options.pickorders:
        chooseOrdersFunc = pick_order
        if sweeping:
            jmprint('WARNING: You may have to pick offers multiple times', "warning")
            jmprint('WARNING: due to manual offer picking while sweeping', "warning")
    else:
        chooseOrdersFunc = options.order_choose_fn

    # Dynamically estimate a realistic fee if it currently is the default value.
    # At this point we do not know even the number of our own inputs, so
    # we guess conservatively with 2 inputs and 2 outputs each.
    if options.txfee == -1:
        options.txfee = max(options.txfee, estimate_tx_fee(2, 2,
                                        txtype="p2sh-p2wpkh"))
        log.debug("Estimated miner/tx fee for each cj participant: " + str(
            options.txfee))
    assert (options.txfee >= 0)

    # From the estimated tx fees, check if the expected amount is a
    # significant value compared the the cj amount
    exp_tx_fees_ratio = ((1 + options.makercount) * options.txfee) / amount
    if exp_tx_fees_ratio > 0.05:
        jmprint('WARNING: Expected bitcoin network miner fees for this coinjoin'
            ' amount are roughly {:.1%}'.format(exp_tx_fees_ratio), "warning")
    else:
        log.info("Estimated miner/tx fees for this coinjoin amount: {:.1%}"
            .format(exp_tx_fees_ratio))


    maxcjfee = (1, float('inf'))
    if not options.p2ep and not options.pickorders and options.makercount != 0:
        maxcjfee = get_max_cj_fee_values(jm_single().config, options)
        log.info("Using maximum coinjoin fee limits per maker of {:.4%}, {} "
                 "sat".format(*maxcjfee))

    log.debug('starting sendpayment')

    max_mix_depth = max([mixdepth, options.amtmixdepths - 1])

    wallet_path = get_wallet_path(wallet_name, None)
    wallet = open_test_wallet_maybe(
        wallet_path, wallet_name, max_mix_depth, gap_limit=options.gaplimit)

    if jm_single().config.get("BLOCKCHAIN",
        "blockchain_source") == "electrum-server" and options.makercount != 0:
        jm_single().bc_interface.synctype = "with-script"
    #wallet sync will now only occur on reactor start if we're joining.
    while not jm_single().bc_interface.wallet_synced:
        sync_wallet(wallet, fast=options.fastsync)
    if options.makercount == 0 and not options.p2ep:
        direct_send(wallet, amount, mixdepth, destaddr, options.answeryes)
        return

    if wallet.get_txtype() == 'p2pkh':
        jmprint("Only direct sends (use -N 0) are supported for "
              "legacy (non-segwit) wallets.", "error")
        return

    def filter_orders_callback(orders_fees, cjamount):
        orders, total_cj_fee = orders_fees
        log.info("Chose these orders: " +pprint.pformat(orders))
        log.info('total cj fee = ' + str(total_cj_fee))
        total_fee_pc = 1.0 * total_cj_fee / cjamount
        log.info('total coinjoin fee = ' + str(float('%.3g' % (
            100.0 * total_fee_pc))) + '%')
        WARNING_THRESHOLD = 0.02  # 2%
        if total_fee_pc > WARNING_THRESHOLD:
            log.info('\n'.join(['=' * 60] * 3))
            log.info('WARNING   ' * 6)
            log.info('\n'.join(['=' * 60] * 1))
            log.info('OFFERED COINJOIN FEE IS UNUSUALLY HIGH. DOUBLE/TRIPLE CHECK.')
            log.info('\n'.join(['=' * 60] * 1))
            log.info('WARNING   ' * 6)
            log.info('\n'.join(['=' * 60] * 3))
        if not options.answeryes:
            if input('send with these orders? (y/n):')[0] != 'y':
                return False
        return True

    def taker_finished(res, fromtx=False, waittime=0.0, txdetails=None):
        if fromtx == "unconfirmed":
            #If final entry, stop *here*, don't wait for confirmation
            if taker.schedule_index + 1 == len(taker.schedule):
                reactor.stop()
            return
        if fromtx:
            if res:
                txd, txid = txdetails
                taker.wallet.remove_old_utxos(txd)
                taker.wallet.add_new_utxos(txd, txid)
                reactor.callLater(waittime*60,
                                  clientfactory.getClient().clientStart)
            else:
                #a transaction failed; we'll try to repeat without the
                #troublemakers.
                #If this error condition is reached from Phase 1 processing,
                #and there are less than minimum_makers honest responses, we
                #just give up (note that in tumbler we tweak and retry, but
                #for sendpayment the user is "online" and so can manually
                #try again).
                #However if the error is in Phase 2 and we have minimum_makers
                #or more responses, we do try to restart with the honest set, here.
                if taker.latest_tx is None:
                    #can only happen with < minimum_makers; see above.
                    log.info("A transaction failed but there are insufficient "
                             "honest respondants to continue; giving up.")
                    reactor.stop()
                    return
                #This is Phase 2; do we have enough to try again?
                taker.add_honest_makers(list(set(
                    taker.maker_utxo_data.keys()).symmetric_difference(
                        set(taker.nonrespondants))))
                if len(taker.honest_makers) < jm_single().config.getint(
                    "POLICY", "minimum_makers"):
                    log.info("Too few makers responded honestly; "
                             "giving up this attempt.")
                    reactor.stop()
                    return
                jmprint("We failed to complete the transaction. The following "
                      "makers responded honestly: " + str(taker.honest_makers) +\
                      ", so we will retry with them.", "warning")
                #Now we have to set the specific group we want to use, and hopefully
                #they will respond again as they showed honesty last time.
                #we must reset the number of counterparties, as well as fix who they
                #are; this is because the number is used to e.g. calculate fees.
                #cleanest way is to reset the number in the schedule before restart.
                taker.schedule[taker.schedule_index][2] = len(taker.honest_makers)
                log.info("Retrying with: " + str(taker.schedule[
                    taker.schedule_index][2]) + " counterparties.")
                #rewind to try again (index is incremented in Taker.initialize())
                taker.schedule_index -= 1
                taker.set_honest_only(True)
                reactor.callLater(5.0, clientfactory.getClient().clientStart)
        else:
            if not res:
                log.info("Did not complete successfully, shutting down")
            #Should usually be unreachable, unless conf received out of order;
            #because we should stop on 'unconfirmed' for last (see above)
            else:
                log.info("All transactions completed correctly")
            reactor.stop()

    if options.p2ep:
        # This workflow requires command line reading; we force info level logging
        # to remove noise, and mostly communicate to the user with the fn
        # log.info (directly or via default taker_info_callback).
        set_logging_level("INFO")
        # in the case where the payment just hangs for a long period, allow
        # it to fail gracefully with an information message; this is triggered
        # only by the stallMonitor, which gives up after 20*maker_timeout_sec:
        def p2ep_on_finished_callback(res, fromtx=False, waittime=0.0,
                                      txdetails=None):
            log.error("PayJoin payment was NOT made, timed out.")
            reactor.stop()
        taker = P2EPTaker(options.p2ep, wallet, schedule,
                          callbacks=(None, None, p2ep_on_finished_callback))
    else:
        taker = Taker(wallet,
                      schedule,
                      order_chooser=chooseOrdersFunc,
                      max_cj_fee=maxcjfee,
                      callbacks=(filter_orders_callback, None, taker_finished))
    clientfactory = JMClientProtocolFactory(taker)
    nodaemon = jm_single().config.getint("DAEMON", "no_daemon")
    daemon = True if nodaemon == 1 else False
    p2ep = True if options.p2ep != "" else False
    if jm_single().config.get("BLOCKCHAIN", "network") in ["regtest", "testnet"]:
        startLogging(sys.stdout)
    start_reactor(jm_single().config.get("DAEMON", "daemon_host"),
                  jm_single().config.getint("DAEMON", "daemon_port"),
                  clientfactory, daemon=daemon, p2ep=p2ep)

if __name__ == "__main__":
    main()
    jmprint('done', "success")
