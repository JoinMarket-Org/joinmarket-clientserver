#!/usr/bin/env python3

"""
A sample implementation of a single coinjoin script,
adapted from `sendpayment.py` in Joinmarket-Org/joinmarket.
For notes, see scripts/README.md; in particular, note the use
of "schedules" with the -S flag.
"""

import sys
from twisted.internet import reactor
import pprint

from jmclient import Taker, load_program_config, get_schedule,\
    JMClientProtocolFactory, start_reactor, validate_address, is_burn_destination, \
    jm_single, estimate_tx_fee, direct_send, WalletService,\
    open_test_wallet_maybe, get_wallet_path, NO_ROUNDING, \
    get_sendpayment_parser, get_max_cj_fee_values, check_regtest, \
    parse_payjoin_setup, send_payjoin
from twisted.python.log import startLogging
from jmbase.support import get_log, set_logging_level, jmprint, \
    EXIT_FAILURE, EXIT_ARGERROR, DUST_THRESHOLD

import jmbitcoin as btc

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
    load_program_config(config_path=options.datadir)

    if options.schedule == '':
        if ((len(args) < 2) or
            (btc.is_bip21_uri(args[1]) and len(args) != 2) or
            (not btc.is_bip21_uri(args[1]) and len(args) != 3)):
                parser.error("Joinmarket sendpayment (coinjoin) needs arguments:"
                    " wallet, amount, destination address or wallet, bitcoin_uri.")
                sys.exit(EXIT_ARGERROR)

    #without schedule file option, use the arguments to create a schedule
    #of a single transaction
    sweeping = False
    bip78url = None
    if options.schedule == '':
        if btc.is_bip21_uri(args[1]):
            parsed = btc.decode_bip21_uri(args[1])
            try:
                amount = parsed['amount']
            except KeyError:
                parser.error("Given BIP21 URI does not contain amount.")
                sys.exit(EXIT_ARGERROR)
            destaddr = parsed['address']
            if "pj" in parsed:
                # note that this is a URL; its validity
                # checking is deferred to twisted.web.client.Agent
                bip78url = parsed["pj"]
                # setting makercount only for fee sanity check.
                # note we ignore any user setting and enforce N=0,
                # as this is a flag in the code for a non-JM coinjoin;
                # for the fee sanity check, note that BIP78 currently
                # will only allow small fee changes, so N=0 won't
                # be very inaccurate.
                jmprint("Attempting to pay via payjoin.", "info")
                options.makercount = 0
        else:
            amount = btc.amount_to_sat(args[1])
            if amount == 0:
                sweeping = True
            destaddr = args[2]
        mixdepth = options.mixdepth
        addr_valid, errormsg = validate_address(destaddr)
        command_to_burn = (is_burn_destination(destaddr) and sweeping and
            options.makercount == 0)
        if not addr_valid and not command_to_burn:
            jmprint('ERROR: Address invalid. ' + errormsg, "error")
            if is_burn_destination(destaddr):
                jmprint("The required options for burning coins are zero makers"
                    + " (-N 0), sweeping (amount = 0) and not using BIP78 Payjoin", "info")
            sys.exit(EXIT_ARGERROR)
        if sweeping == False and amount < DUST_THRESHOLD:
            jmprint('ERROR: Amount ' + btc.amount_to_str(amount) +
                ' is below dust threshold ' +
                btc.amount_to_str(DUST_THRESHOLD) + '.', "error")
            sys.exit(EXIT_ARGERROR)
        if (options.makercount != 0 and
            options.makercount < jm_single().config.getint(
            "POLICY", "minimum_makers")):
            jmprint('ERROR: Maker count ' + str(options.makercount) +
                ' below minimum_makers (' + str(jm_single().config.getint(
                "POLICY", "minimum_makers")) + ') in joinmarket.cfg.',
                "error")
            sys.exit(EXIT_ARGERROR)
        schedule = [[options.mixdepth, amount, options.makercount,
                     destaddr, 0.0, NO_ROUNDING, 0]]
    else:
        if len(args) > 1:
            parser.error("Schedule files are not compatible with "
                         "payment destination/amount arguments.")
            sys.exit(EXIT_ARGERROR)
        result, schedule = get_schedule(options.schedule)
        if not result:
            log.error("Failed to load schedule file, quitting. Check the syntax.")
            log.error("Error was: " + str(schedule))
            sys.exit(EXIT_FAILURE)
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

    # If tx_fees are set manually by CLI argument, override joinmarket.cfg:
    if int(options.txfee) > 0:
        jm_single().config.set("POLICY", "tx_fees", str(options.txfee))

    maxcjfee = (1, float('inf'))
    if not options.pickorders and options.makercount != 0:
        maxcjfee = get_max_cj_fee_values(jm_single().config, options)
        log.info("Using maximum coinjoin fee limits per maker of {:.4%}, {} "
                 "".format(maxcjfee[0], btc.amount_to_str(maxcjfee[1])))

    log.info('starting sendpayment')

    max_mix_depth = max([mixdepth, options.amtmixdepths - 1])

    wallet_path = get_wallet_path(wallet_name, None)
    wallet = open_test_wallet_maybe(
        wallet_path, wallet_name, max_mix_depth,
        wallet_password_stdin=options.wallet_password_stdin,
        gap_limit=options.gaplimit)
    wallet_service = WalletService(wallet)
    if wallet_service.rpc_error:
        sys.exit(EXIT_FAILURE)
    # in this script, we need the wallet synced before
    # logic processing for some paths, so do it now:
    while not wallet_service.synced:
        wallet_service.sync_wallet(fast=not options.recoversync)
    # the sync call here will now be a no-op:
    wallet_service.startService()

    # Dynamically estimate a realistic fee, for coinjoins.
    # At this point we do not know even the number of our own inputs, so
    # we guess conservatively with 2 inputs and 2 outputs each.
    if options.makercount != 0:
        fee_per_cp_guess = estimate_tx_fee(2, 2,
                                           txtype=wallet_service.get_txtype())
        log.debug("Estimated miner/tx fee for each cj participant: " +
                  btc.amount_to_str(fee_per_cp_guess))

    # From the estimated tx fees, check if the expected amount is a
    # significant value compared the the cj amount; currently enabled
    # only for single join (the predominant, non-advanced case)
    if options.schedule == '' and options.makercount != 0:
        total_cj_amount = amount
        if total_cj_amount == 0:
            total_cj_amount = wallet_service.get_balance_by_mixdepth()[options.mixdepth]
            if total_cj_amount == 0:
                raise ValueError("No confirmed coins in the selected mixdepth. Quitting")
        exp_tx_fees_ratio = ((1 + options.makercount) * fee_per_cp_guess) / total_cj_amount
        if exp_tx_fees_ratio > 0.05:
            jmprint('WARNING: Expected bitcoin network miner fees for this coinjoin'
                ' amount are roughly {:.1%}'.format(exp_tx_fees_ratio), "warning")
            if input('You might want to modify your tx_fee'
                ' settings in joinmarket.cfg. Still continue? (y/n):')[0] != 'y':
                sys.exit('Aborted by user.')
        else:
            log.info("Estimated miner/tx fees for this coinjoin amount: {:.1%}"
                .format(exp_tx_fees_ratio))

    if options.makercount == 0 and not bip78url:
        tx = direct_send(wallet_service, amount, mixdepth, destaddr,
                         options.answeryes, with_final_psbt=options.with_psbt)
        if options.with_psbt:
            log.info("This PSBT is fully signed and can be sent externally for "
                     "broadcasting:")
            log.info(tx.to_base64())
        return

    if wallet.get_txtype() == 'p2pkh':
        jmprint("Only direct sends (use -N 0) are supported for "
              "legacy (non-segwit) wallets.", "error")
        sys.exit(EXIT_ARGERROR)

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

    nodaemon = jm_single().config.getint("DAEMON", "no_daemon")
    daemon = True if nodaemon == 1 else False
    dhost = jm_single().config.get("DAEMON", "daemon_host")
    dport = jm_single().config.getint("DAEMON", "daemon_port")
    if bip78url:
        # TODO sanity check wallet type is segwit
        manager = parse_payjoin_setup(args[1], wallet_service, options.mixdepth)
        reactor.callWhenRunning(send_payjoin, manager)
        # JM is default, so must be switched off explicitly in this call:
        start_reactor(dhost, dport, bip78=True, jm_coinjoin=False, daemon=daemon)
        return

    else:
        taker = Taker(wallet_service,
                      schedule,
                      order_chooser=chooseOrdersFunc,
                      max_cj_fee=maxcjfee,
                      callbacks=(filter_orders_callback, None, taker_finished))
    clientfactory = JMClientProtocolFactory(taker)

    if jm_single().config.get("BLOCKCHAIN", "network") == "regtest":
        startLogging(sys.stdout)
    start_reactor(dhost, dport, clientfactory, daemon=daemon)

if __name__ == "__main__":
    main()
    jmprint('done', "success")
