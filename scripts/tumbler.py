#!/usr/bin/env python3

import sys
from twisted.internet import reactor
import os
import pprint
from twisted.python.log import startLogging
from jmclient import Taker, load_program_config, \
    JMClientProtocolFactory, start_reactor, jm_single, get_wallet_path,\
    open_test_wallet_maybe, get_tumble_schedule, \
    schedule_to_text, estimate_tx_fee, WalletService, \
    get_tumble_log, tumbler_taker_finished_update, check_regtest, \
    tumbler_filter_orders_callback, validate_address, get_tumbler_parser, \
    get_max_cj_fee_values, get_total_tumble_amount, ScheduleGenerationErrorNoFunds
from jmclient.wallet_utils import DEFAULT_MIXDEPTH


from jmbase.support import get_log, jmprint, \
    EXIT_FAILURE, EXIT_ARGERROR

log = get_log()

def main():
    (options, args) = get_tumbler_parser().parse_args()
    options_org = options
    options = vars(options)
    if len(args) < 1:
        jmprint('Error: Needs a wallet file', "error")
        sys.exit(EXIT_ARGERROR)
    load_program_config(config_path=options['datadir'])
    logsdir = os.path.join(os.path.dirname(
        jm_single().config_location), "logs")
    tumble_log = get_tumble_log(logsdir)

    if jm_single().bc_interface is None:
        jmprint('Error: Needs a blockchain source', "error")
        sys.exit(EXIT_FAILURE)

    check_regtest()

    #Load the wallet
    wallet_name = args[0]
    # as of #1324 the concept of a max_mix_depth distinct from
    # the normal wallet value (4) no longer applies, since the
    # tumbler cycles; but we keep the `amtmixdepths` option for now,
    # deprecating it later.
    if options['amtmixdepths'] > DEFAULT_MIXDEPTH:
        max_mix_depth = options['amtmixdepths']
    else:
        max_mix_depth = DEFAULT_MIXDEPTH
    wallet_path = get_wallet_path(wallet_name, None)
    wallet = open_test_wallet_maybe(wallet_path, wallet_name, max_mix_depth,
            wallet_password_stdin=options_org.wallet_password_stdin)
    wallet_service = WalletService(wallet)
    if wallet_service.rpc_error:
        sys.exit(EXIT_FAILURE)
    # in this script, we need the wallet synced before
    # logic processing for some paths, so do it now:
    while not wallet_service.synced:
        wallet_service.sync_wallet(fast=not options['recoversync'])
    # the sync call here will now be a no-op:
    wallet_service.startService()

    maxcjfee = get_max_cj_fee_values(jm_single().config, options_org)
    log.info("Using maximum coinjoin fee limits per maker of {:.4%}, {} sat"
             .format(*maxcjfee))

    #Parse options and generate schedule
    #Output information to log files
    jm_single().mincjamount = options['mincjamount']
    destaddrs = args[1:]
    for daddr in destaddrs:
        success, errmsg = validate_address(daddr)
        if not success:
            jmprint("Invalid destination address: " + daddr, "error")
            sys.exit(EXIT_ARGERROR)
    jmprint("Destination addresses: " + str(destaddrs), "important")
    #Create a new schedule from scratch
    try:
        schedule = get_tumble_schedule(options, destaddrs,
            wallet.get_balance_by_mixdepth(), wallet_service.mixdepth)
    except ScheduleGenerationErrorNoFunds:
        jmprint("No funds in wallet to tumble.", "error")
        sys.exit(EXIT_FAILURE)
    tumble_log.info("TUMBLE STARTING")
    with open(os.path.join(logsdir, options['schedulefile']), "wb") as f:
        f.write(schedule_to_text(schedule))
    print("Schedule written to logs/" + options['schedulefile'])
    tumble_log.info("With this schedule: ")
    tumble_log.info(pprint.pformat(schedule))

    # If tx_fees are set manually by CLI argument, override joinmarket.cfg:
    if int(options['txfee']) > 0:
        jm_single().config.set("POLICY", "tx_fees", str(options['txfee']))

    # Dynamically estimate an expected tx fee for the whole tumbling run.
    # This is very rough: we guess with 2 inputs and 2 outputs each.
    fee_per_cp_guess = estimate_tx_fee(2, 2, txtype=wallet_service.get_txtype())
    log.debug("Estimated miner/tx fee for each cj participant: " + str(
            fee_per_cp_guess))

    # From the estimated tx fees, check if the expected amount is a
    # significant value compared the the cj amount
    involved_parties = len(schedule)    # own participation in each CJ
    for item in schedule:
        involved_parties += item[2] #  number of total tumble counterparties

    total_tumble_amount = get_total_tumble_amount(
        wallet.get_balance_by_mixdepth(), schedule)

    exp_tx_fees_ratio = (involved_parties * fee_per_cp_guess) \
        / total_tumble_amount
    if exp_tx_fees_ratio > 0.05:
        jmprint('WARNING: Expected bitcoin network miner fees for the whole '
            'tumbling run are roughly {:.1%}'.format(exp_tx_fees_ratio), "warning")
        if not options['restart'] and input('You might want to modify your tx_fee'
            ' settings in joinmarket.cfg. Still continue? (y/n):')[0] != 'y':
            sys.exit('Aborted by user.')
    else:
        log.info("Estimated miner/tx fees for this coinjoin amount for the "
            "whole tumbling run: {:.1%}".format(exp_tx_fees_ratio))

    print("Progress logging to logs/TUMBLE.log")

    def filter_orders_callback(orders_fees, cjamount):
        """Decide whether to accept fees
        """
        return tumbler_filter_orders_callback(orders_fees, cjamount, taker)

    def taker_finished(res, fromtx=False, waittime=0.0, txdetails=None):
        """on_finished_callback for tumbler; processing is almost entirely
        deferred to generic taker_finished in tumbler_support module, except
        here reactor signalling.
        """
        sfile = os.path.join(logsdir, options['schedulefile'])
        tumbler_taker_finished_update(taker, sfile, tumble_log, options,
                                      res, fromtx, waittime, txdetails)
        if not fromtx:
            reactor.stop()
        elif fromtx != "unconfirmed":
            reactor.callLater(waittime*60, clientfactory.getClient().clientStart)

    #instantiate Taker with given schedule and run
    taker = Taker(wallet_service,
                  schedule,
                  maxcjfee,
                  order_chooser=options['order_choose_fn'],
                  callbacks=(filter_orders_callback, None, taker_finished),
                  tdestaddrs=destaddrs)
    clientfactory = JMClientProtocolFactory(taker)
    nodaemon = jm_single().config.getint("DAEMON", "no_daemon")
    daemon = True if nodaemon == 1 else False
    if jm_single().config.get("BLOCKCHAIN", "network") == "regtest":
        startLogging(sys.stdout)
    start_reactor(jm_single().config.get("DAEMON", "daemon_host"),
                  jm_single().config.getint("DAEMON", "daemon_port"),
                  clientfactory, daemon=daemon)

if __name__ == "__main__":
    main()
    print('done')
