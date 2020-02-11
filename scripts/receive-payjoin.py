#! /usr/bin/env python

from optparse import OptionParser

import sys
from twisted.python.log import startLogging
from jmbase import get_log, set_logging_level
from jmclient import P2EPMaker, jm_single, load_program_config, \
    WalletService, JMClientProtocolFactory, start_reactor, \
    open_test_wallet_maybe, get_wallet_path, check_regtest, \
    add_base_options
from jmbase.support import EXIT_FAILURE, EXIT_ARGERROR
from jmbitcoin import amount_to_sat

jlog = get_log()

def receive_payjoin_main(makerclass):
    parser = OptionParser(usage='usage: %prog [options] [wallet file] [amount-to-receive]')
    add_base_options(parser)
    parser.add_option('-g', '--gap-limit', action='store', type="int",
                      dest='gaplimit', default=6,
                      help='gap limit for wallet, default=6')
    parser.add_option('-m', '--mixdepth', action='store', type='int',
                      dest='mixdepth', default=0,
                      help="mixdepth to source coins from")
    parser.add_option('-a',
                      '--amtmixdepths',
                      action='store',
                      type='int',
                      dest='amtmixdepths',
                      help='number of mixdepths in wallet, default 5',
                      default=5)

    (options, args) = parser.parse_args()
    if len(args) < 2:
        parser.error('Needs a wallet, and a receiving amount in bitcoins or satoshis')
        sys.exit(EXIT_ARGERROR)
    wallet_name = args[0]
    try:
        receiving_amount = amount_to_sat(args[1])
    except:
        parser.error("Invalid receiving amount passed: " + receiving_amount)
        sys.exit(EXIT_FAILURE)
    if receiving_amount < 0:
        parser.error("Receiving amount must be a positive number")
        sys.exit(EXIT_FAILURE)
    load_program_config(config_path=options.datadir)

    check_regtest()

    # This workflow requires command line reading; we force info level logging
    # to remove noise, and mostly communicate to the user with the fn
    # log.info (via P2EPMaker.user_info).
    set_logging_level("INFO")

    wallet_path = get_wallet_path(wallet_name, 'wallets')
    max_mix_depth = max([options.mixdepth, options.amtmixdepths - 1])
    wallet = open_test_wallet_maybe(
        wallet_path, wallet_name, max_mix_depth,
        wallet_password_stdin=options.wallet_password_stdin,
        gap_limit=options.gaplimit)
    wallet_service = WalletService(wallet)

    while not wallet_service.synced:
        wallet_service.sync_wallet(fast=not options.recoversync)
    wallet_service.startService()
    # having enforced wallet sync, we can check if we have coins
    # to do payjoin in the mixdepth
    if wallet_service.get_balance_by_mixdepth()[options.mixdepth] == 0:
        jlog.error("Cannot do payjoin from mixdepth " + str(
            options.mixdepth) + ", no coins. Shutting down.")
        sys.exit(EXIT_ARGERROR)

    maker = makerclass(wallet_service, options.mixdepth, receiving_amount)
    
    jlog.info('starting receive-payjoin')
    clientfactory = JMClientProtocolFactory(maker, proto_type="MAKER")

    nodaemon = jm_single().config.getint("DAEMON", "no_daemon")
    daemon = True if nodaemon == 1 else False
    if jm_single().config.get("BLOCKCHAIN", "network") in ["regtest", "testnet"]:
        startLogging(sys.stdout)
    start_reactor(jm_single().config.get("DAEMON", "daemon_host"),
                  jm_single().config.getint("DAEMON", "daemon_port"),
                  clientfactory, daemon=daemon, p2ep=True)

if __name__ == "__main__":
    receive_payjoin_main(P2EPMaker)
    print('done')
