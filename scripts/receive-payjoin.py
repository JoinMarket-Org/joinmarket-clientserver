#!/usr/bin/env python3

from optparse import OptionParser

import sys
from twisted.python.log import startLogging
from twisted.internet import reactor
from jmbase import get_log, set_logging_level, jmprint
from jmclient import jm_single, load_program_config, \
    WalletService, open_test_wallet_maybe, get_wallet_path, check_regtest, \
    add_base_options, JMBIP78ReceiverManager
from jmbase.support import EXIT_FAILURE, EXIT_ARGERROR
from jmbitcoin import amount_to_sat
jlog = get_log()

def receive_payjoin_main():
    parser = OptionParser(usage='usage: %prog [options] [wallet file] [amount-to-receive]')
    add_base_options(parser)
    parser.add_option('-P', '--hs-port', action='store', type='int',
                      dest='hsport', default=80,
                      help='port on which to serve the ephemeral hidden service.')
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
        # amount is stored internally in sats, but will be decimal in URL.
        bip78_amount = amount_to_sat(args[1])
    except:
        parser.error("Invalid receiving amount passed: " + bip78_amount)
        sys.exit(EXIT_FAILURE)
    if bip78_amount < 0:
        parser.error("Receiving amount must be a positive number")
        sys.exit(EXIT_FAILURE)
    load_program_config(config_path=options.datadir)

    check_regtest()

    wallet_path = get_wallet_path(wallet_name, None)
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
    receiver_manager = JMBIP78ReceiverManager(wallet_service, options.mixdepth,
                                    bip78_amount, options.hsport)
    receiver_manager.start_pj_server_and_tor()
    reactor.run()

if __name__ == "__main__":
    receive_payjoin_main()
    jmprint('done')
