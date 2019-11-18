#! /usr/bin/env python
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401

from optparse import OptionParser

import sys
from twisted.python.log import startLogging
from jmbase import get_log, set_logging_level
from jmclient import P2EPMaker, jm_single, load_program_config, \
    sync_wallet, JMClientProtocolFactory, start_reactor, \
    open_test_wallet_maybe, get_wallet_path
from cli_options import check_regtest
from jmbase.support import EXIT_FAILURE, EXIT_ARGERROR

jlog = get_log()

def receive_payjoin_main(makerclass):
    parser = OptionParser(usage='usage: %prog [options] [wallet file] [amount-to-receive]')
    parser.add_option('-g', '--gap-limit', action='store', type="int",
                      dest='gaplimit', default=6,
                      help='gap limit for wallet, default=6')
    parser.add_option('--recoversync',
                      action='store_true',
                      dest='recoversync',
                      default=False,
                      help=('choose to do detailed wallet sync, '
                            'used for recovering on new Core instance.'))
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
    parser.add_option('--wallet-password-stdin',
                      action='store_true',
                      default=False,
                      dest='wallet_password_stdin',
                      help='Read wallet password from stdin')

    (options, args) = parser.parse_args()
    if len(args) < 2:
        parser.error('Needs a wallet, and a receiving amount in satoshis')
        sys.exit(EXIT_ARGERROR)
    wallet_name = args[0]
    try:
        receiving_amount = int(args[1])
    except:
        parser.error("Invalid receiving amount passed: " + receiving_amount)
        sys.exit(EXIT_FAILURE)
    if receiving_amount < 0:
        parser.error("Receiving amount must be a positive integer in satoshis")
        sys.exit(EXIT_FAILURE)
    load_program_config()

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

    if jm_single().config.get("BLOCKCHAIN", "blockchain_source") == "electrum-server":
        jm_single().bc_interface.synctype = "with-script"

    while not jm_single().bc_interface.wallet_synced:
        sync_wallet(wallet, fast=not options.recoversync)

    maker = makerclass(wallet, options.mixdepth, receiving_amount)
    
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
