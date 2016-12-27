from __future__ import absolute_import, print_function

import random
import sys
import threading
from optparse import OptionParser
from twisted.internet import reactor
import time
import os
import pprint
import copy

from jmclient import (Taker, load_program_config, get_schedule, weighted_order_choose,
                              JMTakerClientProtocolFactory, start_reactor,
                              validate_address, jm_single, WalletError,
                              Wallet, sync_wallet, get_tumble_schedule,
                              RegtestBitcoinCoreInterface, estimate_tx_fee)

from jmbase.support import get_log, debug_dump_object, get_password
from cli_options import get_tumbler_parser
log = get_log()

def main():
    (options, args) = get_tumbler_parser().parse_args()
    options = vars(options)

    if len(args) < 1:
        parser.error('Needs a wallet file')
        sys.exit(0)

    load_program_config()

    #Load the wallet
    wallet_name = args[0]
    max_mix_depth = options['mixdepthsrc'] + options['mixdepthcount']
    if not os.path.exists(os.path.join('wallets', wallet_name)):
        wallet = Wallet(wallet_name, None, max_mix_depth)
    else:
        while True:
            try:
                pwd = get_password("Enter wallet decryption passphrase: ")
                wallet = Wallet(wallet_name, pwd, max_mix_depth)
            except WalletError:
                print("Wrong password, try again.")
                continue
            except Exception as e:
                print("Failed to load wallet, error message: " + repr(e))
                sys.exit(0)
            break
    sync_wallet(wallet, fast=options['fastsync'])

    #Parse options and generate schedule
    
    #for testing, TODO remove
    jm_single().maker_timeout_sec = 5 
    
    jm_single().mincjamount = options['mincjamount']
    destaddrs = args[1:]
    print(destaddrs)
    schedule = get_tumble_schedule(options, destaddrs)
    print("got schedule:")
    print(pprint.pformat(schedule))

    #callback for order checking; dummy/passthrough
    def filter_orders_callback(orders_fees, cjamount):
        return True
    #callback between transactions
    def taker_finished(res, fromtx=False, waittime=0.0):
        if fromtx:
            if res:
                sync_wallet(wallet, fast=options['fastsync'])
                log.info("Waiting for: " + str(waittime) + " seconds.")
                reactor.callLater(waittime, clientfactory.getClient().clientStart)
            else:
                #a transaction failed; just stop
                reactor.stop()
        else:
            if not res:
                log.info("Did not complete successfully, shutting down")
            else:
                log.info("All transactions completed correctly")
            reactor.stop()

    #to allow testing of confirm/unconfirm callback for multiple txs
    if isinstance(jm_single().bc_interface, RegtestBitcoinCoreInterface):
        jm_single().bc_interface.tick_forward_chain_interval = 10

    #instantiate Taker with given schedule and run
    taker = Taker(wallet,
                  schedule,
                  order_chooser=weighted_order_choose,
                  callbacks=(filter_orders_callback, None, taker_finished))
    clientfactory = JMTakerClientProtocolFactory(taker)
    nodaemon = jm_single().config.getint("DAEMON", "no_daemon")
    daemon = True if nodaemon == 1 else False
    start_reactor(jm_single().config.get("DAEMON", "daemon_host"),
                  jm_single().config.getint("DAEMON", "daemon_port"),
                  clientfactory, daemon=daemon)


if __name__ == "__main__":
    main()
    print('done')
