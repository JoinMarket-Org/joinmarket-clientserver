#! /usr/bin/env python
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
import logging

from jmclient import (Taker, load_program_config, get_schedule,
                      weighted_order_choose, JMTakerClientProtocolFactory,
                      start_reactor, validate_address, jm_single, WalletError,
                      Wallet, sync_wallet, get_tumble_schedule,
                      RegtestBitcoinCoreInterface, estimate_tx_fee,
                      tweak_tumble_schedule, human_readable_schedule_entry,
                      schedule_to_text, restart_waiter, get_tumble_log,
                      tumbler_taker_finished_update, tumbler_filter_orders_callback)

from jmbase.support import get_log, debug_dump_object, get_password
from cli_options import get_tumbler_parser
log = get_log()
logsdir = os.path.join(os.path.dirname(
    jm_single().config_location), "logs")


def main():
    tumble_log = get_tumble_log(logsdir)
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
    #Output information to log files
    jm_single().mincjamount = options['mincjamount']
    destaddrs = args[1:]
    print(destaddrs)
    #If the --restart flag is set we read the schedule
    #from the file, and filter out entries that are
    #already complete
    if options['restart']:
        res, schedule = get_schedule(os.path.join(logsdir,
                                                  options['schedulefile']))
        if not res:
            print("Failed to load schedule, name: " + str(
                options['schedulefile']))
            print("Error was: " + str(schedule))
            sys.exit(0)
        #This removes all entries that are marked as done
        schedule = [s for s in schedule if s[5] != 1]
        if isinstance(schedule[0][5], str) and len(schedule[0][5]) == 64:
            #ensure last transaction is confirmed before restart
            tumble_log.info("WAITING TO RESTART...")
            txid = schedule[0][5]
            restart_waiter(txid + ":0") #add 0 index because all have it
            #remove the already-done entry (this connects to the other TODO,
            #probably better *not* to truncate the done-already txs from file,
            #but simplest for now.
            schedule = schedule[1:]
        elif schedule[0][5] != 0:
            print("Error: first schedule entry is invalid.")
            sys.exit(0)
        with open(os.path.join(logsdir, options['schedulefile']), "wb") as f:
                    f.write(schedule_to_text(schedule))
        tumble_log.info("TUMBLE RESTARTING")
    else:
        #Create a new schedule from scratch
        schedule = get_tumble_schedule(options, destaddrs)
        tumble_log.info("TUMBLE STARTING")
        with open(os.path.join(logsdir, options['schedulefile']), "wb") as f:
            f.write(schedule_to_text(schedule))
        print("Schedule written to logs/" + options['schedulefile'])
    tumble_log.info("With this schedule: ")
    tumble_log.info(pprint.pformat(schedule))

    print("Progress logging to logs/TUMBLE.log")

    def filter_orders_callback(orders_fees, cjamount):
        """Decide whether to accept fees
        """
        return tumbler_filter_orders_callback(orders_fees, cjamount, taker, options)

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

    #to allow testing of confirm/unconfirm callback for multiple txs
    if isinstance(jm_single().bc_interface, RegtestBitcoinCoreInterface):
        jm_single().bc_interface.tick_forward_chain_interval = 10
        jm_single().maker_timeout_sec = 5

    #instantiate Taker with given schedule and run
    taker = Taker(wallet,
                  schedule,
                  order_chooser=weighted_order_choose,
                  callbacks=(filter_orders_callback, None, taker_finished),
                  tdestaddrs=destaddrs)
    clientfactory = JMTakerClientProtocolFactory(taker)
    nodaemon = jm_single().config.getint("DAEMON", "no_daemon")
    daemon = True if nodaemon == 1 else False
    start_reactor(jm_single().config.get("DAEMON", "daemon_host"),
                  jm_single().config.getint("DAEMON", "daemon_port"),
                  clientfactory, daemon=daemon)

if __name__ == "__main__":
    main()
    print('done')
