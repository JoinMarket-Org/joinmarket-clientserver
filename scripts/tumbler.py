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
                      schedule_to_text)

from jmbase.support import get_log, debug_dump_object, get_password
from cli_options import get_tumbler_parser
log = get_log()

def main():
    #Prepare log file giving simplified information
    #on progress of tumble.
    tumble_log = logging.getLogger('tumbler')
    tumble_log.setLevel(logging.DEBUG)
    logFormatter = logging.Formatter(
        ('%(asctime)s %(message)s'))
    logsdir = os.path.join(os.path.dirname(
    jm_single().config_location), "logs")
    fileHandler = logging.FileHandler(os.path.join(logsdir, 'TUMBLE.log'))
    fileHandler.setFormatter(logFormatter)
    tumble_log.addHandler(fileHandler)

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
            sys.exit(0)
        #This removes all entries that are marked as done;
        #assumes user has not edited by hand, and edits have only happened
        #on tx completion.
        schedule = [s for s in schedule if s[5] == 0]
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

    #callback for order checking; dummy/passthrough
    def filter_orders_callback(orders_fees, cjamount):
        return True

    def taker_finished(res, fromtx=False, waittime=0.0, txdetails=None):
        """on_finished_callback for tumbler
        """
        def unconf_update():
            #on taker side, cache index update is only required after tx
            #push, to avoid potential of address reuse in case of a crash,
            #because addresses are not public until broadcast (whereas for makers,
            #they are public *during* negotiation). So updating the cache here
            #is sufficient
            taker.wallet.update_cache_index()

            #We persist the fact that the transaction is complete to the
            #schedule file. Note that if a tweak to the schedule occurred,
            #it only affects future (non-complete) transactions, so the final
            #full record should always be accurate; but TUMBLE.log should be
            #used for checking what actually happened.
            taker.schedule[taker.schedule_index][5] = 1
            with open(os.path.join(logsdir, options['schedulefile']),
                      "wb") as f:
                f.write(schedule_to_text(taker.schedule))

        if fromtx == "unconfirmed":
            #unconfirmed event means transaction has been propagated,
            #we update state to prevent accidentally re-creating it in
            #any crash/restart condition
            unconf_update()
            return

        if fromtx:
            if res:
                tumble_log.info("Completed successfully this entry:")
                #this has no effect except in the rare case that confirmation
                #is immediate
                unconf_update()
                #the log output depends on if it's to INTERNAL
                hrdestn = None
                if taker.schedule[taker.schedule_index][3] == "INTERNAL":
                    hrdestn = taker.my_cj_addr
                #Whether sweep or not, the amt is not in satoshis; use taker data
                hramt = taker.cjamount
                tumble_log.info(human_readable_schedule_entry(
                    taker.schedule[taker.schedule_index], hramt, hrdestn))
                tumble_log.info("Txid was: " + taker.txid)
                waiting_message = "Waiting for: " + str(waittime) + " minutes."
                tumble_log.info(waiting_message)
                log.info(waiting_message)
                txd, txid = txdetails
                taker.wallet.remove_old_utxos(txd)
                taker.wallet.add_new_utxos(txd, txid)
                reactor.callLater(waittime*60,
                                  clientfactory.getClient().clientStart)
            else:
                #a transaction failed; tumbler is aggressive in trying to
                #complete; we tweak the schedule from this point in the mixdepth,
                #then try again:
                tumble_log.info("Transaction attempt failed, tweaking schedule"
                                " and trying again.")
                tumble_log.info("The paramaters of the failed attempt: ")
                tumble_log.info(str(taker.schedule[taker.schedule_index]))
                log.info("Schedule entry: " + str(
                    taker.schedule[taker.schedule_index]) + \
                         " failed after timeout, trying again")
                taker.schedule_index -= 1
                taker.schedule = tweak_tumble_schedule(options, taker.schedule,
                                                       taker.schedule_index)
                tumble_log.info("We tweaked the schedule, the new schedule is:")
                tumble_log.info(pprint.pformat(taker.schedule))
                reactor.callLater(0, clientfactory.getClient().clientStart)
        else:
            if not res:
                failure_msg = "Did not complete successfully, shutting down"
                tumble_log.info(failure_msg)
                log.info(failure_msg)
            else:
                log.info("All transactions completed correctly")
                tumble_log.info("Completed successfully the last entry:")
                #Whether sweep or not, the amt is not in satoshis; use taker data
                hramt = taker.cjamount
                tumble_log.info(human_readable_schedule_entry(
                    taker.schedule[taker.schedule_index], hramt))
                #copy of above, TODO refactor out
                taker.schedule[taker.schedule_index][5] = 1
                with open(os.path.join(logsdir, options['schedulefile']),
                          "wb") as f:
                    f.write(schedule_to_text(taker.schedule))
            reactor.stop()

    #to allow testing of confirm/unconfirm callback for multiple txs
    if isinstance(jm_single().bc_interface, RegtestBitcoinCoreInterface):
        jm_single().bc_interface.tick_forward_chain_interval = 10
        jm_single().maker_timeout_sec = 5

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
