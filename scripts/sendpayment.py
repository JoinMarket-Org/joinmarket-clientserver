#! /usr/bin/env python
from __future__ import absolute_import, print_function

"""
A sample implementation of a single coinjoin script,
adapted from `sendpayment.py` in Joinmarket-Org/joinmarket.
This is designed
to illustrate the main functionality of the new architecture:
this code can be run in a separate environment (but not safely
over the internet, better on one machine) to the joinmarketdaemon.
Moreover, it can run several transactions as specified in a "schedule", like:

[(mixdepth, amount, N, destination),(m,a,N,d),..]

call it like the normal Joinmarket sendpayment, but optionally add
a port for the daemon:

`python sendpayment.py -p 27183 -N 3 -m 1 walletseed amount address`;

Schedule can be read from a file with the -S option, in which case no need to
provide amount, mixdepth, number of counterparties or destination from command line.

The idea is that the "backend" (daemon) will keep its orderbook and stay
connected on the message channel between runs, only shutting down
after all are complete. Joins are sequenced using the wallet-notify function as
previously for Joinmarket.

It should be very easy to extend this further, of course.

More complex applications can extend from Taker and add
more features. This will also allow
easier coding of non-CLI interfaces. A plugin for Electrum is in process
and already working.

Other potential customisations of the Taker object instantiation
include:

external_addr=None implies joining to another mixdepth
in the same wallet.

order_chooser can be set to a different custom function that selects
counterparty offers according to different rules.
"""

import random
import sys
import threading
from optparse import OptionParser
from twisted.internet import reactor
import time
import os
import pprint

from jmclient import (Taker, load_program_config, get_schedule,
                              JMTakerClientProtocolFactory, start_reactor,
                              validate_address, jm_single, WalletError,
                              choose_orders, choose_sweep_orders,
                              cheapest_order_choose, weighted_order_choose,
                              Wallet, BitcoinCoreWallet, sync_wallet,
                              RegtestBitcoinCoreInterface, estimate_tx_fee)

from jmbase.support import get_log, debug_dump_object, get_password
from cli_options import get_sendpayment_parser

log = get_log()

def pick_order(orders, n): #pragma: no cover
    print("Considered orders:")
    for i, o in enumerate(orders):
        print("    %2d. %20s, CJ fee: %6s, tx fee: %6d" %
              (i, o[0]['counterparty'], str(o[0]['cjfee']), o[0]['txfee']))
    pickedOrderIndex = -1
    if i == 0:
        print("Only one possible pick, picking it.")
        return orders[0]
    while pickedOrderIndex == -1:
        try:
            pickedOrderIndex = int(raw_input('Pick an order between 0 and ' +
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

    if options.schedule == '' and len(args) < 3:
        parser.error('Needs a wallet, amount and destination address')
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
            print('ERROR: Address invalid. ' + errormsg)
            return
        schedule = [[options.mixdepth, amount, options.makercount, destaddr]]
    else:
        result, schedule = get_schedule(options.schedule)
        if not result:
            log.info("Failed to load schedule file, quitting. Check the syntax.")
            log.info("Error was: " + str(schedule))
            sys.exit(0)
        mixdepth = 0
        for s in schedule:
            if s[1] == 0:
                sweeping = True
            #only used for checking the maximum mixdepth required
            mixdepth = max([mixdepth, s[0]])

    wallet_name = args[0]

    #for testing, TODO remove
    jm_single().maker_timeout_sec = 5

    chooseOrdersFunc = None
    if options.pickorders:
        chooseOrdersFunc = pick_order
        if sweeping:
            print('WARNING: You may have to pick offers multiple times')
            print('WARNING: due to manual offer picking while sweeping')
    elif options.choosecheapest:
        chooseOrdersFunc = cheapest_order_choose
    else:  # choose randomly (weighted)
        chooseOrdersFunc = weighted_order_choose

    # Dynamically estimate a realistic fee if it currently is the default value.
    # At this point we do not know even the number of our own inputs, so
    # we guess conservatively with 2 inputs and 2 outputs each
    if options.txfee == -1:
        options.txfee = max(options.txfee, estimate_tx_fee(2, 2))
        log.debug("Estimated miner/tx fee for each cj participant: " + str(
            options.txfee))
    assert (options.txfee >= 0)

    log.debug('starting sendpayment')

    if not options.userpcwallet:
        max_mix_depth = max([mixdepth, options.amtmixdepths])
        if not os.path.exists(os.path.join('wallets', wallet_name)):
            wallet = Wallet(wallet_name, None, max_mix_depth, options.gaplimit)
        else:
            while True:
                try:
                    pwd = get_password("Enter wallet decryption passphrase: ")
                    wallet = Wallet(wallet_name, pwd, max_mix_depth, options.gaplimit)
                except WalletError:
                    print("Wrong password, try again.")
                    continue
                except Exception as e:
                    print("Failed to load wallet, error message: " + repr(e))
                    sys.exit(0)
                break
    else:
        wallet = BitcoinCoreWallet(fromaccount=wallet_name)
    sync_wallet(wallet, fast=options.fastsync)

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
            if raw_input('send with these orders? (y/n):')[0] != 'y':
                return False
        return True

    def taker_finished(res, fromtx=False, waittime=0.0):
        if fromtx:
            if res:
                sync_wallet(wallet, fast=options.fastsync)
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

    if isinstance(jm_single().bc_interface, RegtestBitcoinCoreInterface):
        #to allow testing of confirm/unconfirm callback for multiple txs
        jm_single().bc_interface.tick_forward_chain_interval = 10
    taker = Taker(wallet,
                  schedule,
                  order_chooser=chooseOrdersFunc,
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
