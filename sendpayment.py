#! /usr/bin/env python
from __future__ import absolute_import, print_function

"""
A sample implementation of a single coinjoin script,
adapted from `sendpayment.py` in Joinmarket-Org/joinmarket.
More complex applications can extend from Taker and add
more features, such as repeated joins. This will also allow
easier coding of non-CLI interfaces.

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

import time

from client import (Taker, load_program_config,
                              JMTakerClientProtocolFactory, start_reactor,
                              validate_address, jm_single,
                              choose_orders, choose_sweep_orders, pick_order,
                              cheapest_order_choose, weighted_order_choose,
                              Wallet, BitcoinCoreWallet,
                              estimate_tx_fee)

from base.support import get_log, debug_dump_object

log = get_log()


def check_high_fee(total_fee_pc):
    WARNING_THRESHOLD = 0.02  # 2%
    if total_fee_pc > WARNING_THRESHOLD:
        print('\n'.join(['=' * 60] * 3))
        print('WARNING   ' * 6)
        print('\n'.join(['=' * 60] * 1))
        print('OFFERED COINJOIN FEE IS UNUSUALLY HIGH. DOUBLE/TRIPLE CHECK.')
        print('\n'.join(['=' * 60] * 1))
        print('WARNING   ' * 6)
        print('\n'.join(['=' * 60] * 3))


def main():
    parser = OptionParser(
        usage=
        'usage: %prog [options] [wallet file / fromaccount] [amount] [destaddr]',
        description='Sends a single payment from a given mixing depth of your '
        +
        'wallet to an given address using coinjoin and then switches off. Also sends from bitcoinqt. '
        +
        'Setting amount to zero will do a sweep, where the entire mix depth is emptied')
    parser.add_option(
        '-f',
        '--txfee',
        action='store',
        type='int',
        dest='txfee',
        default=-1,
        help=
        'number of satoshis per participant to use as the initial estimate ' +
        'for the total transaction fee, default=dynamically estimated, note that this is adjusted '
        +
        'based on the estimated fee calculated after tx construction, based on '
        + 'policy set in joinmarket.cfg.')
    parser.add_option(
        '-w',
        '--wait-time',
        action='store',
        type='float',
        dest='waittime',
        help='wait time in seconds to allow orders to arrive, default=15',
        default=15)
    parser.add_option(
        '-N',
        '--makercount',
        action='store',
        type='int',
        dest='makercount',
        help='how many makers to coinjoin with, default random from 4 to 6',
        default=random.randint(4, 6))
    parser.add_option('-p',
                      '--port',
                      type='int',
                      dest='daemonport',
                      help='port on which joinmarketd is running',
                      default='12345')
    parser.add_option(
        '-C',
        '--choose-cheapest',
        action='store_true',
        dest='choosecheapest',
        default=False,
        help=
        'override weightened offers picking and choose cheapest. this might reduce anonymity.')
    parser.add_option(
        '-P',
        '--pick-orders',
        action='store_true',
        dest='pickorders',
        default=False,
        help=
        'manually pick which orders to take. doesn\'t work while sweeping.')
    parser.add_option('-m',
                      '--mixdepth',
                      action='store',
                      type='int',
                      dest='mixdepth',
                      help='mixing depth to spend from, default=0',
                      default=0)
    parser.add_option('-a',
                      '--amtmixdepths',
                      action='store',
                      type='int',
                      dest='amtmixdepths',
                      help='number of mixdepths in wallet, default 5',
                      default=5)
    parser.add_option('-g',
                      '--gap-limit',
                      type="int",
                      action='store',
                      dest='gaplimit',
                      help='gap limit for wallet, default=6',
                      default=6)
    parser.add_option('--yes',
                      action='store_true',
                      dest='answeryes',
                      default=False,
                      help='answer yes to everything')
    parser.add_option(
        '--rpcwallet',
        action='store_true',
        dest='userpcwallet',
        default=False,
        help=('Use the Bitcoin Core wallet through json rpc, instead '
              'of the internal joinmarket wallet. Requires '
              'blockchain_source=json-rpc'))
    (options, args) = parser.parse_args()

    if len(args) < 3:
        parser.error('Needs a wallet, amount and destination address')
        sys.exit(0)
    wallet_name = args[0]
    amount = int(args[1])
    destaddr = args[2]

    load_program_config()
    jm_single().maker_timeout_sec = 5
    addr_valid, errormsg = validate_address(destaddr)
    if not addr_valid:
        print('ERROR: Address invalid. ' + errormsg)
        return

    chooseOrdersFunc = None
    if options.pickorders:
        chooseOrdersFunc = pick_order
        if amount == 0:
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
        wallet = Wallet(wallet_name, options.amtmixdepths, options.gaplimit)
    else:
        wallet = BitcoinCoreWallet(fromaccount=wallet_name)
    jm_single().bc_interface.sync_wallet(wallet)

    taker = Taker(wallet,
                  options.mixdepth,
                  amount,
                  options.makercount,
                  order_chooser=chooseOrdersFunc,
                  external_addr=destaddr)
    clientfactory = JMTakerClientProtocolFactory(taker)
    start_reactor("localhost", options.daemonport, clientfactory)


if __name__ == "__main__":
    main()
    print('done')
