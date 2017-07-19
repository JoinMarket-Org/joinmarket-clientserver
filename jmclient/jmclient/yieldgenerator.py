#! /usr/bin/env python
from __future__ import absolute_import, print_function

import datetime
import os
import time
import abc
from optparse import OptionParser

from jmclient import (Maker, jm_single, get_network, load_program_config, get_log,
                      SegwitWallet, sync_wallet, JMClientProtocolFactory,
                      start_reactor)

jlog = get_log()

MAX_MIX_DEPTH = 5

# is a maker for the purposes of generating a yield from held
# bitcoins
class YieldGenerator(Maker):
    __metaclass__ = abc.ABCMeta
    statement_file = os.path.join('logs', 'yigen-statement.csv')

    def __init__(self, wallet):
        Maker.__init__(self, wallet)
        self.tx_unconfirm_timestamp = {}
        if not os.path.isfile(self.statement_file):
            self.log_statement(
                ['timestamp', 'cj amount/satoshi', 'my input count',
                 'my input value/satoshi', 'cjfee/satoshi', 'earned/satoshi',
                 'confirm time/min', 'notes'])

        timestamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        self.log_statement([timestamp, '', '', '', '', '', '', 'Connected'])

    def log_statement(self, data):
        data = [str(d) for d in data]
        self.income_statement = open(self.statement_file, 'a')
        self.income_statement.write(','.join(data) + '\n')
        self.income_statement.close()

    @abc.abstractmethod
    def create_my_orders(self):
        """Must generate a set of orders to be displayed
        according to the contents of the wallet + some algo.
        (Note: should be called "create_my_offers")
        """

    @abc.abstractmethod
    def oid_to_order(self, cjorder, oid, amount):
        """Must convert an order with an offer/order id
        into a set of utxos to fill the order.
        Also provides the output addresses for the Taker.
        """

    @abc.abstractmethod
    def on_tx_unconfirmed(self, cjorder, txid, removed_utxos):
        """Performs action on receipt of transaction into the
        mempool in the blockchain instance (e.g. announcing orders)
        """

    @abc.abstractmethod
    def on_tx_confirmed(self, cjorder, confirmations, txid):
        """Performs actions on receipt of 1st confirmation of
        a transaction into a block (e.g. announce orders)
        """


def ygmain(ygclass, txfee=1000, cjfee_a=200, cjfee_r=0.002, ordertype='swreloffer',
           nickserv_password='', minsize=100000, gaplimit=6):
    import sys

    parser = OptionParser(usage='usage: %prog [options] [wallet file]')
    parser.add_option('-o', '--ordertype', action='store', type='string',
                      dest='ordertype', default=ordertype,
                      help='type of order; can be either reloffer or absoffer')
    parser.add_option('-t', '--txfee', action='store', type='int',
                      dest='txfee', default=txfee,
                      help='minimum miner fee in satoshis')
    parser.add_option('-c', '--cjfee', action='store', type='string',
                      dest='cjfee', default='',
                      help='requested coinjoin fee in satoshis or proportion')
    parser.add_option('-p', '--password', action='store', type='string',
                      dest='password', default=nickserv_password,
                      help='irc nickserv password')
    parser.add_option('-s', '--minsize', action='store', type='int',
                      dest='minsize', default=minsize,
                      help='minimum coinjoin size in satoshis')
    parser.add_option('-g', '--gap-limit', action='store', type="int",
                      dest='gaplimit', default=gaplimit,
                      help='gap limit for wallet, default='+str(gaplimit))
    parser.add_option('--fast',
                      action='store_true',
                      dest='fastsync',
                      default=False,
                      help=('choose to do fast wallet sync, only for Core and '
                      'only for previously synced wallet'))
    (options, args) = parser.parse_args()
    if len(args) < 1:
        parser.error('Needs a wallet')
        sys.exit(0)
    wallet_name = args[0]
    ordertype = options.ordertype
    txfee = options.txfee
    if ordertype == 'swreloffer':
        if options.cjfee != '':
            cjfee_r = options.cjfee
        # minimum size is such that you always net profit at least 20%
        #of the miner fee
        minsize = max(int(1.2 * txfee / float(cjfee_r)), options.minsize)
    elif ordertype == 'swabsoffer':
        if options.cjfee != '':
            cjfee_a = int(options.cjfee)
        minsize = options.minsize
    else:
        parser.error('You specified an incorrect order type which ' +\
                     'can be either reloffer or absoffer')
        sys.exit(0)
    nickserv_password = options.password

    load_program_config()
    if not os.path.exists(os.path.join('wallets', wallet_name)):
        wallet = SegwitWallet(wallet_name, None, max_mix_depth=MAX_MIX_DEPTH,
                              gaplimit=options.gaplimit)
    else:
        while True:
            try:
                pwd = get_password("Enter wallet decryption passphrase: ")
                wallet = SegwitWallet(wallet_name, pwd,
                                      max_mix_depth=MAX_MIX_DEPTH,
                                      gaplimit=options.gaplimit)
            except WalletError:
                print("Wrong password, try again.")
                continue
            except Exception as e:
                print("Failed to load wallet, error message: " + repr(e))
                sys.exit(0)
            break
    sync_wallet(wallet, fast=options.fastsync)

    maker = ygclass(wallet, [options.txfee, cjfee_a, cjfee_r,
                             options.ordertype, options.minsize])
    jlog.info('starting yield generator')
    clientfactory = JMClientProtocolFactory(maker, proto_type="MAKER")
    nodaemon = jm_single().config.getint("DAEMON", "no_daemon")
    daemon = True if nodaemon == 1 else False
    start_reactor(jm_single().config.get("DAEMON", "daemon_host"),
                      jm_single().config.getint("DAEMON", "daemon_port"),
                      clientfactory, daemon=daemon)

