#! /usr/bin/env python
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401
from future.utils import iteritems

import datetime
import os
import time
import abc
from twisted.python.log import startLogging
from optparse import OptionParser
from jmbase import get_log
from jmclient import Maker, jm_single, load_program_config, \
    sync_wallet, JMClientProtocolFactory, start_reactor, calc_cj_fee
from .wallet_utils import open_test_wallet_maybe, get_wallet_path

jlog = get_log()

MAX_MIX_DEPTH = 5

class YieldGenerator(Maker):
    """A maker for the purposes of generating a yield from held
    bitcoins, offering from the maximum mixdepth and trying to offer
    the largest amount within the constraints of mixing depth isolation.
    """
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

    def on_tx_unconfirmed(self, offer, txid, removed_utxos):
        self.tx_unconfirm_timestamp[offer["cjaddr"]] = int(time.time())
        newoffers = self.create_my_orders()

        old_oid_offers = {x['oid']: x for x in self.offerlist}
        new_oids = {x['oid'] for x in newoffers}

        to_cancel, to_announce = [], []

        for new_offer in newoffers:
            old_offer = old_oid_offers.get(new_offer['oid'])
            if old_offer is None or old_offer != new_offer:
                to_announce.append(new_offer)

        for old_oid in old_oid_offers:
            if old_oid not in new_oids:
                to_cancel.append(old_oid)

        return to_cancel, to_announce


class YieldGeneratorBasic(YieldGenerator):
    """A simplest possible instantiation of a yieldgenerator.
    It will often (but not always) reannounce orders after transactions,
    thus is somewhat suboptimal in giving more information to spies.
    """
    def __init__(self, wallet, offerconfig):
        self.txfee, self.cjfee_a, self.cjfee_r, self.ordertype, self.minsize \
             = offerconfig
        super(YieldGeneratorBasic,self).__init__(wallet)

    def create_my_orders(self):
        mix_balance = self.wallet.get_balance_by_mixdepth(verbose=False)
        if len([b for m, b in iteritems(mix_balance) if b > 0]) == 0:
            jlog.error('do not have any coins left')
            return []

        # print mix_balance
        max_mix = max(mix_balance, key=mix_balance.get)
        f = '0'
        if self.ordertype in ('reloffer', 'swreloffer'):
            f = self.cjfee_r
            #minimum size bumped if necessary such that you always profit
            #least 50% of the miner fee
            self.minsize = max(int(1.5 * self.txfee / float(self.cjfee_r)),
                self.minsize)
        elif self.ordertype in ('absoffer', 'swabsoffer'):
            f = str(self.txfee + self.cjfee_a)
        order = {'oid': 0,
                 'ordertype': self.ordertype,
                 'minsize': self.minsize,
                 'maxsize': mix_balance[max_mix] - max(
                     jm_single().DUST_THRESHOLD, self.txfee),
                 'txfee': self.txfee,
                 'cjfee': f}

        # sanity check
        assert order['minsize'] >= 0
        assert order['maxsize'] > 0
        if order['minsize'] > order['maxsize']:
            jlog.info('minsize (' + str(order['minsize']) + ') > maxsize (' + str(
                order['maxsize']) + ')')
            return []

        return [order]

    def oid_to_order(self, offer, amount):
        total_amount = amount + offer["txfee"]
        mix_balance = self.wallet.get_balance_by_mixdepth()
        max_mix = max(mix_balance, key=mix_balance.get)

        filtered_mix_balance = [m
                                for m in iteritems(mix_balance)
                                if m[1] >= total_amount]
        if not filtered_mix_balance:
            return None, None, None
        jlog.debug('mix depths that have enough = ' + str(filtered_mix_balance))
        filtered_mix_balance = sorted(filtered_mix_balance, key=lambda x: x[0])
        mixdepth = filtered_mix_balance[0][0]
        jlog.info('filling offer, mixdepth=' + str(mixdepth) + ', amount=' + str(amount))

        # mixdepth is the chosen depth we'll be spending from
        cj_addr = self.wallet.get_internal_addr(
            (mixdepth + 1) % (self.wallet.mixdepth + 1),
            jm_single().bc_interface)
        change_addr = self.wallet.get_internal_addr(mixdepth,
                                                    jm_single().bc_interface)

        utxos = self.wallet.select_utxos(mixdepth, total_amount)
        my_total_in = sum([va['value'] for va in utxos.values()])
        real_cjfee = calc_cj_fee(offer["ordertype"], offer["cjfee"], amount)
        change_value = my_total_in - amount - offer["txfee"] + real_cjfee
        if change_value <= jm_single().DUST_THRESHOLD:
            jlog.debug(('change value={} below dust threshold, '
                       'finding new utxos').format(change_value))
            try:
                utxos = self.wallet.select_utxos(
                    mixdepth, total_amount + jm_single().DUST_THRESHOLD)
            except Exception:
                jlog.info('dont have the required UTXOs to make a '
                          'output above the dust threshold, quitting')
                return None, None, None

        return utxos, cj_addr, change_addr

    def on_tx_confirmed(self, offer, confirmations, txid):
        if offer["cjaddr"] in self.tx_unconfirm_timestamp:
            confirm_time = int(time.time()) - self.tx_unconfirm_timestamp[
                offer["cjaddr"]]
        else:
            confirm_time = 0
        timestamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        real_cjfee = calc_cj_fee(offer["offer"]["ordertype"],
                                 offer["offer"]["cjfee"], offer["amount"])
        self.log_statement([timestamp, offer["amount"], len(
            offer["utxos"]), sum([av['value'] for av in offer["utxos"].values(
            )]), real_cjfee, real_cjfee - offer["offer"]["txfee"], round(
                confirm_time / 60.0, 2), ''])
        return self.on_tx_unconfirmed(offer, txid, None)

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
    parser.add_option('-m', '--mixdepth', action='store', type='int',
                      dest='mixdepth', default=None,
                      help="highest mixdepth to use")
    (options, args) = parser.parse_args()
    if len(args) < 1:
        parser.error('Needs a wallet')
        sys.exit(0)
    wallet_name = args[0]
    ordertype = options.ordertype
    txfee = options.txfee
    if ordertype in ('reloffer', 'swreloffer'):
        if options.cjfee != '':
            cjfee_r = options.cjfee
        # minimum size is such that you always net profit at least 20%
        #of the miner fee
        minsize = max(int(1.2 * txfee / float(cjfee_r)), options.minsize)
    elif ordertype in ('absoffer', 'swabsoffer'):
        if options.cjfee != '':
            cjfee_a = int(options.cjfee)
        minsize = options.minsize
    else:
        parser.error('You specified an incorrect offer type which ' +\
                     'can be either swreloffer or swabsoffer')
        sys.exit(0)
    nickserv_password = options.password

    load_program_config()

    wallet_path = get_wallet_path(wallet_name, 'wallets')
    wallet = open_test_wallet_maybe(
        wallet_path, wallet_name, options.mixdepth,
        gap_limit=options.gaplimit)

    if jm_single().config.get("BLOCKCHAIN", "blockchain_source") == "electrum-server":
        jm_single().bc_interface.synctype = "with-script"

    while not jm_single().bc_interface.wallet_synced:
        sync_wallet(wallet, fast=options.fastsync)

    maker = ygclass(wallet, [options.txfee, cjfee_a, cjfee_r,
                             options.ordertype, options.minsize])
    jlog.info('starting yield generator')
    clientfactory = JMClientProtocolFactory(maker, proto_type="MAKER")

    nodaemon = jm_single().config.getint("DAEMON", "no_daemon")
    daemon = True if nodaemon == 1 else False
    if jm_single().config.get("BLOCKCHAIN", "network") in ["regtest", "testnet"]:
        startLogging(sys.stdout)
    start_reactor(jm_single().config.get("DAEMON", "daemon_host"),
                      jm_single().config.getint("DAEMON", "daemon_port"),
                      clientfactory, daemon=daemon)
