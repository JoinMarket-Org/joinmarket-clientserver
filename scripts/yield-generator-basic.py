#! /usr/bin/env python
from __future__ import absolute_import, print_function

import datetime
import os
import time

from jmclient import YieldGenerator, ygmain, get_log, jm_single, calc_cj_fee
txfee = 1000
cjfee_a = 200
cjfee_r = '0.0002'
ordertype = 'swreloffer' #'swreloffer' or 'swabsoffer'
nickserv_password = ''
max_minsize = 100000
gaplimit = 6

jlog = get_log()

# is a maker for the purposes of generating a yield from held
# bitcoins, offering from the maximum mixdepth and trying to offer
# the largest amount within the constraints of mixing depth isolation.
# It will often (but not always) reannounce orders after transactions,
# thus is somewhat suboptimal in giving more information to spies.
class YieldGeneratorBasic(YieldGenerator):

    def __init__(self, wallet, offerconfig):
        self.txfee, self.cjfee_a, self.cjfee_r, self.ordertype, self.minsize \
             = offerconfig
        super(YieldGeneratorBasic,self).__init__(wallet)

    def create_my_orders(self):
        mix_balance = self.wallet.get_balance_by_mixdepth()
        if len([b for m, b in mix_balance.iteritems() if b > 0]) == 0:
            jlog.error('do not have any coins left')
            return []

        # print mix_balance
        max_mix = max(mix_balance, key=mix_balance.get)
        f = '0'
        if self.ordertype == 'swreloffer':
            f = self.cjfee_r
            #minimum size bumped if necessary such that you always profit
            #least 50% of the miner fee
            self.minsize = max(int(1.5 * self.txfee / float(self.cjfee_r)),
                max_minsize)
        elif self.ordertype == 'swabsoffer':
            f = str(self.txfee + self.cjfee_a)
        order = {'oid': 0,
                 'ordertype': self.ordertype,
                 'minsize': self.minsize,
                 'maxsize': mix_balance[max_mix] - max(
                     jm_single().DUST_THRESHOLD,txfee),
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
                                for m in mix_balance.iteritems()
                                if m[1] >= total_amount]
        if not filtered_mix_balance:
            return None, None, None
        jlog.debug('mix depths that have enough = ' + str(filtered_mix_balance))
        filtered_mix_balance = sorted(filtered_mix_balance, key=lambda x: x[0])
        mixdepth = filtered_mix_balance[0][0]
        jlog.info('filling offer, mixdepth=' + str(mixdepth))

        # mixdepth is the chosen depth we'll be spending from
        cj_addr = self.wallet.get_internal_addr((mixdepth + 1) %
                                                self.wallet.max_mix_depth)
        change_addr = self.wallet.get_internal_addr(mixdepth)

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

    def on_tx_unconfirmed(self, offer, txid, removed_utxos):
        self.tx_unconfirm_timestamp[offer["cjaddr"]] = int(time.time())
        # if the balance of the highest-balance mixing depth change then
        # reannounce it
        oldoffer = self.offerlist[0] if len(self.offerlist) > 0 else None
        newoffers = self.create_my_orders()
        if len(newoffers) == 0:
            return [0], []  # cancel old order
        if oldoffer:
            if oldoffer['maxsize'] == newoffers[0]['maxsize']:
                return [], []  # change nothing
        # announce new order, replacing the old order
        return [], [newoffers[0]]

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

if __name__ == "__main__":
    ygmain(YieldGeneratorBasic, txfee=txfee, cjfee_a=cjfee_a,
           cjfee_r=cjfee_r, ordertype=ordertype,
           nickserv_password=nickserv_password,
           minsize=max_minsize, gaplimit=gaplimit)
    print('done')
