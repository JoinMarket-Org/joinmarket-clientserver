#! /usr/bin/env python
from future.utils import iteritems

import random

from jmbase import get_log, jmprint
from jmclient import YieldGeneratorBasic, ygmain, jm_single


# This is a maker for the purposes of generating a yield from held bitcoins
# while maximising the difficulty of spying on blockchain activity.
# This is primarily attempted by randomizing all aspects of orders
# after transactions wherever possible.

"""THESE SETTINGS CAN SIMPLY BE EDITED BY HAND IN THIS FILE:
"""

ordertype = 'swreloffer'  # [string, 'swreloffer' or 'swabsoffer'] / which fee type to actually use
cjfee_a = 500             # [satoshis, any integer] / absolute offer fee you wish to receive for coinjoins (cj)
cjfee_r = '0.00002'       # [percent, any str between 0-1] / relative offer fee you wish to receive based on a cj's amount
cjfee_factor = 0.1        # [percent, 0-1] / variance around the average fee. Ex: 200 fee, 0.2 var = fee is btw 160-240
txfee = 100               # [satoshis, any integer] / the average transaction fee you're adding to coinjoin transactions
txfee_factor = 0.3        # [percent, 0-1] / variance around the average fee. Ex: 1000 fee, 0.2 var = fee is btw 800-1200
minsize = 1000000         # [satoshis, any integer] / minimum size of your cj offer. Lower cj amounts will be disregarded
size_factor = 0.1         # [percent, 0-1] / variance around all offer sizes. Ex: 500k minsize, 0.1 var = 450k-550k
gaplimit = 6

# end of settings customization

jlog = get_log()

class YieldGeneratorPrivacyEnhanced(YieldGeneratorBasic):

    def __init__(self, wallet_service, offerconfig):
        super(YieldGeneratorPrivacyEnhanced, self).__init__(wallet_service, offerconfig)

    def create_my_orders(self):
        mix_balance = self.get_available_mixdepths()
        # We publish ONLY the maximum amount and use minsize for lower bound;
        # leave it to oid_to_order to figure out the right depth to use.
        f = '0'
        if ordertype == 'swreloffer':
            f = self.cjfee_r
        elif ordertype == 'swabsoffer':
            f = str(self.txfee + self.cjfee_a)
        mix_balance = dict([(m, b) for m, b in iteritems(mix_balance)
                            if b > self.minsize])
        if len(mix_balance) == 0:
            jlog.error('You do not have the minimum required amount of coins'
                       ' to be a maker: ' + str(minsize))
            return []
        max_mix = max(mix_balance, key=mix_balance.get)

        # randomizing the different values
        randomize_txfee = int(random.uniform(txfee * (1 - float(txfee_factor)),
                                             txfee * (1 + float(txfee_factor))))
        randomize_minsize = int(random.uniform(self.minsize * (1 - float(size_factor)),
                                               self.minsize * (1 + float(size_factor))))
        possible_maxsize = mix_balance[max_mix] - max(jm_single().DUST_THRESHOLD, randomize_txfee)
        randomize_maxsize = int(random.uniform(possible_maxsize * (1 - float(size_factor)),
                                               possible_maxsize))

        if ordertype == 'swabsoffer':
            randomize_cjfee = int(random.uniform(float(cjfee_a) * (1 - float(cjfee_factor)),
                                                 float(cjfee_a) * (1 + float(cjfee_factor))))
            randomize_cjfee = randomize_cjfee + randomize_txfee
        else:
            randomize_cjfee = random.uniform(float(f) * (1 - float(cjfee_factor)),
                                             float(f) * (1 + float(cjfee_factor)))
            randomize_cjfee = "{0:.6f}".format(randomize_cjfee)  # round to 6 decimals

        order = {'oid': 0,
                 'ordertype': self.ordertype,
                 'minsize': randomize_minsize,
                 'maxsize': randomize_maxsize,
                 'txfee': randomize_txfee,
                 'cjfee': str(randomize_cjfee)}

        # sanity check
        assert order['minsize'] >= 0
        assert order['maxsize'] > 0
        assert order['minsize'] <= order['maxsize']
        if order['ordertype'] == 'swreloffer':
            while order['txfee'] >= (float(order['cjfee']) * order['minsize']):
                order['txfee'] = int(order['txfee'] / 2)
                jlog.info('Warning: too high txfee to be profitable, halfing it to: ' + str(order['txfee']))

        return [order]


if __name__ == "__main__":
    ygmain(YieldGeneratorPrivacyEnhanced, txfee=txfee, cjfee_a=cjfee_a,
           cjfee_r=cjfee_r, ordertype=ordertype,
           nickserv_password='',
           minsize=minsize, gaplimit=gaplimit)
    jmprint('done', "success")
