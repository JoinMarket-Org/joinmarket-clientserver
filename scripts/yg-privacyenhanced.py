#!/usr/bin/env python3
import random
import sys

from jmbase import get_log, jmprint, EXIT_ARGERROR
from jmbitcoin import amount_to_str
from jmclient import YieldGeneratorBasic, ygmain, jm_single

# This is a maker for the purposes of generating a yield from held bitcoins
# while maximising the difficulty of spying on blockchain activity.
# This is primarily attempted by randomizing all aspects of orders
# after transactions wherever possible.

# YIELD GENERATOR SETTINGS ARE NOW IN YOUR joinmarket.cfg CONFIG FILE
# (You can also use command line flags; see --help for this script).

jlog = get_log()

class YieldGeneratorPrivacyEnhanced(YieldGeneratorBasic):

    def __init__(self, wallet_service, offerconfig):
        super().__init__(wallet_service, offerconfig)

    def select_input_mixdepth(self, available, offer, amount):
        """Mixdepths are in cyclic order and we select the mixdepth to
        maximize the largest interval of non-available mixdepths by choosing
        the first mixdepth available after the largest such interval.
        This forces the biggest UTXOs to stay in a bulk of few mixdepths so
        that the maker can always maximize the size of his orders even when
        some coins are sent from the last to the first mixdepth"""
        # We sort the available depths for linear scaling of the interval search
        available = sorted(available.keys())
        # For an available mixdepth, the smallest interval starting from this mixdepth
        # containing all the other available mixdepths necessarily ends at the previous
        # available mixdepth in the cyclic order. The successive difference of sorted
        # depths is then the length of the largest interval ending at the same mixdepth
        # without any available mixdepths, modulo the number of mixdepths if 0 is in it
        # which is only the case for the first (in linear order) available mixdepth case
        intervals = ([self.wallet_service.mixdepth + 1 + available[0] - available[-1]] + \
                    [(available[i+1] - available[i]) for i in range(len(available)-1)])
        # We return the mixdepth value at which the largest interval without
        # available mixdepths ends. Selecting this mixdepth will send the CoinJoin
        # outputs closer to the others available mixdepths which are after in cyclical order
        return available[max(range(len(available)), key = intervals.__getitem__)]

    def create_my_orders(self):
        mix_balance = self.get_available_mixdepths()
        # We publish ONLY the maximum amount and use minsize for lower bound;
        # leave it to oid_to_order to figure out the right depth to use.
        f = '0'
        if self.ordertype in ['swreloffer', 'sw0reloffer']:
            f = self.cjfee_r
        elif self.ordertype in ['swabsoffer', 'sw0absoffer']:
            f = str(self.txfee_contribution + self.cjfee_a)
        mix_balance = dict([(m, b) for m, b in mix_balance.items() if b > self.minsize])
        if len(mix_balance) == 0:
            jlog.error('You do not have the minimum required amount of coins'
                       ' to be a maker: ' + str(self.minsize) + \
                       '\nTry setting txfee_contribution to zero and/or '
                       'lowering the minsize.')
            return []
        max_mix = max(mix_balance, key=mix_balance.get)

        # randomizing the different values
        randomize_txfee = int(random.uniform(
            self.txfee_contribution * (1 - float(self.txfee_contribution_factor)),
            self.txfee_contribution * (1 + float(self.txfee_contribution_factor))))
        randomize_minsize = int(random.uniform(
            self.minsize * (1 - float(self.size_factor)),
            self.minsize * (1 + float(self.size_factor))))
        if randomize_minsize < jm_single().DUST_THRESHOLD:
            jlog.warn("Minsize was randomized to below dust; resetting to dust "
                      "threshold: " + amount_to_str(jm_single().DUST_THRESHOLD))
            randomize_minsize = jm_single().DUST_THRESHOLD
        possible_maxsize = mix_balance[max_mix] - max(jm_single().DUST_THRESHOLD, randomize_txfee)
        randomize_maxsize = int(random.uniform(possible_maxsize * (1 - float(self.size_factor)),
                                               possible_maxsize))

        if self.ordertype in ['swabsoffer', 'sw0absoffer']:
            randomize_cjfee = int(random.uniform(float(self.cjfee_a) * (1 - float(self.cjfee_factor)),
                                                 float(self.cjfee_a) * (1 + float(self.cjfee_factor))))
            randomize_cjfee = randomize_cjfee + randomize_txfee
        else:
            randomize_cjfee = random.uniform(float(f) * (1 - float(self.cjfee_factor)),
                                             float(f) * (1 + float(self.cjfee_factor)))
            randomize_cjfee = "{0:.6f}".format(randomize_cjfee)  # round to 6 decimals

        order = {'oid': 0,
                 'ordertype': self.ordertype,
                 'minsize': randomize_minsize,
                 'maxsize': randomize_maxsize,
                 'txfee': randomize_txfee,
                 'cjfee': str(randomize_cjfee),
                 # TODO: add some randomization factor here?
                 'minimum_tx_fee_rate': self.minimum_tx_fee_rate}

        # sanity check
        assert order['minsize'] >= jm_single().DUST_THRESHOLD
        assert order['minsize'] <= order['maxsize']
        if order['ordertype'] in ['swreloffer', 'sw0reloffer']:
            for i in range(20):
                if order['txfee'] < (float(order['cjfee']) * order['minsize']):
                    break
                order['txfee'] = int(order['txfee'] / 2)
                jlog.info('Warning: too high txfee to be profitable, halving it to: ' + str(order['txfee']))
            else:
                jlog.error("Tx fee reduction algorithm failed. Quitting.")
                sys.exit(EXIT_ARGERROR)
        return [order]


if __name__ == "__main__":
    ygmain(YieldGeneratorPrivacyEnhanced, nickserv_password='')
    jmprint('done', "success")
