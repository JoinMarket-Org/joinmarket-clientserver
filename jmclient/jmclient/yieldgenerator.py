#! /usr/bin/env python

import datetime
import os
import time
import abc
from twisted.python.log import startLogging
from optparse import OptionParser
from jmbase import get_log
from jmclient import Maker, jm_single, load_program_config, \
    JMClientProtocolFactory, start_reactor, calc_cj_fee, \
    WalletService, add_base_options
from .wallet_utils import open_test_wallet_maybe, get_wallet_path
from jmbase.support import EXIT_ARGERROR, EXIT_FAILURE

jlog = get_log()

MAX_MIX_DEPTH = 5

class YieldGenerator(Maker):
    """A maker for the purposes of generating a yield from held
    bitcoins, offering from the maximum mixdepth and trying to offer
    the largest amount within the constraints of mixing depth isolation.
    """
    __metaclass__ = abc.ABCMeta

    def __init__(self, wallet_service):
        Maker.__init__(self, wallet_service)
        self.tx_unconfirm_timestamp = {}
        self.statement_file = os.path.join(jm_single().datadir,
                                      'logs', 'yigen-statement.csv')
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

    def on_tx_unconfirmed(self, offer, txid):
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
    def __init__(self, wallet_service, offerconfig):
        # note the randomizing entries are ignored in this base class:
        self.txfee, self.cjfee_a, self.cjfee_r, self.ordertype, self.minsize, \
            self.txfee_factor, self.cjfee_factor, self.size_factor = offerconfig
        super().__init__(wallet_service)

    def create_my_orders(self):
        mix_balance = self.get_available_mixdepths()
        if len([b for m, b in mix_balance.items() if b > 0]) == 0:
            jlog.error('do not have any coins left')
            return []

        max_mix = max(mix_balance, key=mix_balance.get)
        f = '0'
        if self.ordertype in ('reloffer', 'swreloffer', 'sw0reloffer'):
            f = self.cjfee_r
            #minimum size bumped if necessary such that you always profit
            #least 50% of the miner fee
            self.minsize = max(int(1.5 * self.txfee / float(self.cjfee_r)),
                self.minsize)
        elif self.ordertype in ('absoffer', 'swabsoffer', 'sw0absoffer'):
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
        mix_balance = self.get_available_mixdepths()

        filtered_mix_balance = {m: b
                                for m, b in mix_balance.items()
                                if b >= total_amount}
        if not filtered_mix_balance:
            return None, None, None
        jlog.debug('mix depths that have enough = ' + str(filtered_mix_balance))
        mixdepth = self.select_input_mixdepth(filtered_mix_balance, offer, amount)
        if mixdepth is None:
            return None, None, None
        jlog.info('filling offer, mixdepth=' + str(mixdepth) + ', amount=' + str(amount))

        cj_addr = self.select_output_address(mixdepth, offer, amount)
        if cj_addr is None:
            return None, None, None
        jlog.info('sending output to address=' + str(cj_addr))

        change_addr = self.wallet_service.get_internal_addr(mixdepth)

        utxos = self.wallet_service.select_utxos(mixdepth, total_amount,
                                        minconfs=1, includeaddr=True)
        my_total_in = sum([va['value'] for va in utxos.values()])
        real_cjfee = calc_cj_fee(offer["ordertype"], offer["cjfee"], amount)
        change_value = my_total_in - amount - offer["txfee"] + real_cjfee
        if change_value <= jm_single().DUST_THRESHOLD:
            jlog.debug(('change value={} below dust threshold, '
                       'finding new utxos').format(change_value))
            try:
                utxos = self.wallet_service.select_utxos(mixdepth,
                    total_amount + jm_single().DUST_THRESHOLD,
                    minconfs=1, includeaddr=True)
            except Exception:
                jlog.info('dont have the required UTXOs to make a '
                          'output above the dust threshold, quitting')
                return None, None, None

        return utxos, cj_addr, change_addr

    def on_tx_confirmed(self, offer, txid, confirmations):
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
        return self.on_tx_unconfirmed(offer, txid)

    def get_available_mixdepths(self):
        """Returns the mixdepth/balance dict from the wallet that contains
        all available inputs for offers."""
        return self.wallet_service.get_balance_by_mixdepth(verbose=False,
                                                           minconfs=1)

    def select_input_mixdepth(self, available, offer, amount):
        """Returns the mixdepth from which the given order should spend the
        inputs.  available is a mixdepth/balance dict of all the mixdepths
        that can be chosen from, i.e. have enough balance.  If there is no
        suitable input, the function can return None to abort the order."""
        available = sorted(available.items(), key=lambda entry: entry[0])
        return available[0][0]

    def select_output_address(self, input_mixdepth, offer, amount):
        """Returns the address to which the mixed output should be sent for
        an order spending from the given input mixdepth.  Can return None if
        there is no suitable output, in which case the order is
        aborted."""
        cjoutmix = (input_mixdepth + 1) % (self.wallet_service.mixdepth + 1)
        return self.wallet_service.get_internal_addr(cjoutmix)


def ygmain(ygclass, nickserv_password='', gaplimit=6):
    import sys

    parser = OptionParser(usage='usage: %prog [options] [wallet file]')
    add_base_options(parser)
    # A note about defaults:
    # We want command line settings to override config settings.
    # This would naturally mean setting `default=` arguments here, to the
    # values in the config.
    # However, we cannot load the config until we know the datadir.
    # The datadir is a setting in the command line options, so we have to
    # call parser.parse_args() before we know the datadir.
    # Hence we do the following: set all modifyable-by-config arguments to
    # default "None" initially; call parse_args(); then call load_program_config
    # and override values of "None" with what is set in the config.
    # (remember, the joinmarket defaultconfig always sets every value, even if
    # the user doesn't).
    parser.add_option('-o', '--ordertype', action='store', type='string',
                      dest='ordertype', default=None,
                      help='type of order; can be either reloffer or absoffer')
    parser.add_option('-t', '--txfee', action='store', type='int',
                      dest='txfee', default=None,
                      help='minimum miner fee in satoshis')
    parser.add_option('-f', '--txfee-factor', action='store', type='float',
                      dest='txfee_factor', default=None,
                      help='variance around the average fee, decimal fraction')
    parser.add_option('-a', '--cjfee-a', action='store', type='string',
                      dest='cjfee_a', default=None,
                      help='requested coinjoin fee (absolute) in satoshis')
    parser.add_option('-r', '--cjfee-r', action='store', type='string',
                      dest='cjfee_r', default=None,
                      help='requested coinjoin fee (relative) as a decimal')
    parser.add_option('-j', '--cjfee-factor', action='store', type='float',
                      dest='cjfee_factor', default=None,
                      help='variance around the average fee, decimal fraction')
    parser.add_option('-p', '--password', action='store', type='string',
                      dest='password', default=nickserv_password,
                      help='irc nickserv password')
    parser.add_option('-s', '--minsize', action='store', type='int',
                      dest='minsize', default=None,
                      help='minimum coinjoin size in satoshis')
    parser.add_option('-z', '--size-factor', action='store', type='float',
                      dest='size_factor', default=None,
                      help='variance around all offer sizes, decimal fraction')
    parser.add_option('-g', '--gap-limit', action='store', type="int",
                      dest='gaplimit', default=gaplimit,
                      help='gap limit for wallet, default='+str(gaplimit))
    parser.add_option('-m', '--mixdepth', action='store', type='int',
                      dest='mixdepth', default=None,
                      help="highest mixdepth to use")
    (options, args) = parser.parse_args()
    # for string access, convert to dict:
    options = vars(options)
    if len(args) < 1:
        parser.error('Needs a wallet')
        sys.exit(EXIT_ARGERROR)

    load_program_config(config_path=options["datadir"])

    # As per previous note, override non-default command line settings:
    for x in ["ordertype", "txfee", "txfee_factor", "cjfee_a", "cjfee_r",
              "cjfee_factor", "minsize", "size_factor"]:
        if options[x] is None:
            options[x] = jm_single().config.get("YIELDGENERATOR", x)
    wallet_name = args[0]
    ordertype = options["ordertype"]
    txfee = int(options["txfee"])
    txfee_factor = float(options["txfee_factor"])
    cjfee_factor = float(options["cjfee_factor"])
    size_factor = float(options["size_factor"])
    if ordertype == 'reloffer':
        cjfee_r = options["cjfee_r"]
        # minimum size is such that you always net profit at least 20%
        #of the miner fee
        minsize = max(int(1.2 * txfee / float(cjfee_r)), int(options["minsize"]))
        cjfee_a = None
    elif ordertype == 'absoffer':
        cjfee_a = int(options["cjfee_a"])
        minsize = int(options["minsize"])
        cjfee_r = None
    else:
        parser.error('You specified an incorrect offer type which ' +\
                     'can be either reloffer or absoffer')
        sys.exit(EXIT_ARGERROR)
    nickserv_password = options["password"]

    if jm_single().bc_interface is None:
        jlog.error("Running yield generator requires configured " +
            "blockchain source.")
        sys.exit(EXIT_FAILURE)

    wallet_path = get_wallet_path(wallet_name, None)
    wallet = open_test_wallet_maybe(
        wallet_path, wallet_name, options["mixdepth"],
        wallet_password_stdin=options["wallet_password_stdin"],
        gap_limit=options["gaplimit"])

    wallet_service = WalletService(wallet)
    while not wallet_service.synced:
        wallet_service.sync_wallet(fast=not options["recoversync"])
    wallet_service.startService()

    txtype = wallet_service.get_txtype()
    if txtype == "p2wpkh":
        prefix = "sw0"
    elif txtype == "p2sh-p2wpkh":
        prefix = "sw"
    elif txtype == "p2pkh":
        prefix = ""
    else:
        jlog.error("Unsupported wallet type for yieldgenerator: " + txtype)
        sys.exit(EXIT_ARGERROR)

    ordertype = prefix + ordertype
    jlog.debug("Set the offer type string to: " + ordertype)

    maker = ygclass(wallet_service, [txfee, cjfee_a, cjfee_r,
                             ordertype, minsize, txfee_factor,
                             cjfee_factor, size_factor])
    jlog.info('starting yield generator')
    clientfactory = JMClientProtocolFactory(maker, proto_type="MAKER")

    nodaemon = jm_single().config.getint("DAEMON", "no_daemon")
    daemon = True if nodaemon == 1 else False
    if jm_single().config.get("BLOCKCHAIN", "network") in ["regtest", "testnet"]:
        startLogging(sys.stdout)
    start_reactor(jm_single().config.get("DAEMON", "daemon_host"),
                      jm_single().config.getint("DAEMON", "daemon_port"),
                      clientfactory, daemon=daemon)
