#! /usr/bin/env python

import datetime
import os
import time
import abc
import base64
from jmclient.wallet import WatchonlyMixin
from twisted.python.log import startLogging
from optparse import OptionParser
from jmbase import get_log
from jmclient import (Maker, jm_single, load_program_config,
                      JMClientProtocolFactory, start_reactor, calc_cj_fee,
                      WalletService, add_base_options, SNICKERReceiver,
                      SNICKERClientProtocolFactory, FidelityBondMixin,
                      get_interest_rate, fmt_utxo)
from .wallet_utils import open_test_wallet_maybe, get_wallet_path
from jmbase.support import EXIT_ARGERROR, EXIT_FAILURE, get_jm_version_str
import jmbitcoin as btc
from jmclient.fidelity_bond import FidelityBond

jlog = get_log()

MAX_MIX_DEPTH = 5


class NoIoauthInputException(Exception):
    pass


class YieldGenerator(Maker):
    """A maker for the purposes of generating a yield from held
    bitcoins, offering from the maximum mixdepth and trying to offer
    the largest amount within the constraints of mixing depth isolation.
    """
    __metaclass__ = abc.ABCMeta

    def __init__(self, wallet_service):
        Maker.__init__(self, wallet_service)
        jlog.info(get_jm_version_str())
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
    def __init__(self, wallet_service, offerconfig, cswallet_service = None, csconfig = None):
        # note the randomizing entries are ignored in this base class:
        self.txfee, self.cjfee_a, self.cjfee_r, self.ordertype, self.minsize, \
            self.txfee_factor, self.cjfee_factor, self.size_factor = offerconfig
        
        if cswallet_service:
            assert isinstance(cswallet_service, WalletService)
            self.cs_min_balance, self.cs_min_txsize, self.cs_mixdepth = csconfig
        self.cswallet_service = cswallet_service
        
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

    def get_fidelity_bond_template(self):
        if not isinstance(self.wallet_service.wallet, FidelityBondMixin):
            jlog.info("Not a fidelity bond wallet, not announcing fidelity bond")
            return None
        blocks = jm_single().bc_interface.get_current_block_height()
        mediantime = jm_single().bc_interface.get_best_block_median_time()

        BLOCK_COUNT_SAFETY = 2 #use this safety number to reduce chances of the proof expiring
                               #before the taker gets a chance to verify it
        RETARGET_INTERVAL = 2016
        CERT_MAX_VALIDITY_TIME = 1
        cert_expiry = ((blocks + BLOCK_COUNT_SAFETY) // RETARGET_INTERVAL) + CERT_MAX_VALIDITY_TIME

        utxos = self.wallet_service.wallet.get_utxos_by_mixdepth(include_disabled=True,
            includeheight=True)[FidelityBondMixin.FIDELITY_BOND_MIXDEPTH]
        timelocked_utxos = [(outpoint, info) for outpoint, info in utxos.items()
            if FidelityBondMixin.is_timelocked_path(info["path"])]
        if len(timelocked_utxos) == 0:
            jlog.info("No timelocked coins in wallet, not announcing fidelity bond")
            return
        timelocked_utxos_with_confirmation_time = [(outpoint, info,
            jm_single().bc_interface.get_block_time(
                jm_single().bc_interface.get_block_hash(info["height"])
            ))
            for (outpoint, info) in timelocked_utxos]

        interest_rate = get_interest_rate()
        max_valued_bond = max(timelocked_utxos_with_confirmation_time, key=lambda x:
            FidelityBondMixin.calculate_timelocked_fidelity_bond_value(x[1]["value"], x[2],
                x[1]["path"][-1], mediantime, interest_rate)
        )
        (utxo_priv, locktime), engine = self.wallet_service.wallet._get_key_from_path(
            max_valued_bond[1]["path"])
        utxo_pub = engine.privkey_to_pubkey(utxo_priv)
        cert_priv = os.urandom(32) + b"\x01"
        cert_pub = btc.privkey_to_pubkey(cert_priv)
        cert_msg = b"fidelity-bond-cert|" + cert_pub + b"|" + str(cert_expiry).encode("ascii")
        cert_sig = base64.b64decode(btc.ecdsa_sign(cert_msg, utxo_priv))
        utxo = (max_valued_bond[0][0], max_valued_bond[0][1])
        fidelity_bond = FidelityBond(utxo, utxo_pub, locktime, cert_expiry,
                                     cert_priv, cert_pub, cert_sig)
        jlog.info("Announcing fidelity bond coin {}".format(fmt_utxo(utxo)))
        return fidelity_bond

    def oid_to_order(self, offer, amount):
        total_amount = amount + offer["txfee"]
        real_cjfee = calc_cj_fee(offer["ordertype"], offer["cjfee"], amount)
        required_amount = total_amount + \
            jm_single().DUST_THRESHOLD + 1 - real_cjfee

        mix_balance = self.get_available_mixdepths()
        filtered_mix_balance = {m: b
                                for m, b in mix_balance.items()
                                if b >= required_amount}
        if not filtered_mix_balance:
            return None, None, None
        jlog.debug('mix depths that have enough = ' + str(filtered_mix_balance))

        try:
            mixdepth, utxos = self._get_order_inputs(
                filtered_mix_balance, offer, required_amount)
        except NoIoauthInputException:
            jlog.error(
                'unable to fill order, no suitable IOAUTH UTXO found. In '
                'order to spend coins (UTXOs) from a mixdepth using coinjoin,'
                ' there needs to be at least one standard wallet UTXO (not '
                'fidelity bond or different address type).')
            return None, None, None

        jlog.info('filling offer, mixdepth=' + str(mixdepth) + ', amount=' + str(amount))

        cj_addr = self.select_output_address(mixdepth, offer, amount)
        if cj_addr is None:
            return None, None, None
        jlog.info('sending output to address=' + str(cj_addr))

        change_addr = self.wallet_service.get_internal_addr(mixdepth)
        return utxos, cj_addr, change_addr

    def _get_order_inputs(self, filtered_mix_balance, offer, required_amount):
        """
        Select inputs from some applicable mixdepth that has a utxo suitable
        for ioauth.

        params:
            filtered_mix_balance: see get_available_mixdepths() output
            offer: offer dict
            required_amount: int, total inputs value in sat

        returns:
            mixdepth, utxos (int, dict)

        raises:
            NoIoauthInputException: if no provided mixdepth has a suitable utxo
        """
        while filtered_mix_balance:
            mixdepth = self.select_input_mixdepth(
                filtered_mix_balance, offer, required_amount)
            utxos = self.wallet_service.select_utxos(
                mixdepth, required_amount, minconfs=1, includeaddr=True,
                require_auth_address=True)
            if utxos:
                return mixdepth, utxos
            filtered_mix_balance.pop(mixdepth)
        raise NoIoauthInputException()

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

    def should_use_cswallet(self, input_mixdepth, amount):
        if not self.cswallet_service:
            return False

        if input_mixdepth != self.cs_mixdepth:
            jlog.debug("input mixdepth {} dosen't match cs_mixdepth {}".format(
                input_mixdepth, self.cs_mixdepth))
            return False

        if amount < self.cs_min_txsize:
            jlog.debug("coin join size {} is less than cs_min_txsize {}".format(
                amount, self.cs_min_txsize))
            return False

        # Check if the wallet balance can maintain the min balance after this coin join
        total_wallet_balance = sum(self.wallet_service.get_balance_by_mixdepth().values())
        if total_wallet_balance - amount < self.cs_min_balance:
            jlog.debug("total_wallet_balance - amount {} is less than cs_min_balance {}".format(
                total_wallet_balance - amount, self.cs_min_balance))
            return False
        else:
            jlog.debug("sending coin join output to cold storage wallet {}".format(
                self.cswallet_service.get_wallet_name()))
            return True

    def select_output_address(self, input_mixdepth, offer, amount):
        """Returns the address to which the mixed output should be sent for
        an order spending from the given input mixdepth.  Can return None if
        there is no suitable output, in which case the order is
        aborted."""
        if self.should_use_cswallet(input_mixdepth, amount):
            output_address = self.cswallet_service.get_internal_addr(WatchonlyMixin.WATCH_ONLY_MIXDEPTH)
            jlog.info("sending coin join output to cold storage wallet {} at address {}".format(
                self.cswallet_service.get_wallet_name(), output_address))
            return output_address
        else:
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
    parser.add_option('-c', '--cswallet', action='store', type='string',
                      dest='cswallet_name', default=None,
                      help='a watch only cold storage wallet to send coinjoin output to')
    parser.add_option('-d', '--cs-mixdepth', action='store', type='int',
                      dest='cs_mixdepth', default=4,
                      help='only send coinjoin output to cold storage from this mixdepth')
    parser.add_option('-x', '--cs-min-txsize', action='store', type='int',
                      dest='cs_min_txsize', default=100000000,
                      help='minimum coinjoin size in satoshis for sending to cold storage')
    parser.add_option('-b', '--cs-min-balance', action='store', type='int',
                      dest='cs_min_balance', default=500000000,
                      help='minimum balalance in satoshis to keep locally')
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

    cswallet_name = options["cswallet_name"]
    cs_min_balance = int(options["cs_min_balance"])
    cs_min_txsize = int(options["cs_min_txsize"])
    cs_mixdepth = int(options["cs_mixdepth"])

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

    if cswallet_name:
        cswallet_path = get_wallet_path(cswallet_name, None)
        cswallet = open_test_wallet_maybe(
            cswallet_path, cswallet_name, 0,
            wallet_password_stdin=options["wallet_password_stdin"],
            gap_limit=options["gaplimit"])
            
        cswallet_service = WalletService(cswallet)
        while not cswallet_service.synced:
            cswallet_service.sync_wallet(fast=not options["recoversync"])
        cswallet_service.startService()
    else:
        cswallet_service = None

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
                             cjfee_factor, size_factor],
                    cswallet_service, [cs_min_balance, cs_min_txsize, cs_mixdepth])

    jlog.info('starting yield generator')
    clientfactory = JMClientProtocolFactory(maker, proto_type="MAKER")
    if jm_single().config.get("SNICKER", "enabled") == "true":
        if jm_single().config.get("BLOCKCHAIN", "network") == "mainnet":
            jlog.error("You have enabled SNICKER on mainnet, this is not "
                       "yet supported for yieldgenerators; either use "
                       "signet/regtest/testnet, or run SNICKER manually "
                       "with snicker/receive-snicker.py.")
            sys.exit(EXIT_ARGERROR)
        snicker_r = SNICKERReceiver(wallet_service)
        servers = jm_single().config.get("SNICKER", "servers").split(",")
        snicker_factory = SNICKERClientProtocolFactory(snicker_r, servers)
    else:
        snicker_factory = None
    nodaemon = jm_single().config.getint("DAEMON", "no_daemon")
    daemon = True if nodaemon == 1 else False
    if jm_single().config.get("BLOCKCHAIN", "network") in ["regtest", "testnet", "signet"]:
        startLogging(sys.stdout)
    start_reactor(jm_single().config.get("DAEMON", "daemon_host"),
                      jm_single().config.getint("DAEMON", "daemon_port"),
                      clientfactory, snickerfactory=snicker_factory,
                      daemon=daemon)
