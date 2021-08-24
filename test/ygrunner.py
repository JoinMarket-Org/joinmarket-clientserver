#! /usr/bin/env python
'''Creates wallets and yield generators in regtest. 
   Provides seed for joinmarket-qt test.
   This should be run via pytest, even though
   it's NOT part of the test-suite, because that
   makes it much easier to handle start up and
   shut down of the environment.
   Run it like:
   PYTHONPATH=.:$PYTHONPATH pytest \
   --btcroot=/path/to/bitcoin/bin/ \
   --btcpwd=123456abcdef --btcconf=/blah/bitcoin.conf \
   --nirc=2 -s test/ygrunner.py
   '''
from twisted.internet import task
from common import make_wallets
import pytest
import random
from datetime import datetime
from jmbase import jmprint
from jmclient import YieldGeneratorBasic, load_test_config, jm_single,\
    JMClientProtocolFactory, start_reactor, SegwitWallet,\
    SegwitLegacyWallet, cryptoengine, SNICKERClientProtocolFactory, SNICKERReceiver
from jmclient.wallet_utils import wallet_gettimelockaddress

# For quicker testing, restrict the range of timelock
# addresses to avoid slow load of multiple bots.
# Note: no need to revert this change as ygrunner runs
# in isolation.
from jmclient import FidelityBondMixin
FidelityBondMixin.TIMELOCK_ERA_YEARS = 2
FidelityBondMixin.TIMELOCK_EPOCH_YEAR = datetime.now().year
FidelityBondMixin.TIMENUMBERS_PER_PUBKEY = 12

class MaliciousYieldGenerator(YieldGeneratorBasic):
    """Overrides, randomly, some maker functions
    to prevent taker continuing successfully (unless
    they can complete-with-subset).
    """
    def set_maliciousness(self, frac, mtype=None):
        self.authmal = False
        self.txmal = False
        if mtype == "tx":
            self.txmal = True
        elif mtype == "auth":
            self.authmal = True
        else:
            self.txmal = True
            self.authmal = True
        self.mfrac = frac

    def on_auth_received(self, nick, offer, commitment, cr, amount, kphex):
        if self.authmal:
            if random.randint(1, 100) < self.mfrac:
                jmprint("Counterparty commitment rejected maliciously", "debug")
                return (False,)
        return super().on_auth_received(nick, offer, commitment, cr, amount, kphex)
    def on_tx_received(self, nick, tx, offerinfo):
        if self.txmal:
            if random.randint(1, 100) < self.mfrac:
                jmprint("Counterparty tx rejected maliciously", "debug")
                return (False, "malicious tx rejection")
        return super().on_tx_received(nick, tx, offerinfo)

class DeterministicMaliciousYieldGenerator(YieldGeneratorBasic):
    """Overrides, randomly chosen persistently, some maker functions
    to prevent taker continuing successfully (unless
    they can complete-with-subset).
    """
    def set_maliciousness(self, frac, mtype=None):
        self.authmal = False
        self.txmal = False
        if mtype == "tx":
            if random.randint(1, 100) < frac:
                self.txmal = True
        elif mtype == "auth":
            if random.randint(1, 100) < frac:
                self.authmal = True
        else:
            if random.randint(1, 100) < frac:
                self.txmal = True
                self.authmal = True

    def on_auth_received(self, nick, offer, commitment, cr, amount, kphex):
        if self.authmal:
            jmprint("Counterparty commitment rejected maliciously", "debug")
            return (False,)
        return super().on_auth_received(nick, offer, commitment, cr, amount, kphex)
    def on_tx_received(self, nick, tx, offerinfo):
        if self.txmal:
            jmprint("Counterparty tx rejected maliciously", "debug")
            return (False, "malicious tx rejection")
        return super().on_tx_received(nick, tx, offerinfo)


@pytest.mark.parametrize(
    "num_ygs, wallet_structures, fb_indices, mean_amt, malicious, deterministic",
    [
        # 1sp 3yg, honest makers, one maker has FB:
        (3, [[1, 3, 0, 0, 0]] * 4, [], 2, 0, False),
        # 1sp 3yg, malicious makers reject on auth and on tx 30% of time
        #(3, [[1, 3, 0, 0, 0]] * 4, 2, 30, False),
        # 1 sp 9 ygs, deterministically malicious 50% of time
        #(9, [[1, 3, 0, 0, 0]] * 10, 2, 50, True),
    ])
def test_start_ygs(setup_ygrunner, num_ygs, wallet_structures, fb_indices,
                   mean_amt, malicious, deterministic):
    """Set up some wallets, for the ygs and 1 sp.
    Then start the ygs in background and publish
    the seed of the sp wallet for easy import into -qt
    """
    if jm_single().config.get("POLICY", "native") == "true":
        walletclass = SegwitWallet
    else:
        # TODO add Legacy
        walletclass = SegwitLegacyWallet

    wallet_services = make_wallets(num_ygs + 1,
                           wallet_structures=wallet_structures,
                           mean_amt=mean_amt,
                           walletclass=walletclass,
                           fb_indices=fb_indices)
    #the sendpayment bot uses the last wallet in the list
    wallet_service = wallet_services[num_ygs]['wallet']
    jmprint("\n\nTaker wallet seed : " + wallet_services[num_ygs]['seed'])
    # for manual audit if necessary, show the maker's wallet seeds
    # also (note this audit should be automated in future, see
    # test_full_coinjoin.py in this directory)
    jmprint("\n\nMaker wallet seeds: ")
    for i in range(num_ygs):
        jmprint("Maker seed: " + wallet_services[i]['seed'])
    jmprint("\n")
    wallet_service.sync_wallet(fast=True)
    ygclass = YieldGeneratorBasic

    # As per previous note, override non-default command line settings:
    options = {}
    for x in ["ordertype", "txfee_contribution", "txfee_contribution_factor",
              "cjfee_a", "cjfee_r", "cjfee_factor", "minsize", "size_factor"]:
        options[x] = jm_single().config.get("YIELDGENERATOR", x)
    ordertype = options["ordertype"]
    txfee_contribution = int(options["txfee_contribution"])
    txfee_contribution_factor = float(options["txfee_contribution_factor"])
    cjfee_factor = float(options["cjfee_factor"])
    size_factor = float(options["size_factor"])
    if ordertype == 'reloffer':
        cjfee_r = options["cjfee_r"]
        # minimum size is such that you always net profit at least 20%
        #of the miner fee
        minsize = max(int(1.2 * txfee_contribution / float(cjfee_r)),
            int(options["minsize"]))
        cjfee_a = None
    elif ordertype == 'absoffer':
        cjfee_a = int(options["cjfee_a"])
        minsize = int(options["minsize"])
        cjfee_r = None
    else:
        assert False, "incorrect offertype config for yieldgenerator."

    txtype = wallet_service.get_txtype()
    if txtype == "p2wpkh":
        prefix = "sw0"
    elif txtype == "p2sh-p2wpkh":
        prefix = "sw"
    elif txtype == "p2pkh":
        prefix = ""
    else:
        assert False, "Unsupported wallet type for yieldgenerator: " + txtype

    ordertype = prefix + ordertype

    if malicious:
        if deterministic:
            ygclass = DeterministicMaliciousYieldGenerator
        else:
            ygclass = MaliciousYieldGenerator

    for i in range(num_ygs):
        cfg = [txfee_contribution, cjfee_a, cjfee_r, ordertype, minsize,
               txfee_contribution_factor, cjfee_factor, size_factor]
        wallet_service_yg = wallet_services[i]["wallet"]

        wallet_service_yg.startService()

        yg = ygclass(wallet_service_yg, cfg)
        if i in fb_indices:
            # create a timelocked address and fund it;
            # must be done after sync, so deferred:
            wallet_service_yg.timelock_funded = False
            sync_wait_loop = task.LoopingCall(get_addr_and_fund, yg)
            sync_wait_loop.start(1.0, now=False)
        if malicious:
            yg.set_maliciousness(malicious, mtype="tx")
        clientfactory = JMClientProtocolFactory(yg, proto_type="MAKER")
        if jm_single().config.get("SNICKER", "enabled") == "true":
            snicker_r = SNICKERReceiver(wallet_service_yg)
            servers = jm_single().config.get("SNICKER", "servers").split(",")
            snicker_factory = SNICKERClientProtocolFactory(snicker_r, servers)
        else:
            snicker_factory = None
        nodaemon = jm_single().config.getint("DAEMON", "no_daemon")
        daemon = True if nodaemon == 1 else False
        rs = True if i == num_ygs - 1 else False
        start_reactor(jm_single().config.get("DAEMON", "daemon_host"),
                      jm_single().config.getint("DAEMON", "daemon_port"),
                      clientfactory, snickerfactory=snicker_factory,
                      daemon=daemon, rs=rs)

def get_addr_and_fund(yg):
    """ This function allows us to create
    and publish a fidelity bond for a particular
    yield generator object after the wallet has reached
    a synced state and is therefore ready to serve up
    timelock addresses. We create the TL address, fund it,
    refresh the wallet and then republish our offers, which
    will also publish the new FB.
    """
    if not yg.wallet_service.synced:
        return
    if yg.wallet_service.timelock_funded:
        return
    addr = wallet_gettimelockaddress(yg.wallet_service.wallet, "2023-11")
    print("Got timelockaddress: {}".format(addr))

    # pay into it; amount is randomized for now.
    # Note that grab_coins already mines 1 block.
    fb_amt = random.randint(1, 5)
    jm_single().bc_interface.grab_coins(addr, fb_amt)

    # we no longer have to run this loop (TODO kill with nonlocal)
    yg.wallet_service.timelock_funded = True

    # force wallet to check for the new coins so the new
    # yg offers will include them:
    yg.wallet_service.transaction_monitor()

    # publish a new offer:
    yg.offerlist = yg.create_my_orders()
    yg.fidelity_bond = yg.get_fidelity_bond_template()
    jmprint('updated offerlist={}'.format(yg.offerlist))

@pytest.fixture(scope="module")
def setup_ygrunner():
    load_test_config()
    jm_single().bc_interface.tick_forward_chain_interval = 10
    jm_single().bc_interface.simulate_blocks()
    # handles the custom regtest hrp for bech32
    cryptoengine.BTC_P2WPKH.VBYTE = 100
