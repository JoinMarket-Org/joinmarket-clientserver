#! /usr/bin/env python
from __future__ import absolute_import, print_function
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
from common import make_wallets
import pytest
import random
from jmclient import YieldGeneratorBasic, load_program_config, jm_single,\
    sync_wallet, JMClientProtocolFactory, start_reactor


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
                print("Counterparty commitment rejected maliciously")
                return (False,)
        return super(MaliciousYieldGenerator, self).on_auth_received(nick,
                                    offer, commitment, cr, amount, kphex)
    def on_tx_received(self, nick, txhex, offerinfo):
        if self.txmal:
            if random.randint(1, 100) < self.mfrac:
                print("Counterparty tx rejected maliciously")
                return (False, "malicious tx rejection")
        return super(MaliciousYieldGenerator, self).on_tx_received(nick, txhex,
                                                                   offerinfo)

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
            print("Counterparty commitment rejected maliciously")
            return (False,)
        return super(DeterministicMaliciousYieldGenerator, self).on_auth_received(nick,
                                    offer, commitment, cr, amount, kphex)
    def on_tx_received(self, nick, txhex, offerinfo):
        if self.txmal:
            print("Counterparty tx rejected maliciously")
            return (False, "malicious tx rejection")
        return super(DeterministicMaliciousYieldGenerator, self).on_tx_received(nick, txhex,
                                                                   offerinfo)

@pytest.mark.parametrize(
    "num_ygs, wallet_structures, mean_amt, malicious, deterministic",
    [
        # 1sp 3yg, honest makers
        (3, [[1, 3, 0, 0, 0]] * 4, 2, 0, False),
        # 1sp 3yg, malicious makers reject on auth and on tx 30% of time
        #(3, [[1, 3, 0, 0, 0]] * 4, 2, 30, False),
        # 1 sp 9 ygs, deterministically malicious 50% of time
        #(9, [[1, 3, 0, 0, 0]] * 10, 2, 50, True),
    ])
def test_start_ygs(setup_ygrunner, num_ygs, wallet_structures, mean_amt,
                   malicious, deterministic):
    """Set up some wallets, for the ygs and 1 sp.
    Then start the ygs in background and publish
    the seed of the sp wallet for easy import into -qt
    """
    wallets = make_wallets(num_ygs + 1,
                           wallet_structures=wallet_structures,
                           mean_amt=mean_amt)
    #the sendpayment bot uses the last wallet in the list
    wallet = wallets[num_ygs]['wallet']
    print("Seed : " + wallets[num_ygs]['seed'])
    #useful to see the utxos on screen sometimes
    sync_wallet(wallet, fast=True)
    print(wallet.get_utxos_by_mixdepth())
    txfee = 1000
    cjfee_a = 4200
    cjfee_r = '0.001'
    ordertype = 'swreloffer'
    minsize = 100000
    ygclass = YieldGeneratorBasic
    if malicious:
        if deterministic:
            ygclass = DeterministicMaliciousYieldGenerator
        else:
            ygclass = MaliciousYieldGenerator
    for i in range(num_ygs):
        
        cfg = [txfee, cjfee_a, cjfee_r, ordertype, minsize]
        sync_wallet(wallets[i]["wallet"], fast=True)
        yg = ygclass(wallets[i]["wallet"], cfg)
        if malicious:
            yg.set_maliciousness(malicious, mtype="tx")
        clientfactory = JMClientProtocolFactory(yg, proto_type="MAKER")
        nodaemon = jm_single().config.getint("DAEMON", "no_daemon")
        daemon = True if nodaemon == 1 else False
        rs = True if i == num_ygs - 1 else False
        start_reactor(jm_single().config.get("DAEMON", "daemon_host"),
                      jm_single().config.getint("DAEMON", "daemon_port"),
                      clientfactory, daemon=daemon, rs=rs)

@pytest.fixture(scope="module")
def setup_ygrunner():
    load_program_config()
    jm_single().bc_interface.tick_forward_chain_interval = 10
    jm_single().bc_interface.simulate_blocks()