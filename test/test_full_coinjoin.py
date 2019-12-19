#! /usr/bin/env python
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401
'''Runs a full joinmarket pit (using `nirc` miniircd servers,
with `nirc` options specified as an option to pytest),in
bitcoin regtest mode with 3 maker bots and 1 taker bot,
and does 1 coinjoin. This is intended as an E2E sanity check
but certainly could be extended further.
'''

from common import make_wallets
import pytest
import sys
from jmclient import YieldGeneratorBasic, load_test_config, jm_single,\
    sync_wallet, JMClientProtocolFactory, start_reactor, Taker, \
    random_under_max_order_choose
from jmbase.support import get_log
from twisted.internet import reactor
from twisted.python.log import startLogging

log = get_log()

# Note that this parametrization is inherited (i.e. copied) from
# the previous 'ygrunner.py' script which is intended to be run
# manually to test out complex scenarios. Here, we only run one
# simple test with honest makers (and for simplicity malicious
# makers are not included in the code). Vars are left in in case
# we want to do more complex stuff in the automated tests later.
@pytest.mark.parametrize(
    "num_ygs, wallet_structures, mean_amt, malicious, deterministic",
    [
        # 1sp 3yg, honest makers
        (3, [[1, 3, 0, 0, 0]] * 4, 2, 0, False),
    ])
def test_cj(setup_full_coinjoin, num_ygs, wallet_structures, mean_amt,
                   malicious, deterministic):
    """Starts by setting up wallets for maker and taker bots; then,
    instantiates a single taker with the final wallet.
    The remaining wallets are used to set up YieldGenerators (basic form).
    All the wallets are given coins according to the rules of make_wallets,
    using the parameters for the values.
    The final start_reactor call is the only one that actually starts the
    reactor; the others only set up protocol instances.
    Inline are custom callbacks for the Taker, and these are basically
    copies of those in the `sendpayment.py` script for now, but they could
    be customized later for testing.
    The Taker's schedule is a single coinjoin, using basically random values,
    again this could be easily edited or parametrized if we feel like it.
    """

    # Set up some wallets, for the ygs and 1 sp.
    wallets = make_wallets(num_ygs + 1,
                           wallet_structures=wallet_structures,
                           mean_amt=mean_amt)
    #the sendpayment bot uses the last wallet in the list
    wallet = wallets[num_ygs]['wallet']
    sync_wallet(wallet, fast=True)
    # grab a dest addr from the wallet
    destaddr = wallet.get_external_addr(4)
    coinjoin_amt = 20000000
    schedule = [[1, coinjoin_amt, 2, destaddr,
                     0.0, False]]

    """ The following two callback functions are as simple as possible
    modifications of the same in scripts/sendpayment.py
    """
    def filter_orders_callback(orders_fees, cjamount):
        return True

    def taker_finished(res, fromtx=False, waittime=0.0, txdetails=None):
        def final_checks():
            sync_wallet(wallet, fast=True)
            newbal = wallet.get_balance_by_mixdepth()[4]
            oldbal = wallet.get_balance_by_mixdepth()[1]
            # These are our check that the coinjoin succeeded
            assert newbal == coinjoin_amt
            # TODO: parametrize these; cj fees = 38K (.001 x 20M x 2 makers)
            # minus 1K tx fee contribution each; 600M is original balance
            # in mixdepth 1
            assert oldbal + newbal + (40000 - 2000) + taker.total_txfee == 600000000

        if fromtx == "unconfirmed":
            #If final entry, stop *here*, don't wait for confirmation
            if taker.schedule_index + 1 == len(taker.schedule):
                reactor.stop()
                final_checks()
                return
        if fromtx:
            # currently this test uses a schedule with only one entry
            assert False, "taker_finished was called with fromtx=True"
            reactor.stop()
            return
        else:
            if not res:
                assert False, "Did not complete successfully, shutting down"
            # Note that this is required in both conditional branches,
            # especially in testing, because it's possible to receive the
            # confirmed callback before the unconfirmed.
            reactor.stop()
            final_checks()

    # twisted logging is required for debugging:
    startLogging(sys.stdout)

    taker = Taker(wallet,
                  schedule,
                  order_chooser=random_under_max_order_choose,
                  max_cj_fee=(0.1, 200),
                  callbacks=(filter_orders_callback, None, taker_finished))
    clientfactory = JMClientProtocolFactory(taker)
    nodaemon = jm_single().config.getint("DAEMON", "no_daemon")
    daemon = True if nodaemon == 1 else False
    start_reactor(jm_single().config.get("DAEMON", "daemon_host"),
                  jm_single().config.getint("DAEMON", "daemon_port"),
                  clientfactory, daemon=daemon, rs=False)

    txfee = 1000
    cjfee_a = 4200
    cjfee_r = '0.001'
    ordertype = 'swreloffer'
    minsize = 100000
    ygclass = YieldGeneratorBasic
    # As noted above, this is not currently used but can be in future:
    if malicious or deterministic:
        raise NotImplementedError
    for i in range(num_ygs):
        cfg = [txfee, cjfee_a, cjfee_r, ordertype, minsize]
        sync_wallet(wallets[i]["wallet"], fast=True)
        yg = ygclass(wallets[i]["wallet"], cfg)
        if malicious:
            yg.set_maliciousness(malicious, mtype="tx")
        clientfactory = JMClientProtocolFactory(yg, proto_type="MAKER")
        nodaemon = jm_single().config.getint("DAEMON", "no_daemon")
        daemon = True if nodaemon == 1 else False
        # As noted above, only the final start_reactor() call will
        # actually start it!
        rs = True if i == num_ygs - 1 else False
        start_reactor(jm_single().config.get("DAEMON", "daemon_host"),
                      jm_single().config.getint("DAEMON", "daemon_port"),
                      clientfactory, daemon=daemon, rs=rs)

@pytest.fixture(scope="module")
def setup_full_coinjoin():
    load_test_config()
    jm_single().bc_interface.tick_forward_chain_interval = 10
    jm_single().bc_interface.simulate_blocks()
