
"""
Test doing payjoins over tcp client/server
"""

import os
from twisted.internet import reactor
from twisted.web.server import Site
from twisted.web.client import readBody
from twisted.web.http_headers import Headers
from twisted.trial import unittest
import urllib.parse as urlparse
from urllib.parse import urlencode

from jmbase import (get_log, jmprint, BytesProducer,
                    JMHTTPResource, get_nontor_agent,
                    wrapped_urlparse)
from jmbitcoin import (encode_bip21_uri,
                       amount_to_btc, amount_to_sat)
from jmclient import (load_test_config, jm_single,
                      SegwitLegacyWallet, SegwitWallet,
                      parse_payjoin_setup,
                      JMBIP78ReceiverManager)
from jmclient.payjoin import make_payjoin_request_params, make_payment_psbt
from jmclient.payjoin import process_payjoin_proposal_from_server
from commontest import make_wallets
from test_coinjoin import make_wallets_to_list, sync_wallets

testdir = os.path.dirname(os.path.realpath(__file__))
log = get_log()

class DummyBIP78ReceiverResource(JMHTTPResource):
    """ A simplified version of the BIP78Resource object created
    to serve requests in jmdaemon.
    """
    def __init__(self, info_callback, shutdown_callback, bip78receivermanager):
        assert isinstance(bip78receivermanager, JMBIP78ReceiverManager)
        self.bip78_receiver_manager = bip78receivermanager
        self.info_callback = info_callback
        self.shutdown_callback = shutdown_callback
        super().__init__(info_callback, shutdown_callback)

    def render_POST(self, request):
        proposed_tx = request.content
        payment_psbt_base64 = proposed_tx.read().decode("utf-8")
        retval = self.bip78_receiver_manager.receive_proposal_from_sender(
            payment_psbt_base64, request.args)
        assert retval[0]
        content = retval[1].encode("utf-8")
        request.setHeader(b"content-length", ("%d" % len(content)))
        return content

class PayjoinTestBase(object):
    """ This tests that a payjoin invoice and
    then payment of the invoice, results in the correct changes
    in balance in the sender and receiver wallets, while also
    implicitly testing all the BIP78 rules (failures are caught
    by the JMPayjoinManager and PayjoinConverter rules).
    """
    # the indices in our wallets to populate
    wallet_structure = [1, 3, 0, 0, 0]
    # the mean amount of each deposit in the above indices, in btc
    mean_amt = 2.0
    def setUp(self):
        load_test_config()
        jm_single().bc_interface.tick_forward_chain_interval = 5
        jm_single().bc_interface.simulate_blocks()

    def do_test_payment(self, wc1, wc2, amt=1.1):
        wallet_structures = [self.wallet_structure] * 2
        wallet_cls = (wc1, wc2)
        self.wallet_services = []
        self.wallet_services.append(make_wallets_to_list(make_wallets(
            1, wallet_structures=[wallet_structures[0]],
            mean_amt=self.mean_amt, wallet_cls=wallet_cls[0]))[0])
        self.wallet_services.append(make_wallets_to_list(make_wallets(
                1, wallet_structures=[wallet_structures[1]],
                mean_amt=self.mean_amt, wallet_cls=wallet_cls[1]))[0])
        jm_single().bc_interface.tickchain()
        sync_wallets(self.wallet_services)

        # For accounting purposes, record the balances
        # at the start.
        self.rsb = getbals(self.wallet_services[0], 0)
        self.ssb = getbals(self.wallet_services[1], 0)

        self.cj_amount = int(amt * 10**8)
        def cbStopListening():
            return self.port.stopListening()
        b78rm = JMBIP78ReceiverManager(self.wallet_services[0], 0,
                                       self.cj_amount, 47083)
        resource = DummyBIP78ReceiverResource(jmprint, cbStopListening, b78rm)
        self.site = Site(resource)
        self.site.displayTracebacks = False
        # NB The connectivity aspects of the onion-based BIP78 setup
        # are time heavy. This server is TCP only.
        self.port = reactor.listenTCP(47083, self.site)
        self.addCleanup(cbStopListening)

        # setup of spender
        bip78_btc_amount = amount_to_btc(amount_to_sat(self.cj_amount))
        bip78_uri = encode_bip21_uri(str(b78rm.receiving_address),
                                {"amount": bip78_btc_amount,
                                 "pj": b"http://127.0.0.1:47083"},
                                safe=":/")
        self.manager = parse_payjoin_setup(bip78_uri, self.wallet_services[1], 0)
        self.manager.mode = "testing"
        success, msg = make_payment_psbt(self.manager)
        assert success, msg
        params = make_payjoin_request_params(self.manager)
        # avoiding backend daemon (testing only jmclient code here),
        # we send the http request manually:
        serv = b"http://127.0.0.1:47083"
        agent = get_nontor_agent()
        body = BytesProducer(self.manager.initial_psbt.to_base64().encode("utf-8"))
        url_parts = list(wrapped_urlparse(serv))
        url_parts[4] = urlencode(params).encode("utf-8")
        destination_url = urlparse.urlunparse(url_parts)
        d = agent.request(b"POST", destination_url,
                          Headers({"Content-Type": ["text/plain"]}),
                          bodyProducer=body)
        d.addCallback(bip78_receiver_response, self.manager)
        return d

    def tearDown(self):
        for dc in reactor.getDelayedCalls():
            dc.cancel()
        res = final_checks(self.wallet_services, self.cj_amount,
                           self.manager.final_psbt.get_fee(),
                           self.ssb, self.rsb)
        assert res, "final checks failed"

class TrialTestPayjoin1(PayjoinTestBase, unittest.TestCase):
    def test_payment(self):
        return self.do_test_payment(SegwitLegacyWallet, SegwitLegacyWallet)

class TrialTestPayjoin2(PayjoinTestBase, unittest.TestCase):
    def test_bech32_payment(self):
        return self.do_test_payment(SegwitWallet, SegwitWallet)

class TrialTestPayjoin3(PayjoinTestBase, unittest.TestCase):
    def test_multi_input(self):
        # wallet structure and amt are chosen so that the sender
        # will need 3 utxos rather than 1 (to pay 4.5 from 2,2,2).
        self.wallet_structure = [3, 1, 0, 0, 0]
        return self.do_test_payment(SegwitWallet, SegwitWallet, amt=4.5)

class TrialTestPayjoin4(PayjoinTestBase, unittest.TestCase):
    def reset_fee(self, res):
        jm_single().config.set("POLICY", "txfees", self.old_txfees)
    def test_low_feerate(self):
        self.old_txfees = jm_single().config.get("POLICY", "tx_fees")
        # set such that randomization cannot pull it below minfeerate
        # (default of 1.1 sat/vbyte):
        jm_single().config.set("POLICY", "tx_fees", "1376")
        d = self.do_test_payment(SegwitWallet, SegwitWallet)
        d.addCallback(self.reset_fee)
        return d

def bip78_receiver_response(response, manager):
    d = readBody(response)
    # if the response code is not 200 OK, we must assume payjoin
    # attempt has failed, and revert to standard payment.
    if int(response.code) != 200:
        d.addCallback(process_receiver_errormsg, response.code)
        return
    d.addCallback(process_receiver_psbt, manager)

def process_receiver_errormsg(r, c):
    print("Failed: r, c: ", r, c)
    assert False

def process_receiver_psbt(response, manager):
    process_payjoin_proposal_from_server(response.decode("utf-8"), manager)

def getbals(wallet_service, mixdepth):
    """ Retrieves balances for a mixdepth and the 'next'
    """
    bbm = wallet_service.get_balance_by_mixdepth()
    return (bbm[mixdepth], bbm[(mixdepth + 1) % (wallet_service.mixdepth + 1)])

def final_checks(wallet_services, amount, txfee, ssb, rsb, source_mixdepth=0):
    """We use this to check that the wallet contents are
    as we've expected according to the test case.
    amount is the payment amount going from spender to receiver.
    txfee is the bitcoin network transaction fee, paid by the spender.
    ssb, rsb are spender and receiver starting balances, each a tuple
    of two entries, source and destination mixdepth respectively.
    """
    jm_single().bc_interface.tickchain()
    sync_wallets(wallet_services)
    spenderbals = getbals(wallet_services[1], source_mixdepth)
    receiverbals = getbals(wallet_services[0], source_mixdepth)
    # is the payment received?
    receiver_newcoin_amt = receiverbals[1] - rsb[1]
    if not receiver_newcoin_amt >= amount:
        print("Receiver expected to receive at least: ", amount,
              " but got: ", receiver_newcoin_amt)
        return False
    # assert that the receiver received net exactly the right amount
    receiver_spentcoin_amt = rsb[0] - receiverbals[0]
    if not receiver_spentcoin_amt >= 0:
        # for now allow the non-cj fallback case
        print("receiver's spent coin should have been positive, was: ", receiver_spentcoin_amt)
        return False
    if not receiver_newcoin_amt == amount + receiver_spentcoin_amt:
        print("receiver's new coins should have been: ", amount + receiver_spentcoin_amt,
              " but was: ", receiver_newcoin_amt)
        return False

    # Spender-side check
    # assert that the spender's total ending minus total starting
    # balance is the amount plus the txfee given.
    if not (sum(spenderbals) - sum(ssb) + txfee + amount) == 0:
        print("Taker should have spent: ", txfee + amount,
              " but spent: ", sum(ssb) - sum(spenderbals))
        return False
    print("Final checks were passed")
    return True
