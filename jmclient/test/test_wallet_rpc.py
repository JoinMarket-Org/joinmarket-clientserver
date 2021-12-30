import os, json
from twisted.internet import reactor, defer, task

from twisted.web.client import readBody, Headers
from twisted.trial import unittest

from autobahn.twisted.websocket import WebSocketClientFactory, \
    connectWS

from jmbase import get_nontor_agent, hextobin, BytesProducer, get_log
from jmbitcoin import CTransaction
from jmclient import (load_test_config, jm_single, SegwitWalletFidelityBonds,
                      JMWalletDaemon, validate_address, start_reactor)
from jmclient.wallet_rpc import api_version_string, CJ_MAKER_RUNNING, CJ_NOT_RUNNING
from commontest import make_wallets
from test_coinjoin import make_wallets_to_list, sync_wallets

from test_websocket import (ClientTProtocol, test_tx_hex_1,
                            test_tx_hex_txid, encoded_token)

testdir = os.path.dirname(os.path.realpath(__file__))

testfileloc = "testwrpc.jmdat"

jlog = get_log()

class JMWalletDaemonT(JMWalletDaemon):
    def check_cookie(self, request):
        if self.auth_disabled:
            return True
        return super().check_cookie(request)

class WalletRPCTestBase(object):
    """ Base class for set up of tests of the
    Wallet RPC calls using the wallet_rpc.JMWalletDaemon service.
    """
    # the indices in our wallets to populate
    wallet_structure = [1, 3, 0, 0, 0]
    # the mean amount of each deposit in the above indices, in btc
    mean_amt = 2.0
    # the port for the jmwallet daemon
    dport = 28183
    # the port for the ws
    wss_port = 28283
    
    def setUp(self):
        load_test_config()
        self.clean_out_wallet_file()
        jm_single().bc_interface.tick_forward_chain_interval = 5
        jm_single().bc_interface.simulate_blocks()
        # a client connnection object which is often but not always
        # instantiated:
        self.client_connector = None
        # start the daemon; note we are using tcp connections
        # to avoid storing certs in the test env.
        # TODO change that.
        self.daemon = JMWalletDaemonT(self.dport, self.wss_port, tls=False)
        self.daemon.auth_disabled = False
        # because we sync and start the wallet service manually here
        # (and don't use wallet files yet), we won't have set a wallet name,
        # so we set it here:
        self.daemon.wallet_name = testfileloc
        r, s = self.daemon.startService()
        self.listener_rpc = r
        self.listener_ws = s
        wallet_structures = [self.wallet_structure] * 2
        # note: to test fidelity bond wallets we should add the argument
        # `wallet_cls=SegwitWalletFidelityBonds` here, but it slows the
        # test down from 9 seconds to 1 minute 40s, which is too slow
        # to be acceptable. TODO: add a test with FB by speeding up
        # the sync for test, by some means or other.
        self.daemon.wallet_service = make_wallets_to_list(make_wallets(
            1, wallet_structures=[wallet_structures[0]],
            mean_amt=self.mean_amt, wallet_cls=SegwitWalletFidelityBonds))[0]
        jm_single().bc_interface.tickchain()
        sync_wallets([self.daemon.wallet_service])
        # dummy tx example to force a notification event:
        self.test_tx = CTransaction.deserialize(hextobin(test_tx_hex_1))

    def get_route_root(self):
        addr = "http://127.0.0.1:" + str(self.dport)
        addr += api_version_string
        return addr

    def clean_out_wallet_file(self):
        if os.path.exists(os.path.join(".", "wallets", testfileloc)):
            os.remove(os.path.join(".", "wallets", testfileloc))

    def tearDown(self):
        self.clean_out_wallet_file()
        for dc in reactor.getDelayedCalls():
            dc.cancel()        
        d1 = defer.maybeDeferred(self.listener_ws.stopListening)
        d2 = defer.maybeDeferred(self.listener_rpc.stopListening)
        if self.client_connector:
            self.client_connector.disconnect()
        # only fire if everything is finished:
        return defer.gatherResults([d1, d2])

class TrialTestWRPC_WS(WalletRPCTestBase, unittest.TestCase):
    """ class for testing websocket subscriptions/events etc.
    """
    def test_notif(self):
        # simulate the daemon already having created
        # a valid token (which it usually does when
        # starting the WalletService:
        self.daemon.wss_factory.valid_token = encoded_token
        self.client_factory = WebSocketClientFactory(
            "ws://127.0.0.1:"+str(self.wss_port))
        self.client_factory.protocol = ClientTProtocol
        self.client_connector = connectWS(self.client_factory)
        d = task.deferLater(reactor, 0.1, self.fire_tx_notif)
        # create a small delay between the instruction to send
        # the notification, and the checking of its receipt,
        # otherwise the client will be queried before the notification
        # arrived:
        d.addCallback(self.wait_to_receive)
        return d

    def wait_to_receive(self, res):
        d = task.deferLater(reactor, 0.1, self.checkNotifs)
        return d
    
    def checkNotifs(self):
        assert self.client_factory.notifs == 1

    def fire_tx_notif(self):
        self.daemon.wss_factory.sendTxNotification(self.test_tx,
                                            test_tx_hex_txid)

class TrialTestWRPC_DisplayWallet(WalletRPCTestBase, unittest.TestCase):

    @defer.inlineCallbacks
    def do_request(self, agent, method, addr, body, handler, token=None):
        if token:
            headers = Headers({"Authorization": ["Bearer " + self.jwt_token]})
        else:
            headers = None
        response = yield agent.request(method, addr, headers, bodyProducer=body)
        yield self.response_handler(response, handler)

    @defer.inlineCallbacks
    def response_handler(self, response, handler):
        body = yield readBody(response)
        # handlers check the body is as expected; no return.
        yield handler(body, response.code)
        return True

    @defer.inlineCallbacks
    def test_create_list_lock_unlock(self):
        """ A batch of tests in sequence here,
            so we can track the state of a created
            wallet and check it is what is expected.
            We test create first, so we have a wallet.

        1. create a wallet and have it persisted
           to disk in ./wallets, and get a token.
        2. list wallets and check they contain the new
           wallet.
        3. lock the existing wallet service, using the token.
        4. Unlock the wallet with /unlock, get a token.
        """
        # before starting, we have to shut down the existing
        # wallet service (usually this would be `lock`):
        self.daemon.wallet_service = None
        self.daemon.stopService()
        self.daemon.auth_disabled = False

        agent = get_nontor_agent()
        root = self.get_route_root()
        addr = root + "/wallet/create"
        addr = addr.encode()
        body = BytesProducer(json.dumps({"walletname": testfileloc,
                "password": "hunter2", "wallettype": "sw-fb"}).encode())
        yield self.do_request(agent, b"POST", addr, body,
                              self.process_create_wallet_response)

        addr = root + "/wallet/all"
        addr = addr.encode()
        # does not require a token, though we just got one.
        yield self.do_request(agent, b"GET", addr, None,
                               self.process_list_wallets_response)

        # now *lock* the existing, which will shut down the wallet
        # service associated.
        addr = root + "/wallet/" + self.daemon.wallet_name + "/lock"
        addr = addr.encode()
        jlog.info("Using address: {}".format(addr))
        yield self.do_request(agent, b"GET", addr, None,
                self.process_lock_response, token=self.jwt_token)
        # wallet service should now be stopped.
        addr = root + "/wallet/" + self.daemon.wallet_name + "/unlock"
        addr = addr.encode()
        body = BytesProducer(json.dumps({"password": "hunter2"}).encode())
        yield self.do_request(agent, b"POST", addr, body,
                              self.process_unlock_response)


    def process_create_wallet_response(self, response, code):
        assert code == 201
        json_body = json.loads(response.decode("utf-8"))
        assert json_body["walletname"] == testfileloc
        self.jwt_token = json_body["token"]
        # we don't use this in test, but it must exist:
        assert json_body["seedphrase"]

    def process_list_wallets_response(self, body, code):
        assert code == 200
        json_body = json.loads(body.decode("utf-8"))
        assert json_body["wallets"] == [testfileloc]

    @defer.inlineCallbacks
    def test_direct_send_and_display_wallet(self):
        """ First spend a coin, then check the balance
        via the display wallet output.
        """
        self.daemon.auth_disabled = True
        agent = get_nontor_agent()
        addr = self.get_route_root()
        addr += "/wallet/"
        addr += self.daemon.wallet_name
        addr += "/taker/direct-send"
        addr = addr.encode()
        body = BytesProducer(json.dumps({"mixdepth": "1",
            "amount_sats": "100000000",
            "destination": "2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br"}).encode())
        yield self.do_request(agent, b"POST", addr, body,
                              self.process_direct_send_response)
        # force the wallet service txmonitor to wake up, to see the new
        # tx before querying /display:
        self.daemon.wallet_service.transaction_monitor()
        addr = self.get_route_root()
        addr += "/wallet/"
        addr += self.daemon.wallet_name
        addr += "/display"
        addr = addr.encode()
        yield self.do_request(agent, b"GET", addr, None,
                              self.process_wallet_display_response)

    def process_direct_send_response(self, response, code):
        assert code == 200
        json_body = json.loads(response.decode("utf-8"))
        assert "txinfo" in json_body
        # TODO tx check
        print(json_body["txinfo"])

    def process_wallet_display_response(self, response, code):
        assert code == 200
        json_body = json.loads(response.decode("utf-8"))
        latest_balance = float(json_body["walletinfo"]["total_balance"])
        jlog.info("Wallet display currently shows balance: {}".format(
            latest_balance))
        assert latest_balance > self.mean_amt * 4.0 - 1.1
        assert latest_balance <= self.mean_amt * 4.0 - 1.0

    @defer.inlineCallbacks
    def test_getaddress(self):
        """ Tests that we can source a valid address
        for deposits using getaddress.
        """
        self.daemon.auth_disabled = True
        agent = get_nontor_agent()
        addr = self.get_route_root()
        addr += "/wallet/"
        addr += self.daemon.wallet_name
        addr += "/address/new/3"
        addr = addr.encode()
        yield self.do_request(agent, b"GET", addr, None,
                              self.process_new_addr_response)

    @defer.inlineCallbacks
    def test_maker_start_stop(self):
        """ Tests that we can start the maker service.
        As for the taker coinjoin test, this is currently
        a simple/artificial test, only checking return status
        codes and state updates, but not checking that an actual
        backend maker service is started.
        """
        self.daemon.auth_disabled = True
        agent = get_nontor_agent()
        addr_start = self.get_route_root()
        addr_start += "/wallet/"
        addr_start += self.daemon.wallet_name
        addr = addr_start + "/maker/start"
        addr = addr.encode()
        body = BytesProducer(json.dumps({"txfee": "0",
            "cjfee_a": "1000", "cjfee_r": "0.0002",
            "ordertype": "reloffer", "minsize": "1000000"}).encode())
        yield self.do_request(agent, b"POST", addr, body,
                              self.process_maker_start)
        # For the second phase, since we are not currently processing
        # via actual backend connections, we need to mock the client
        # protocol instance that requests shutdown of all message channels:
        class DummyMakerClientProto(object):
            def request_mc_shutdown(self):
                jlog.info("Message channel shutdown request registered.")
        self.daemon.services["maker"].clientfactory.proto_client = \
            DummyMakerClientProto()
        addr = addr_start + "/maker/stop"
        addr = addr.encode()
        yield self.do_request(agent, b"GET", addr, None,
                              self.process_maker_stop)

    def process_maker_start(self, request, code):
        assert code == 202
        assert self.daemon.coinjoin_state == CJ_MAKER_RUNNING

    def process_maker_stop(self, request, code):
        assert code == 202
        assert self.daemon.coinjoin_state == CJ_NOT_RUNNING

    @defer.inlineCallbacks
    def test_gettimelockaddress(self):
        self.daemon.auth_disabled = True
        agent = get_nontor_agent()
        addr = self.get_route_root()
        addr += "/wallet/"
        addr += self.daemon.wallet_name
        addr += "/address/timelock/new/2023-02"
        addr = addr.encode()
        yield self.do_request(agent, b"GET", addr, None,
                              self.process_new_addr_response)

    def process_new_addr_response(self, response, code):
        assert code == 200
        json_body = json.loads(response.decode("utf-8"))
        assert validate_address(json_body["address"])[0]

    @defer.inlineCallbacks
    def test_listutxos(self):
        self.daemon.auth_disabled = True
        agent = get_nontor_agent()
        addr = self.get_route_root()
        addr += "/wallet/"
        addr += self.daemon.wallet_name
        addr += "/utxos"
        addr = addr.encode()
        yield self.do_request(agent, b"GET", addr, None,
                              self.process_listutxos_response)

    def process_listutxos_response(self, response, code):
        assert code == 200
        json_body = json.loads(response.decode("utf-8"))
        # some fragility in test structure here: what utxos we
        # have depend on what other tests occurred.
        # For now, we at least check that we have 3 utxos in mixdepth
        # 1 because none of the other tests spend them:
        mixdepth1_utxos = 0
        for d in json_body["utxos"]:
            if d["mixdepth"] == 1:
                mixdepth1_utxos += 1
        assert mixdepth1_utxos == 3

    @defer.inlineCallbacks
    def test_session(self):
        agent = get_nontor_agent()
        addr = self.get_route_root()
        addr += "/session"
        addr = addr.encode()
        yield self.do_request(agent, b"GET", addr, None,
                              self.process_session_response)

    def process_session_response(self, response, code):
        assert code == 200
        json_body = json.loads(response.decode("utf-8"))
        assert json_body["maker_running"] is False
        assert json_body["coinjoin_in_process"] is False

    def process_unlock_response(self, response, code):
        assert code == 200
        json_body = json.loads(response.decode("utf-8"))
        assert json_body["walletname"] == testfileloc
        self.jwt_token = json_body["token"]

    def process_lock_response(self, response, code):
        assert code == 200
        json_body = json.loads(response.decode("utf-8"))
        assert json_body["walletname"] == testfileloc

    @defer.inlineCallbacks
    def test_do_coinjoin(self):
        """ This slightly weird test curently only
        tests *requesting* a coinjoin; because there are
        no makers running in the test suite, the Taker will
        give up early due to the empty orderbook, but that is
        OK since this API call only makes the request.
        """
        self.daemon.auth_disabled = True
        # in normal operations, the RPC call will trigger
        # the jmclient to connect to an *existing* daemon
        # that was created on startup, but here, that daemon
        # does not yet exist, so we will get 503 Backend Not Ready,
        # unless we manually create it:
        scon, ccon = start_reactor(jm_single().config.get("DAEMON",
                    "daemon_host"), jm_single().config.getint("DAEMON",
                    "daemon_port"), None, daemon=True, rs=False)
        # must be manually set:
        self.scon = scon
        agent = get_nontor_agent()
        addr = self.get_route_root()
        addr += "/wallet/"
        addr += self.daemon.wallet_name
        addr += "/taker/coinjoin"
        addr = addr.encode()
        body = BytesProducer(json.dumps({"mixdepth": "1",
            "amount_sats": "22000000",
            "counterparties": "2",
            "destination": "2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br"}).encode())
        yield self.do_request(agent, b"POST", addr, body,
                              self.process_do_coinjoin_response)

    def process_do_coinjoin_response(self, response, code):
        assert code == 202
        # response code is already checked to be 200
        clientconn = self.daemon.coinjoin_connection
        # backend's AMP connection must be cleaned up, otherwise
        # test will fail for unclean reactor:
        self.addCleanup(clientconn.disconnect)
        self.addCleanup(self.scon.stopListening)
        assert json.loads(response.decode("utf-8")) == {}
"""
Sample listutxos response for reference:

{
	"utxos": [{
		"utxo": "e01f349b1b5659c01f09ec70ca418a26d34f573e13f878db46dff39763e4dd15:0",
		"address": "bcrt1qxgqw54x46kmkkg6g23kdfuy76mfhc4m88shg4n",
		"value": 200000000,
		"tries": 0,
		"tries_remaining": 3,
		"external": false,
		"mixdepth": 0,
		"confirmations": 5,
		"frozen": false
	}, {
		"utxo": "eba94a0011e0f3f97a9c49be7f6ae38eb75bbeacd8c1797425e9005d80ec2f70:0",
		"address": "bcrt1qz5p304dj54g9nxh87afyvwpkv0jd3lydka6nfp",
		"value": 200000000,
		"tries": 0,
		"tries_remaining": 3,
		"external": false,
		"mixdepth": 1,
		"confirmations": 4,
		"frozen": false
	}, {
		"utxo": "fd5f181f1c1d1d47f3f110c3426769e60450e779addabf3f57f1732099ecdf97:0",
		"address": "bcrt1qu7k4dppungsqp95nwc7ansqs9m0z95h72j9mze",
		"value": 200000000,
		"tries": 0,
		"tries_remaining": 3,
		"external": false,
		"mixdepth": 1,
		"confirmations": 3,
		"frozen": false
	}, {
		"utxo": "03de36659e18068d272e182b2a57fdf8364d0d8c9aaf1b8c971a1590fa983cd5:0",
		"address": "bcrt1qk0thvwz8djvnynv2cmq7706ff9tjxcjef3cr7l",
		"value": 200000000,
		"tries": 0,
		"tries_remaining": 3,
		"external": false,
		"mixdepth": 1,
		"confirmations": 2,
		"frozen": false
	}]
}
"""

"""
Sample displaywallet response for reference:
[{"succeed": true, "status": 200, "walletname": "testwrpc.jmdat", "walletinfo": {"wallet_name": "JM wallet", "total_balance": "6.99998570", "accounts": [{"account": "0", "account_balance": "2.00000000", "branches": [{"branch": "external addresses\tm/84'/1'/0'/0\ttpubDExGchYUujKhNNYvVMjW6S9X4B3Cd3mNqm19vknwovH8buM7GJACi6gCi8Qc9Q9ejBx7phVRUrJFNT5GwpcUSTLqEKNbdCEaKLMdKfgp6Yd", "balance": "2.00000000", "entries": [{"hd_path": "m/84'/1'/0'/0/0", "address": "bcrt1qk4txxx2xzdz8y6yg2w60l9lea6h3k3el7jqnxk", "amount": "2.00000000", "labels": "used"}]}, {"branch": "internal addresses\tm/84'/1'/0'/1\t", "balance": "0.00000000", "entries": []}]}, {"account": "1", "account_balance": "4.99998570", "branches": [{"branch": "external addresses\tm/84'/1'/1'/0\ttpubDET2QAFuGCcmMhzJ6E7yTKUD5Fc8PqnL81yxmb2YZuWcG2MmhoUjLERK7S2gwyGPM1wiaCxWRjWXjnw3KgC9X2wMN38YRj3z4yz43HoMP67", "balance": "4.00000000", "entries": [{"hd_path": "m/84'/1'/1'/0/0", "address": "bcrt1qyqa9sawgwmkpy3pg599mv6peyg9uag8s2pdkpr", "amount": "2.00000000", "labels": "used"}, {"hd_path": "m/84'/1'/1'/0/1", "address": "bcrt1q0ky7pwdzpftd3jy6w6rt8krap2tsrcuzjte69y", "amount": "2.00000000", "labels": "used"}]}, {"branch": "internal addresses\tm/84'/1'/1'/1\t", "balance": "0.99998570", "entries": [{"hd_path": "m/84'/1'/1'/1/0", "address": "bcrt1qjdnnz5w75upqquvcsksyyeq0u9c2m5j9eld0nf", "amount": "0.99998570", "labels": "used"}]}]}, {"account": "2", "account_balance": "0.00000000", "branches": [{"branch": "external addresses\tm/84'/1'/2'/0\ttpubDEGRBmiDr2tqdcQFCVykULPzmuvTUeXCrG6w7C46wp7wrncU1hPpSzoYKn44kw6J6i5doWLSx8bzkjBeh8HvqRVPzJBetuq5xeV2iFWwS6q", "balance": "0.00000000", "entries": []}, {"branch": "internal addresses\tm/84'/1'/2'/1\t", "balance": "0.00000000", "entries": []}]}, {"account": "3", "account_balance": "0.00000000", "branches": [{"branch": "external addresses\tm/84'/1'/3'/0\ttpubDFa44cU854x2qYsHgWU1CFNaNRyQwaceXEHb41BEWw97KMmpaWP9JrbdF3mnzCq1se8GbnT5Ra7erPrh8vSCCNqPUsmsahYVZ3dgVg19dWF", "balance": "0.00000000", "entries": []}, {"branch": "internal addresses\tm/84'/1'/3'/1\t", "balance": "0.00000000", "entries": []}]}, {"account": "4", "account_balance": "0.00000000", "branches": [{"branch": "external addresses\tm/84'/1'/4'/0\ttpubDFK8hTjQBCEz3aaiDeyucPX56DBZprCpJZ5Jrb2cHiWDTudBTYtj6EHSxXypnQQFPAfJH6zVVnC6YzeHBsc79XErY1AkQrJkayySMhKhQbK", "balance": "0.00000000", "entries": []}, {"branch": "internal addresses\tm/84'/1'/4'/1\t", "balance": "0.00000000", "entries": []}]}]}}]
"""
