import base64
import datetime
import functools
import json
import os

import jwt
import pytest
from twisted.internet import reactor, defer, task
from twisted.web.client import readBody, Headers
from twisted.trial import unittest
from autobahn.twisted.websocket import WebSocketClientFactory, \
    connectWS

from jmbase import get_nontor_agent, hextobin, BytesProducer, get_log
from jmbase.support import get_free_tcp_ports, JM_CORE_VERSION
from jmbitcoin import CTransaction
from jmclient import (
    load_test_config,
    jm_single,
    SegwitWalletFidelityBonds,
    JMWalletDaemon,
    validate_address,
    start_reactor,
    SegwitWallet,
    storage,
)
from jmclient.wallet_rpc import api_version_string, CJ_MAKER_RUNNING, CJ_NOT_RUNNING
from commontest import make_wallets
from test_coinjoin import make_wallets_to_list, sync_wallets

from test_websocket import ClientTProtocol, test_tx_hex_1, test_tx_hex_txid

pytestmark = pytest.mark.usefixtures("setup_regtest_bitcoind")

testdir = os.path.dirname(os.path.realpath(__file__))

testfilename = "testwrpc"

jlog = get_log()

def ensure_deferred(func):
    def wrapper(*args, **kwargs):
        return defer.ensureDeferred(func(*args, **kwargs))
    return wrapper

class JMWalletDaemonT(JMWalletDaemon):
    def check_cookie(self, request, *args, **kwargs):
        if self.auth_disabled:
            return True
        return super().check_cookie(request, *args, **kwargs)

class WalletRPCTestBase(object):
    """ Base class for set up of tests of the
    Wallet RPC calls using the wallet_rpc.JMWalletDaemon service.
    """
    # the indices in our wallets to populate
    wallet_structure = [1, 3, 0, 0, 0]
    # the mean amount of each deposit in the above indices, in btc
    mean_amt = 2.0
    # the port for the jmwallet daemon (auto)
    dport = None
    # the port for the ws (auto)
    wss_port = None
    # how many different wallets we need
    num_wallet_files = 2
    # wallet type
    wallet_cls = SegwitWallet

    def setUp(self):
        load_test_config()
        self.clean_out_wallet_files()
        jm_single().bc_interface.tick_forward_chain_interval = 5
        jm_single().bc_interface.simulate_blocks()
        # a client connnection object which is often but not always
        # instantiated:
        self.client_connector = None
        # start the daemon; note we are using tcp connections
        # to avoid storing certs in the test env.
        # TODO change that.
        if self.dport is None and self.wss_port is None:
            free_ports = get_free_tcp_ports(2)
            self.dport = free_ports[0]
            self.wss_port = free_ports[1]
        elif self.dport is None:
            free_ports = get_free_tcp_ports(1)
            self.dport = free_ports[0]
        elif self.wss_port is None:
            free_ports = get_free_tcp_ports(1)
            self.wss_port = free_ports[0]
        self.daemon = JMWalletDaemonT(self.dport, self.wss_port, tls=False)
        self.daemon.auth_disabled = False
        # because we sync and start the wallet service manually here
        # (and don't use wallet files yet), we won't have set a wallet name,
        # so we set it here:
        self.daemon.wallet_name = self.get_wallet_file_name(1)
        self.daemon.token.wallet_name = self.daemon.wallet_name
        r, s = self.daemon.startService()
        self.listener_rpc = r
        self.listener_ws = s
        wallet_structures = [self.wallet_structure] * 2
        self.daemon.services["wallet"] = make_wallets_to_list(make_wallets(
            1, wallet_structures=[wallet_structures[0]],
            mean_amt=self.mean_amt, wallet_cls=self.wallet_cls))[0]
        jm_single().bc_interface.tickchain()
        sync_wallets([self.daemon.services["wallet"]])
        # dummy tx example to force a notification event:
        self.test_tx = CTransaction.deserialize(hextobin(test_tx_hex_1))
        # auth token is not set at the start
        self.jwt_token = None

    def get_route_root(self):
        addr = "http://127.0.0.1:" + str(self.dport)
        addr += api_version_string
        return addr

    def clean_out_wallet_files(self):
        for i in range(1, self.num_wallet_files + 1):
            wfn = self.get_wallet_file_name(i, fullpath=True)
            if os.path.exists(wfn):
                os.remove(wfn)

            parent, name = os.path.split(wfn)
            lockfile = os.path.join(parent, f".{name}.lock")
            if os.path.exists(lockfile):
                os.remove(lockfile)

    def get_wallet_file_name(self, i, fullpath=False):
        tfn = testfilename + str(i) + ".jmdat"
        if fullpath:
            return os.path.join(".", "wallets", tfn)
        else:
            return tfn

    async def do_request(self, agent, method, addr, body, handler, token=None):
        if token:
            headers = Headers({"Authorization": ["Bearer " + token]})
        else:
            headers = None
        response = await agent.request(method, addr, headers, bodyProducer=body)
        await self.response_handler(response, handler)

    async def response_handler(self, response, handler):
        body = await readBody(response)
        # handlers check the body is as expected; no return.
        handler(body, response.code)

    def process_new_addr_response(self, response, code):
        assert code == 200
        json_body = json.loads(response.decode("utf-8"))
        self.created_tl_address = json_body["address"]
        assert validate_address(json_body["address"])[0]

    def process_direct_send_response(self, response, code):
        assert code == 200
        json_body = json.loads(response.decode("utf-8"))
        assert "txinfo" in json_body
        # TODO tx check
        print(json_body["txinfo"])

    def make_comms_backend(self):
        # in normal operations, the RPC call will trigger
        # the jmclient to connect to an *existing* daemon
        # that was created on startup, but here, that daemon
        # does not yet exist, so we will get 503 Backend Not Ready,
        # unless we manually create it:
        return start_reactor(jm_single().config.get("DAEMON",
                    "daemon_host"), jm_single().config.getint("DAEMON",
                    "daemon_port"), None, daemon=True, rs=False)

    def tearDown(self):
        self.clean_out_wallet_files()
        for dc in reactor.getDelayedCalls():
            if not dc.cancelled:
                dc.cancel()
        d1 = defer.maybeDeferred(self.listener_ws.stopListening)
        d2 = defer.maybeDeferred(self.listener_rpc.stopListening)
        if self.client_connector:
            self.client_connector.disconnect()
        # only fire if everything is finished:
        return defer.gatherResults([d1, d2])

class WalletRPCTestBaseFB(WalletRPCTestBase):
    wallet_cls = SegwitWalletFidelityBonds
    # we are using fresh (empty) wallets for these tests
    wallet_structure = [0, 0, 0, 0, 0]

class ClientNotifTestProto(ClientTProtocol):

    def sendAuth(self):
        task.deferLater(reactor, self.factory.delay,
                        self.factory.callbackfn)
        super().sendAuth()

class ClientNotifTestFactory(WebSocketClientFactory):
    def __init__(self, *args, **kwargs):
        if "delay" in kwargs:
            self.delay = kwargs.pop("delay", None)
        if "callbackfn" in kwargs:
            self.callbackfn = kwargs.pop("callbackfn", None)
        super().__init__(*args, **kwargs)

class TrialTestWRPC_WS(WalletRPCTestBase, unittest.TestCase):
    """ class for testing websocket subscriptions/events etc.
    """

    def test_notif(self):
        # simulate the daemon already having created
        # an active session (which it usually does when
        # starting the WalletService:
        self.daemon.wss_factory.protocol.active_session = True
        # once the websocket connection is established, and auth
        # is sent, our custom clientfactory will fire the tx
        # notification via the callback passed as argument here;
        # and we wait for the receipt in the code below:
        self.client_factory = ClientNotifTestFactory(
            "ws://127.0.0.1:"+str(self.wss_port),
            delay=0.1, callbackfn=self.fire_tx_notif)
        self.client_factory.protocol = ClientNotifTestProto
        self.client_factory.protocol.ACCESS_TOKEN = self.daemon.token.issue()["token"].encode("utf8")
        self.client_connector = connectWS(self.client_factory)
        self.attempt_receipt_counter = 0
        return task.deferLater(reactor, 0.0, self.wait_to_receive)

    def wait_to_receive(self):
        d = task.deferLater(reactor, 0.1, self.checkNotifs)
        return d
    
    def checkNotifs(self):
        # We wait and monitor if the notification has been received,
        # but give up after 10 attempts spaced by 0.2 seconds each.
        # It should usually succeed on the first try.
        if self.attempt_receipt_counter > 10:
            assert False
        if not self.client_factory.notifs == 1:
            jlog.info("Failed to receive notification, waiting and trying again")
            self.attempt_receipt_counter += 1
            d = task.deferLater(reactor, 0.2, self.checkNotifs)
            return d

    def fire_tx_notif(self):
        self.daemon.wss_factory.sendTxNotification(self.test_tx,
                                            test_tx_hex_txid)

class TrialTestWRPC_FB(WalletRPCTestBaseFB, unittest.TestCase):
    @ensure_deferred
    async def test_gettimelockaddress(self):
        self.daemon.auth_disabled = True
        agent = get_nontor_agent()
        addr = self.get_route_root()
        addr += "/wallet/"
        addr += self.daemon.wallet_name
        addr += "/address/timelock/new/2023-02"
        addr = addr.encode()
        await self.do_request(agent, b"GET", addr, None, self.process_new_addr_response)

    @ensure_deferred
    async def test_no_maker_start_expiredtl_only(self):
        # test strategy:
        # 1. create a TL address with expired TL
        # 2. fund the above
        # 3. Attempt to start maker,
        #    catch expected failure.
        self.scon, _ = self.make_comms_backend()
        self.daemon.auth_disabled = True
        agent = get_nontor_agent()
        # 1
        addr = self.get_route_root()
        addr += "/wallet/"
        addr += self.daemon.wallet_name
        addr += "/address/timelock/new/2022-01"
        addr = addr.encode()
        await self.do_request(agent, b"GET", addr, None, self.process_new_addr_response)
        # 2
        jm_single().bc_interface.grab_coins(self.created_tl_address, 0.05)
        # 3
        addr_start = self.get_route_root()
        addr_start += "/wallet/"
        addr_start += self.daemon.wallet_name
        addr = addr_start + "/maker/start"
        addr = addr.encode()
        body = BytesProducer(json.dumps({"txfee": "0",
            "cjfee_a": "1000", "cjfee_r": "0.0002",
            "ordertype": "reloffer", "minsize": "1000000"}).encode())
        await self.do_request(agent, b"POST", addr, body, self.process_failed_maker_start)

    def process_failed_maker_start(self, response, code):
        assert code == 409
        # backend's AMP connection must be cleaned up, otherwise
        # test will fail for unclean reactor:
        self.addCleanup(self.scon.stopListening)
        # Here is the actual functional check: status should not
        # be MAKER_RUNNING since no non-TL-type coin existed:
        assert self.daemon.coinjoin_state == CJ_NOT_RUNNING

class TrialTestWRPC_DisplayWallet(WalletRPCTestBase, unittest.TestCase):

    async def do_session_request(self, agent, addr, handler=None, token=None):
        """ A `None` value for handler is reserved for the case
        where we expect an Unauthorized request because we provided a token,
        but it is not valid.
        For other cases, provide the url prefix before `/session' as addr,
        and we expect a 200 if token is valid *or* token is None, but contents
        are to be checked by provided response handler callback.
        """
        if handler is None:
            assert token is not None
            handler = self.unauthorized_session_request_handler
        await self.do_request(agent, b"GET", (addr+"/session").encode(),
                              None, handler, token)

    def authorized_session_request_handler(self, response, code):
        assert code == 200

    def unauthorized_session_request_handler(self, response, code):
        assert code == 401

    @ensure_deferred
    async def test_recover_wallet(self):
        # before starting, we have to shut down the existing
        # wallet service (usually this would be `lock`):
        self.daemon.services["wallet"] = None
        self.daemon.stopService()
        self.daemon.auth_disabled = False

        wfn1 = self.get_wallet_file_name(1)
        self.wfnames = [wfn1]
        agent = get_nontor_agent()
        root = self.get_route_root()

        addr = root + "/wallet/recover"
        addr = addr.encode()
        body = BytesProducer(json.dumps({"walletname": wfn1,
                "password": "hunter2", "wallettype": "sw-fb",
                "seedphrase": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"}).encode())
        # Note: the recover wallet response is identical to
        # the create wallet response
        await self.do_request(agent, b"POST", addr, body,
                              self.process_create_wallet_response)

        # Sanity check of startup; does a auth-ed session request succeed?
        await self.do_session_request(agent, root,
            self.authorized_session_request_handler, token=self.jwt_token)
        # What about display?
        addr = self.get_route_root()
        addr += "/wallet/"
        addr += self.daemon.wallet_name
        addr += "/display"
        addr = addr.encode()
        self.daemon.auth_disabled = True
        await self.do_request(agent, b"GET", addr, None,
                              self.process_empty_wallet_display_response)

    @ensure_deferred
    async def test_create_list_lock_unlock(self):
        """ A batch of tests in sequence here,
            so we can track the state of a created
            wallet and check it is what is expected.
            We test create first, so we have a wallet.

        1. create a wallet and have it persisted
           to disk in ./wallets, and get a token.
        2. lock that wallet.
        3. create a second wallet as above.
        4. list wallets and check they contain the new
           wallet.
        5. lock the existing wallet service, using the token.
        6. Unlock the original wallet with /unlock, get a token.
        7. Unlock the second wallet with /unlock, get a token.
        """
        # before starting, we have to shut down the existing
        # wallet service (usually this would be `lock`):
        self.daemon.services["wallet"] = None
        self.daemon.stopService()
        self.daemon.auth_disabled = False

        wfn1 = self.get_wallet_file_name(1)
        wfn2 = self.get_wallet_file_name(2)
        self.wfnames = [wfn1, wfn2]
        agent = get_nontor_agent()
        root = self.get_route_root()

        # 1. Create first
        addr = root + "/wallet/create"
        addr = addr.encode()
        body = BytesProducer(json.dumps({"walletname": wfn1,
                "password": "hunter2", "wallettype": "sw-fb"}).encode())
        await self.do_request(agent, b"POST", addr, body,
                              self.process_create_wallet_response)

        # 1a. Session request with valid token; should succeed
        await self.do_session_request(agent, root,
            self.authorized_session_request_handler, token=self.jwt_token)
        # 1b. Session request without token, even though one is active; should succeed
        await self.do_session_request(agent, root,
            self.authorized_session_request_handler)

        # 2. now *lock*
        addr = root + "/wallet/" + wfn1 + "/lock"
        addr = addr.encode()
        jlog.info("Using address: {}".format(addr))
        await self.do_request(agent, b"GET", addr, None,
                self.process_lock_response, token=self.jwt_token)

        # 2a. Session request with now invalid token; should fail
        await self.do_session_request(agent, root,
            self.unauthorized_session_request_handler, token=self.jwt_token)
        # 2b. Session request without token, should still succeed.
        await self.do_session_request(agent, root,
            self.authorized_session_request_handler)

        # 3. Create this secondary wallet (so we can test re-unlock)
        addr = root + "/wallet/create"
        addr = addr.encode()
        body = BytesProducer(json.dumps({"walletname": wfn2,
                "password": "hunter3", "wallettype": "sw"}).encode())
        await self.do_request(agent, b"POST", addr, body,
                              self.process_create_wallet_response)

        # 4. List wallets
        addr = root + "/wallet/all"
        addr = addr.encode()
        # does not require a token, though we just got one.
        await self.do_request(agent, b"GET", addr, None,
                               self.process_list_wallets_response)

        # 5. now *lock* the active.
        addr = root + "/wallet/" + wfn2 + "/lock"
        addr = addr.encode()
        jlog.info("Using address: {}".format(addr))
        await self.do_request(agent, b"GET", addr, None,
                self.process_lock_response, token=self.jwt_token)
        # wallet service should now be stopped.
        # 6. Unlock the original wallet
        addr = root + "/wallet/" + wfn1 + "/unlock"
        addr = addr.encode()
        body = BytesProducer(json.dumps({"password": "hunter2"}).encode())
        await self.do_request(agent, b"POST", addr, body,
                              self.process_unlock_response)

        # 7. Unlock the second wallet again
        addr = root + "/wallet/" + wfn2 + "/unlock"
        addr = addr.encode()
        body = BytesProducer(json.dumps({"password": "hunter3"}).encode())
        await self.do_request(agent, b"POST", addr, body,
                              self.process_unlock_response)

    @ensure_deferred
    async def test_unlock_locked(self):
        """Assert if unlocking a wallet locked by another process fails."""
        self.clean_out_wallet_files()
        self.daemon.services["wallet"] = None
        self.daemon.stopService()
        self.daemon.auth_disabled = False

        wfn = self.get_wallet_file_name(1)
        self.wfnames = [wfn]

        agent = get_nontor_agent()
        root = self.get_route_root()

        # Create first
        p = self.get_wallet_file_name(1, True)
        pw = "None"

        s = storage.Storage(p, bytes(pw, "utf-8"), create=True)
        assert s.is_locked()

        # Unlocking a locked wallet should fail

        addr = root + "/wallet/" + wfn + "/unlock"
        addr = addr.encode()
        body = BytesProducer(json.dumps({"password": pw}).encode())
        await self.do_request(
            agent, b"POST", addr, body, self.process_failed_unlock_response
        )

        s.close()

    def process_create_wallet_response(self, response, code):
        assert code == 201
        json_body = json.loads(response.decode("utf-8"))
        assert json_body["walletname"] in self.wfnames
        self.jwt_token = json_body["token"]
        # we don't use this in test, but it must exist:
        assert json_body["seedphrase"]

    def process_list_wallets_response(self, body, code):
        assert code == 200
        json_body = json.loads(body.decode("utf-8"))
        assert set(json_body["wallets"]) == set(self.wfnames)

    @ensure_deferred
    async def test_direct_send_and_display_wallet(self):
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
        await self.do_request(agent, b"POST", addr, body,
                              self.process_direct_send_response)
        # before querying the wallet display, set a label to check:
        labeladdr = self.daemon.services["wallet"].get_addr(0,0,0)
        self.daemon.services["wallet"].set_address_label(labeladdr,
                                        "test-wallet-rpc-label")
        # force the wallet service txmonitor to wake up, to see the new
        # tx before querying /display:
        self.daemon.services["wallet"].transaction_monitor()
        addr = self.get_route_root()
        addr += "/wallet/"
        addr += self.daemon.wallet_name
        addr += "/display"
        addr = addr.encode()
        await self.do_request(agent, b"GET", addr, None,
                              self.process_wallet_display_response)

    def process_empty_wallet_display_response(self, response, code):
        assert code == 200
        json_body = json.loads(response.decode("utf-8"))
        wi = json_body["walletinfo"]
        assert float(wi["total_balance"]) == 0.0 #?

    def process_wallet_display_response(self, response, code):
        assert code == 200
        json_body = json.loads(response.decode("utf-8"))
        wi = json_body["walletinfo"]
        latest_balance = float(wi["total_balance"])
        jlog.info("Wallet display currently shows balance: {}".format(
            latest_balance))
        assert latest_balance > self.mean_amt * 4.0 - 1.1
        assert latest_balance <= self.mean_amt * 4.0 - 1.0
        # these samplings are an attempt to ensure object structure:
        wia = wi["accounts"]
        # note that only certain indices are present, based on funding
        # and the direct-send tx above:
        assert wia[0]["branches"][0]["entries"][0]["label"] == "test-wallet-rpc-label"
        assert wia[0]["branches"][0]["entries"][0]["hd_path"] == "m/84'/1'/0'/0/0"
        assert wia[1]["branches"][0]["entries"][1]["status"] == "deposit"
        assert wia[1]["branches"][0]["entries"][1]["extradata"] == ""
        # currently this test only produces output with available_balance = balance,
        # at every level in the tree (no freeze here), but could add TODO
        assert wi["available_balance"] == wi["total_balance"]
        assert all([wia[i]["account_balance"] == wia[i][
            "available_balance"] for i in range(len(wia))])
        assert all([x["balance"] == x["available_balance"] for x in wia[
            0]["branches"]])

    @ensure_deferred
    async def test_getaddress(self):
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
        await self.do_request(agent, b"GET", addr, None,
                              self.process_new_addr_response)

    @ensure_deferred
    async def test_maker_start_stop(self):
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
        await self.do_request(agent, b"POST", addr, body,
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
        await self.do_request(agent, b"GET", addr, None,
                              self.process_maker_stop)

    def process_maker_start(self, request, code):
        assert code == 202
        assert self.daemon.coinjoin_state == CJ_MAKER_RUNNING

    def process_maker_stop(self, request, code):
        assert code == 202
        assert self.daemon.coinjoin_state == CJ_NOT_RUNNING

    @ensure_deferred
    async def test_listutxos_and_freeze(self):
        self.daemon.auth_disabled = True
        agent = get_nontor_agent()
        pre_addr = self.get_route_root()
        pre_addr += "/wallet/"
        pre_addr += self.daemon.wallet_name
        addr = pre_addr + "/utxos"
        addr = addr.encode()
        await self.do_request(agent, b"GET", addr, None,
                              self.process_listutxos_response)
        # Test of freezing is currently very primitive: we only
        # check that the action was accepted; a full test would
        # involve checking that spending the coin works or doesn't
        # work, as expected.
        addr = pre_addr + "/freeze"
        addr = addr.encode()
        utxostr = self.mixdepth1_utxos[0]["utxo"]
        body = BytesProducer(json.dumps({"utxo-string": utxostr,
            "freeze": True}).encode())
        await self.do_request(agent, b"POST", addr, body,
                              self.process_utxo_freeze)
        body = BytesProducer(json.dumps({"utxo-string": utxostr,
            "freeze": False}).encode())
        await self.do_request(agent, b"POST", addr, body,
                              self.process_utxo_freeze)

    def process_listutxos_response(self, response, code):
        assert code == 200
        json_body = json.loads(response.decode("utf-8"))
        # some fragility in test structure here: what utxos we
        # have depend on what other tests occurred.
        # For now, we at least check that we have 3 utxos in mixdepth
        # 1 because none of the other tests spend them:
        mixdepth1_utxos = []
        for d in json_body["utxos"]:
            if d["mixdepth"] == 1:
                mixdepth1_utxos.append(d)
        assert len(mixdepth1_utxos) == 3
        self.mixdepth1_utxos = mixdepth1_utxos

    def process_utxo_freeze(self, response, code):
        assert code == 200

    @ensure_deferred
    async def test_session(self):
        agent = get_nontor_agent()
        addr = self.get_route_root()
        addr += "/session"
        addr = addr.encode()
        await self.do_request(agent, b"GET", addr, None,
                              self.process_session_response)

    def process_session_response(self, response, code):
        assert code == 200
        json_body = json.loads(response.decode("utf-8"))
        assert json_body["maker_running"] is False
        assert json_body["coinjoin_in_process"] is False

    def process_unlock_response(self, response, code):
        assert code == 200
        json_body = json.loads(response.decode("utf-8"))
        assert json_body["walletname"] in self.wfnames
        self.jwt_token = json_body["token"]

    def process_failed_unlock_response(self, response, code):
        assert code == 409

    def process_lock_response(self, response, code):
        assert code == 200
        json_body = json.loads(response.decode("utf-8"))
        assert json_body["walletname"] in self.wfnames

    @ensure_deferred
    async def test_do_coinjoin(self):
        """ This slightly weird test curently only
        tests *requesting* a coinjoin; because there are
        no makers running in the test suite, the Taker will
        give up early due to the empty orderbook, but that is
        OK since this API call only makes the request.
        """
        self.daemon.auth_disabled = True
        self.scon, self.ccon = self.make_comms_backend()
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
        await self.do_request(agent, b"POST", addr, body,
                              self.process_do_coinjoin_response)

    @ensure_deferred
    async def test_getinfo(self):
        agent = get_nontor_agent()
        addr = self.get_route_root()
        addr += "/getinfo"
        addr = addr.encode()
        await self.do_request(agent, b"GET", addr, None,
                              self.process_getinfo_response)

    def process_getinfo_response(self, response, code):
        assert code==200
        responseobj = json.loads(response.decode("utf-8"))
        assert responseobj["version"] == JM_CORE_VERSION

    def process_do_coinjoin_response(self, response, code):
        assert code == 202
        # response code is already checked to be 200
        clientconn = self.daemon.coinjoin_connection
        # backend's AMP connection must be cleaned up, otherwise
        # test will fail for unclean reactor:
        self.addCleanup(clientconn.disconnect)
        self.addCleanup(self.scon.stopListening)
        assert json.loads(response.decode("utf-8")) == {}

    @ensure_deferred
    async def test_get_seed(self):
        self.daemon.auth_disabled = True
        agent = get_nontor_agent()
        addr = self.get_route_root()
        addr += "/wallet/"
        addr += self.daemon.wallet_name
        addr += "/getseed"
        addr = addr.encode()
        await self.do_request(agent, b"GET", addr, None,
                              self.process_get_seed_response)

    def process_get_seed_response(self, response, code):
        assert code == 200
        json_body = json.loads(response.decode('utf-8'))
        assert json_body["seedphrase"]


class TrialTestWRPC_JWT(WalletRPCTestBase, unittest.TestCase):
    async def do_request(self, agent, method, addr, body, handler, token):
        headers = Headers({"Authorization": ["Bearer " + token]})
        response = await agent.request(method, addr, headers, bodyProducer=body)
        handler(response)

    def get_token(self, grant_type: str, status: str = "valid"):
        now, delta = datetime.datetime.utcnow(), datetime.timedelta(hours=1)
        exp = now - delta if status == "expired" else now + delta

        scope = f"walletrpc {self.daemon.wallet_name}"
        if status == "invalid_scope":
            scope = status

        alg = self.daemon.token.SIGNATURE_ALGORITHM
        if status == "invalid_alg":
            alg = ({"HS256", "HS384", "HS512"} - {alg}).pop()

        t = jwt.encode(
            {"exp": exp, "scope": scope},
            self.daemon.token.signature_key[grant_type],
            algorithm=alg,
        )

        if status == "invalid_sig":
            # Get token string
            token_parts = t.split(".")
            sig = token_parts[-1]

            # Pad as needed
            if len(sig) % 4 != 0:
                sig += "=" * (len(sig) % 4)

            # Flip fist byte, unpad
            sig_bytes = base64.urlsafe_b64decode(sig)
            flipped_bytes = bytes([sig_bytes[0] ^ 1]) + sig_bytes[1:]
            flipped_sig = base64.urlsafe_b64encode(flipped_bytes).replace(b"=", b"")

            # Reconstruct JWT with invalid sig
            token_parts[-1] = str(flipped_sig)
            t = ".".join(token_parts)

        return t

    def authorized_response_handler(self, response):
        assert response.code == 200

    def forbidden_response_handler(self, response):
        assert response.code == 403
        assert "insufficient_scope" in response.headers.getRawHeaders("WWW-Authenticate").pop()

    def unauthorized_response_handler(self, response):
        assert response.code == 401
        assert "Bearer" in response.headers.getRawHeaders("WWW-Authenticate").pop()

    def expired_access_token_response_handler(self, response):
        self.unauthorized_response_handler(response)
        assert "expired" in response.headers.getRawHeaders("WWW-Authenticate").pop()

    @ensure_deferred
    async def test_jwt_authentication(self):
        """Test JWT authentication and authorization"""

        agent = get_nontor_agent()
        addr = (self.get_route_root() + "/session").encode()

        for access_token_status, responde_handler in [
            ("valid", "authorized"),
            ("expired", "expired"),
            ("invalid_scope", "forbidden"),
            ("invalid_sig", "unauthorized"),
            ("invalid_alg", "unauthorized"),
        ]:
            handler = {
                "authorized": self.authorized_response_handler,
                "expired": self.expired_access_token_response_handler,
                "forbidden": self.forbidden_response_handler,
                "unauthorized": self.unauthorized_response_handler,
            }[responde_handler]
            token = self.get_token("access", access_token_status)

            await self.do_request(agent, b"GET", addr, None, handler, token)

    async def successful_refresh_response_handler(self, response):
        self.authorized_response_handler(response)
        body = await readBody(response)
        json_body = json.loads(body.decode("utf-8"))
        assert {"token", "refresh_token", "expires_in", "token_type", "scope"} <= set(
            json_body.keys()
        )

    async def failed_refresh_response_handler(
        self, response, *, message=None, error_description=None
    ):
        assert response.code == 400
        body = await readBody(response)
        json_body = json.loads(body.decode("utf-8"))
        if message is not None:
            assert json_body.get("message") == message
        if error_description is not None:
            assert error_description in json_body.get("error_description")

    async def do_refresh_request(self, body, handler, token):
        agent = get_nontor_agent()
        addr = (self.get_route_root() + "/token").encode()
        body = BytesProducer(json.dumps(body).encode())
        await self.do_request(agent, b"POST", addr, body, handler, token)

    @ensure_deferred
    async def test_refresh_token_request(self):
        """Test token endpoint with valid refresh token"""
        for access_token_status, request_status, error in [
            ("valid", "valid", None),
            ("expired", "valid", None),
            ("valid", "invalid_request", "invalid_request"),
            ("valid", "invalid_grant", "unsupported_grant_type"),
        ]:
            if error is None:
                handler = self.successful_refresh_response_handler
            else:
                handler = functools.partial(
                    self.failed_refresh_response_handler, message=error
                )

            body = {
                "grant_type": "refresh_token",
                "refresh_token": self.get_token("refresh"),
            }
            if request_status == "invalid_request":
                body["refresh"] = body.pop("refresh_token")
            if request_status == "unsupported_grant_type":
                body["grant_type"] = "joinmarket"

            await self.do_refresh_request(
                body, handler, self.get_token("access", access_token_status)
            )

    @ensure_deferred
    async def test_refresh_token(self):
        """Test refresh token endpoint"""
        for refresh_token_status, error in [
            ("expired", "expired"),
            ("invalid_scope", "invalid_scope"),
            ("invalid_sig", "invalid_grant"),
        ]:
            if error == "expired":
                handler = functools.partial(
                    self.failed_refresh_response_handler, error_description=error
                )
            else:
                handler = functools.partial(
                    self.failed_refresh_response_handler, message=error
                )

            body = {
                "grant_type": "refresh_token",
                "refresh_token": self.get_token("refresh", refresh_token_status),
            }

            await self.do_refresh_request(body, handler, self.get_token("access"))


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
