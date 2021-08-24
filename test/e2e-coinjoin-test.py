#! /usr/bin/env python
'''Creates wallets and yield generators in regtest,
   then runs both them and a JMWalletDaemon instance
   for the taker, injecting the newly created taker
   wallet into it and running sendpayment once.
   Number of ygs is configured in the joinmarket.cfg
   with `regtest-count` in the `ln-onion` type MESSAGING
   section.
   See notes below for more detail on config.
   Run it like:
   pytest \
   --btcroot=/path/to/bitcoin/bin/ \
   --btcpwd=123456abcdef --btcconf=/blah/bitcoin.conf \
   -s test/ln-ygrunner.py
   '''
from twisted.internet import reactor, defer
from twisted.web.client import readBody, Headers
from common import make_wallets
import pytest
import random
import json
from datetime import datetime
from jmbase import (get_nontor_agent, BytesProducer, jmprint,
                    get_log, stop_reactor, hextobin, bintohex)
from jmclient import (YieldGeneratorBasic, load_test_config, jm_single,
    JMClientProtocolFactory, start_reactor, SegwitWallet, get_mchannels,
    SegwitLegacyWallet, JMWalletDaemon)
from jmclient.wallet_utils import wallet_gettimelockaddress
from jmclient.wallet_rpc import api_version_string

log = get_log()

# For quicker testing, restrict the range of timelock
# addresses to avoid slow load of multiple bots.
# Note: no need to revert this change as ygrunner runs
# in isolation.
from jmclient import FidelityBondMixin
FidelityBondMixin.TIMELOCK_ERA_YEARS = 2
FidelityBondMixin.TIMELOCK_EPOCH_YEAR = datetime.now().year
FidelityBondMixin.TIMENUMBERS_PER_PUBKEY = 12

wallet_name = "test-onion-yg-runner.jmdat"

mean_amt = 2.0

directory_node_indices = [1]

#
def get_onion_messaging_config_regtest(run_num: int, dns=[1], hsd=""):
    """ Sets a onion messaging channel section for a regtest instance
    indexed by `run_num`. The indices to be used as directory nodes
    should be passed as `dns`, as a list of ints.
    """
    def location_string(directory_node_run_num):
        return "127.0.0.1:" + str(
            8080 + directory_node_run_num)
    if run_num in dns:
        # means *we* are a dn, and dns currently
        # do not use other dns:
        dns_to_use = [location_string(run_num)]
    else:
        dns_to_use = [location_string(a) for a in dns]
    dn_nodes_list = ",".join(dns_to_use)
    log.info("For node: {}, set dn list to: {}".format(run_num, dn_nodes_list))
    cf = {"type": "onion",
            "socks5_host": "127.0.0.1",
            "socks5_port": 9050,
            "tor_control_host": "127.0.0.1",
            "tor_control_port": 9051,
            "onion_serving_host": "127.0.0.1",
            "onion_serving_port": 8080 + run_num,
            "hidden_service_dir": "",
            "directory_nodes": dn_nodes_list,
            "regtest_count": "1, 1"}
    if run_num in dns:
        # only directories need to use fixed hidden service directories:
        cf["hidden_service_dir"] = hsd
    return cf


class RegtestJMClientProtocolFactory(JMClientProtocolFactory):
    i = 1
    def set_directory_nodes(self, dns):
        # a list of integers representing the directory nodes
        # for this test:
        self.dns = dns

    def get_mchannels(self):
        # swaps out any existing lightning configs
        # in the config settings on startup, for one
        # that's indexed to the regtest counter var:
        default_chans = get_mchannels()
        new_chans = []
        onion_found = False
        hsd = ""
        for c in default_chans:
            if "type" in c and c["type"] == "onion":
                onion_found = True
                if c["hidden_service_dir"] != "":
                    hsd = c["hidden_service_dir"]
                continue
            else:
                new_chans.append(c)
        if onion_found:
            new_chans.append(get_onion_messaging_config_regtest(
                self.i, self.dns, hsd))
        return new_chans

class JMWalletDaemonT(JMWalletDaemon):
    def check_cookie(self, request):
        if self.auth_disabled:
            return True
        return super().check_cookie(request)

class TWalletRPCManager(object):
    """ Base class for set up of tests of the
    Wallet RPC calls using the wallet_rpc.JMWalletDaemon service.
    """
    # the port for the jmwallet daemon
    dport = 28183
    # the port for the ws
    wss_port = 28283
    
    def __init__(self):
        # a client connnection object which is often but not always
        # instantiated:
        self.client_connector = None
        self.daemon = JMWalletDaemonT(self.dport, self.wss_port, tls=False)
        self.daemon.auth_disabled = True
        # because we sync and start the wallet service manually here
        # (and don't use wallet files yet), we won't have set a wallet name,
        # so we set it here:
        self.daemon.wallet_name = wallet_name

    def start(self):
        r, s = self.daemon.startService()
        self.listener_rpc = r
        self.listener_ws = s        

    def get_route_root(self):
        addr = "http://127.0.0.1:" + str(self.dport)
        addr += api_version_string
        return addr

    def stop(self):
        for dc in reactor.getDelayedCalls():
            dc.cancel()        
        d1 = defer.maybeDeferred(self.listener_ws.stopListening)
        d2 = defer.maybeDeferred(self.listener_rpc.stopListening)
        if self.client_connector:
            self.client_connector.disconnect()
        # only fire if everything is finished:
        return defer.gatherResults([d1, d2])

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
        # these responses should always be 200 OK.
        #assert response.code == 200
        # handlers check the body is as expected; no return.
        yield handler(body)
        return True

def test_start_yg_and_taker_setup(setup_onion_ygrunner):
    """Set up some wallets, for the ygs and 1 taker.
    Then start LN and the ygs in the background, then fire
    a startup of a wallet daemon for the taker who then
    makes a coinjoin payment.
    """
    if jm_single().config.get("POLICY", "native") == "true":
        walletclass = SegwitWallet
    else:
        # TODO add Legacy
        walletclass = SegwitLegacyWallet

    start_bot_num, end_bot_num = [int(x) for x in jm_single().config.get(
        "MESSAGING:onion1", "regtest_count").split(",")]
    num_ygs = end_bot_num - start_bot_num
    # specify the number of wallets and bots of each type:
    wallet_services = make_wallets(num_ygs + 1,
                           wallet_structures=[[1, 3, 0, 0, 0]] * (num_ygs + 1),
                           mean_amt=2.0,
                           walletclass=walletclass)
    #the sendpayment bot uses the last wallet in the list
    wallet_service = wallet_services[end_bot_num - 1]['wallet']
    jmprint("\n\nTaker wallet seed : " + wallet_services[end_bot_num - 1]['seed'])
    # for manual audit if necessary, show the maker's wallet seeds
    # also (note this audit should be automated in future, see
    # test_full_coinjoin.py in this directory)
    jmprint("\n\nMaker wallet seeds: ")
    for i in range(start_bot_num, end_bot_num):
        jmprint("Maker seed: " + wallet_services[i - 1]['seed'])
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

    for i in range(start_bot_num, end_bot_num):
        cfg = [txfee_contribution, cjfee_a, cjfee_r, ordertype, minsize,
               txfee_contribution_factor, cjfee_factor, size_factor]
        wallet_service_yg = wallet_services[i - 1]["wallet"]

        wallet_service_yg.startService()

        yg = ygclass(wallet_service_yg, cfg)
        clientfactory = RegtestJMClientProtocolFactory(yg, proto_type="MAKER")
        # This ensures that the right rpc/port config is passed into the daemon,
        # for this specific bot:
        clientfactory.i = i
        # This ensures that this bot knows which other bots are directory nodes:
        clientfactory.set_directory_nodes(directory_node_indices)
        nodaemon = jm_single().config.getint("DAEMON", "no_daemon")
        daemon = True if nodaemon == 1 else False
        #rs = True if i == num_ygs - 1 else False
        start_reactor(jm_single().config.get("DAEMON", "daemon_host"),
                      jm_single().config.getint("DAEMON", "daemon_port"),
                      clientfactory, daemon=daemon, rs=False)
    reactor.callLater(1.0, start_test_taker, wallet_services[end_bot_num - 1]['wallet'], end_bot_num)
    reactor.run()

@defer.inlineCallbacks
def start_test_taker(wallet_service, i):
    # this rpc manager has auth disabled,
    # and the wallet_service is set manually,
    # so no unlock etc.
    mgr = TWalletRPCManager()
    mgr.daemon.wallet_service = wallet_service
    # because we are manually setting the wallet_service
    # of the JMWalletDaemon instance, we do not follow the
    # usual flow of `initialize_wallet_service`, we do not set
    # the auth token or start the websocket; so we must manually
    # sync the wallet, including bypassing any restart callback:
    def dummy_restart_callback(msg):
        log.warn("Ignoring rescan request from backend wallet service: " + msg)
    mgr.daemon.wallet_service.add_restart_callback(dummy_restart_callback)
    mgr.daemon.wallet_name = wallet_name
    while not mgr.daemon.wallet_service.synced:
        mgr.daemon.wallet_service.sync_wallet(fast=True)
    mgr.daemon.wallet_service.startService()
    def get_client_factory():
        clientfactory = RegtestJMClientProtocolFactory(mgr.daemon.taker,
                                                       proto_type="TAKER")
        clientfactory.i = i
        clientfactory.set_directory_nodes(directory_node_indices)
        return clientfactory

    mgr.daemon.get_client_factory = get_client_factory
    # before preparing the RPC call to the wallet daemon,
    # we decide a coinjoin destination and amount. Choosing
    # a destination in the wallet is a bit easier because
    # we can query the mixdepth balance at the end.
    coinjoin_destination = mgr.daemon.wallet_service.get_internal_addr(4)
    cj_amount = 22000000
    # once the taker is finished we sanity check before
    # shutting down:
    def dummy_taker_finished(res, fromtx=False,
                               waittime=0.0, txdetails=None):
        jmprint("Taker is finished")
        # check that the funds have arrived.
        mbal = mgr.daemon.wallet_service.get_balance_by_mixdepth()[4]
        assert mbal == cj_amount
        jmprint("Funds: {} sats successfully arrived into mixdepth 4.".format(cj_amount))
        stop_reactor()
    mgr.daemon.taker_finished = dummy_taker_finished
    mgr.start()
    agent = get_nontor_agent()
    addr = mgr.get_route_root()
    addr += "/wallet/"
    addr += mgr.daemon.wallet_name
    addr += "/taker/coinjoin"
    addr = addr.encode()
    body = BytesProducer(json.dumps({"mixdepth": "1",
        "amount_sats": cj_amount,
        "counterparties": "2",
        "destination": coinjoin_destination}).encode())
    yield mgr.do_request(agent, b"POST", addr, body,
                          process_coinjoin_response)

def process_coinjoin_response(response):
    json_body = json.loads(response.decode("utf-8"))
    print("coinjoin response: {}".format(json_body))

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
    addr = wallet_gettimelockaddress(yg.wallet_service.wallet, "2021-11")
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
def setup_onion_ygrunner():
    load_test_config()
    jm_single().bc_interface.tick_forward_chain_interval = 10
    jm_single().bc_interface.simulate_blocks()
