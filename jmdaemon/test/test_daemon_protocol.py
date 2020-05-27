#! /usr/bin/env python
'''test daemon-protocol interfacae.'''

from jmdaemon import MessageChannelCollection
from jmdaemon.orderbookwatch import OrderbookWatch
from jmdaemon.daemon_protocol import JMDaemonServerProtocol
from jmdaemon.protocol import NICK_HASH_LENGTH, NICK_MAX_ENCODED, JM_VERSION,\
    JOINMARKET_NICK_HEADER
from jmbase import get_log
from jmclient import (load_test_config, jm_single, get_irc_mchannels)
from twisted.python.log import msg as tmsg
from twisted.python.log import startLogging
from twisted.internet import protocol, reactor, task
from twisted.internet.protocol import ServerFactory
from twisted.internet.error import (ConnectionLost, ConnectionAborted,
                                    ConnectionClosed, ConnectionDone)
from twisted.protocols.amp import UnknownRemoteError
from twisted.protocols import amp
from twisted.trial import unittest
from jmbase.commands import *
from msgdata import *
import json
import base64
import sys
from dummy_mc import DummyMessageChannel
test_completed = False
end_early = False
jlog = get_log()

class DummyMC(DummyMessageChannel):
    #override run() for twisted compatibility
    def run(self):
        if self.on_welcome:
            reactor.callLater(1, self.on_welcome, self)

class JMProtocolError(Exception):
    pass

class JMBaseProtocol(amp.AMP):
    def checkClientResponse(self, response):
        """A generic check of client acceptance; any failure
        is considered criticial.
        """
        if 'accepted' not in response or not response['accepted']:
            reactor.stop()

    def defaultErrback(self, failure):
        failure.trap(ConnectionAborted, ConnectionClosed, ConnectionDone,
                     ConnectionLost, UnknownRemoteError)
        reactor.stop()

    def defaultCallbacks(self, d):
        d.addCallback(self.checkClientResponse)
        d.addErrback(self.defaultErrback)

class JMTestClientProtocol(JMBaseProtocol):

    def connectionMade(self):
        self.clientStart()

    def clientStart(self):
        self.sigs_received = 0
        irc = get_irc_mchannels()
        d = self.callRemote(JMInit,
                            bcsource="dummyblockchain",
                            network="dummynetwork",
                            irc_configs=json.dumps(irc),
                            minmakers=2,
                            maker_timeout_sec=3)
        self.defaultCallbacks(d)

    @JMInitProto.responder
    def on_JM_INIT_PROTO(self, nick_hash_length, nick_max_encoded,
                         joinmarket_nick_header, joinmarket_version):
        show_receipt("JMINITPROTO", nick_hash_length, nick_max_encoded,
                     joinmarket_nick_header, joinmarket_version)
        d = self.callRemote(JMStartMC,
                            nick="dummynick")
        self.defaultCallbacks(d)
        return {'accepted': True}

    @JMUp.responder
    def on_JM_UP(self):
        show_receipt("JMUP")
        d = self.callRemote(JMSetup,
                            role="TAKER",
                            offers="{}",
                            fidelity_bond=b'')
        self.defaultCallbacks(d)
        return {'accepted': True}

    @JMSetupDone.responder
    def on_JM_SETUP_DONE(self):
        show_receipt("JMSETUPDONE")
        d = self.callRemote(JMRequestOffers)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @JMFillResponse.responder
    def on_JM_FILL_RESPONSE(self, success, ioauth_data):
        show_receipt("JMFILLRESPONSE", success, ioauth_data)
        reactor.callLater(1, self.maketx, ioauth_data)
        return {'accepted': True}
    
    def maketx(self, ioauth_data):
        ioauth_data = json.loads(ioauth_data)
        nl = list(ioauth_data.keys())
        d = self.callRemote(JMMakeTx,
                            nick_list= json.dumps(nl),
                            txhex="deadbeef")
        self.defaultCallbacks(d)

    @JMOffers.responder
    def on_JM_OFFERS(self, orderbook, fidelitybonds):
        if end_early:
            return {'accepted': True}
        jlog.debug("JMOFFERS" + str(orderbook))
        #Trigger receipt of verified privmsgs, including unverified
        nick = str(list(t_chosen_orders.keys())[0])
        b64tx = base64.b64encode(b"deadbeef").decode('ascii')
        d1 = self.callRemote(JMMsgSignatureVerify,
                            verif_result=True,
                            nick=nick,
                            fullmsg="!push " + b64tx + " abc def",
                            hostid="dummy")
        self.defaultCallbacks(d1)
        #unverified
        d2 = self.callRemote(JMMsgSignatureVerify,
                            verif_result=False,
                            nick=nick,
                            fullmsg="!push " + b64tx + " abc def",
                            hostid="dummy")
        self.defaultCallbacks(d2)        
        d = self.callRemote(JMFill,
                            amount=100,
                            commitment="dummycommitment",
                            revelation="dummyrevelation",
                            filled_offers=json.dumps(t_chosen_orders))
        self.defaultCallbacks(d)
        return {'accepted': True}

    @JMSigReceived.responder
    def on_JM_SIG_RECEIVED(self, nick, sig):
        show_receipt("JMSIGRECEIVED", nick, sig)
        self.sigs_received += 1
        if self.sigs_received == 3:
            #end of test
            reactor.callLater(1, end_test)
        return {'accepted': True}

    @JMRequestMsgSig.responder
    def on_JM_REQUEST_MSGSIG(self, nick, cmd, msg, msg_to_be_signed, hostid):
        show_receipt("JMREQUESTMSGSIG", nick, cmd, msg, msg_to_be_signed, hostid)
        d = self.callRemote(JMMsgSignature,
                            nick=nick,
                            cmd=cmd,
                            msg_to_return="xxxcreatedsigxx",
                            hostid=hostid)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @JMRequestMsgSigVerify.responder
    def on_JM_REQUEST_MSGSIG_VERIFY(self, msg, fullmsg, sig, pubkey, nick,
                                    hashlen, max_encoded, hostid):
        show_receipt("JMREQUESTMSGSIGVERIFY", msg, fullmsg, sig, pubkey,
                     nick, hashlen, max_encoded, hostid)
        d = self.callRemote(JMMsgSignatureVerify,
                            verif_result=True,
                            nick=nick,
                            fullmsg=fullmsg,
                            hostid=hostid)
        self.defaultCallbacks(d)
        return {'accepted': True}

class JMTestClientProtocolFactory(protocol.ClientFactory):
    protocol = JMTestClientProtocol
        

def show_receipt(name, *args):
    tmsg("Received msgtype: " + name + ", args: " + ",".join([str(x) for x in args]))

def end_test():
    global test_completed
    test_completed = True



class JMDaemonTestServerProtocol(JMDaemonServerProtocol):

    def __init__(self, factory):
        super().__init__(factory)
        #respondtoioauths should do nothing unless jmstate = 2
        self.respondToIoauths(True)
        #calling on_JM_MAKE_TX should also do nothing in wrong state
        assert super().on_JM_MAKE_TX(1, 2) == {'accepted': False}
        #calling on_JM_FILL with negative amount should reject
        assert super().on_JM_FILL(-1000, 2, 3, 4) == {'accepted': False}
        #checkutxos also does nothing for rejection at the moment
        self.checkUtxosAccepted(False)
        #None should be returned requesting a cryptobox for an unknown cp
        assert self.get_crypto_box_from_nick("notrealcp") == None
        #does nothing yet
        self.on_error("dummy error")

    @JMRequestOffers.responder
    def on_JM_REQUEST_OFFERS(self):
        for o in t_orderbook:
            #counterparty, oid, ordertype, minsize, maxsize,txfee, cjfee):
            self.on_order_seen(o["counterparty"], o["oid"], o["ordertype"],
                                 o["minsize"], o["maxsize"],
                                 o["txfee"], o["cjfee"])
        return super().on_JM_REQUEST_OFFERS()
        
    @JMInit.responder
    def on_JM_INIT(self, bcsource, network, irc_configs, minmakers,
                   maker_timeout_sec):
        self.maker_timeout_sec = int(maker_timeout_sec)
        self.minmakers = int(minmakers)
        mcs = [DummyMC(None)]
        self.mcc = MessageChannelCollection(mcs)
        #The following is a hack to get the counterparties marked seen/active;
        #note it must happen before callign set_msgchan for OrderbookWatch
        self.mcc.on_order_seen = None
        for c in [o['counterparty'] for o in t_orderbook]:
            self.mcc.on_order_seen_trigger(mcs[0], c, "a", "b", "c", "d", "e", "f")
        OrderbookWatch.set_msgchan(self, self.mcc)
        #register taker-specific msgchan callbacks here
        self.mcc.register_taker_callbacks(self.on_error, self.on_pubkey,
                                                      self.on_ioauth, self.on_sig)
        self.mcc.set_daemon(self)
        self.restart_mc_required = True
        d = self.callRemote(JMInitProto,
                                   nick_hash_length=NICK_HASH_LENGTH,
                                   nick_max_encoded=NICK_MAX_ENCODED,
                                   joinmarket_nick_header=JOINMARKET_NICK_HEADER,
                                   joinmarket_version=JM_VERSION)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @JMFill.responder
    def on_JM_FILL(self, amount, commitment, revelation, filled_offers):       
        tmpfo = json.loads(filled_offers)
        dummypub = "073732a7ca60470f709f23c602b2b8a6b1ba62ee8f3f83a61e5484ab5cbf9c3d"
        #trigger invalid on_pubkey conditions
        reactor.callLater(1, self.on_pubkey, "notrealcp", dummypub)
        reactor.callLater(2, self.on_pubkey, list(tmpfo.keys())[0], dummypub + "deadbeef")
        #trigger invalid on_ioauth condition
        reactor.callLater(2, self.on_ioauth, "notrealcp", 1, 2, 3, 4, 5)
        #trigger msg sig verify request operation for a dummy message
        #currently a pass-through
        reactor.callLater(1, self.request_signature_verify, "1",
                          "!push abcd abc def", "3", "4",
                          str(list(tmpfo.keys())[0]), 6, 7, self.mcc.mchannels[0].hostid)
        #send "valid" onpubkey, onioauth messages
        for k, v in tmpfo.items():
            reactor.callLater(1, self.on_pubkey, k, dummypub)
            reactor.callLater(2, self.on_ioauth, k, ['a', 'b'], "auth_pub",
                              "cj_addr", "change_addr", "btc_sig")
        return super().on_JM_FILL(amount, commitment, revelation, filled_offers)

    @JMMakeTx.responder
    def on_JM_MAKE_TX(self, nick_list, txhex):
        for n in json.loads(nick_list):
            reactor.callLater(1, self.on_sig, n, "dummytxsig")
        return super().on_JM_MAKE_TX(nick_list, txhex)



class JMDaemonTestServerProtocolFactory(ServerFactory):
    protocol = JMDaemonTestServerProtocol
    
    def buildProtocol(self, addr):
        return JMDaemonTestServerProtocol(self)


class JMDaemonTest2ServerProtocol(JMDaemonServerProtocol):
    #override here to avoid actually instantiating IRCMessageChannels
    def init_connections(self, nick):
        self.mc_shutdown()

class JMDaemonTest2ServerProtocolFactory(ServerFactory):
    protocol = JMDaemonTest2ServerProtocol
    def buildProtocol(self, addr):
        return JMDaemonTest2ServerProtocol(self)

class TrialTestJMDaemonProto(unittest.TestCase):

    def setUp(self):
        startLogging(sys.stdout)
        load_test_config()
        jm_single().maker_timeout_sec = 1
        self.port = reactor.listenTCP(28184, JMDaemonTestServerProtocolFactory())
        self.addCleanup(self.port.stopListening)
        clientconn = reactor.connectTCP("localhost", 28184,
                                        JMTestClientProtocolFactory())
        self.addCleanup(clientconn.disconnect)

    def test_waiter(self):
        return task.deferLater(reactor, 12, self._called_by_deffered)

    def _called_by_deffered(self):
        pass


class TestJMDaemonProtoInit(unittest.TestCase):

    def setUp(self):
        global end_early
        end_early = True
        load_test_config()
        jm_single().maker_timeout_sec = 1
        self.port = reactor.listenTCP(28184, JMDaemonTest2ServerProtocolFactory())
        self.addCleanup(self.port.stopListening)
        clientconn = reactor.connectTCP("localhost", 28184,
                                        JMTestClientProtocolFactory())
        self.addCleanup(clientconn.disconnect)

    def test_waiter(self):
        return task.deferLater(reactor, 5, self._called_by_deffered)

    def _called_by_deffered(self):
        global end_early
        end_early = False
