#! /usr/bin/env python
from twisted.internet import protocol, reactor, task
from twisted.internet.error import (ConnectionLost, ConnectionAborted,
                                    ConnectionClosed, ConnectionDone)
from twisted.protocols.amp import UnknownRemoteError
from twisted.protocols import amp
from twisted.trial import unittest

from jmbase.commands import *

import json

test_completed = False

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

def show_receipt(name, *args):
    print("Received msgtype: " + name + ", args: " + ",".join([str(x) for x in args]))

def end_test():
    global test_completed
    test_completed = True


class JMTestServerProtocol(JMBaseProtocol):

    @JMInit.responder
    def on_JM_INIT(self, bcsource, network, irc_configs, minmakers,
                   maker_timeout_sec):
        show_receipt("JMINIT", bcsource, network, irc_configs, minmakers,
                     maker_timeout_sec)
        d = self.callRemote(JMInitProto,
                            nick_hash_length=1,
                            nick_max_encoded=2,
                            joinmarket_nick_header="J",
                            joinmarket_version=5)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @JMStartMC.responder
    def on_JM_START_MC(self, nick):
        show_receipt("STARTMC", nick)
        d = self.callRemote(JMUp)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @JMSetup.responder
    def on_JM_SETUP(self, role, initdata):
        show_receipt("JMSETUP", role, initdata)
        d = self.callRemote(JMSetupDone)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @JMRequestOffers.responder
    def on_JM_REQUEST_OFFERS(self):
        show_receipt("JMREQUESTOFFERS")
        #build a huge orderbook to test BigString Argument
        orderbook = ["aaaa" for _ in range(2**15)]
        d = self.callRemote(JMOffers,
                        orderbook=json.dumps(orderbook))
        self.defaultCallbacks(d)
        return {'accepted': True}

    @JMFill.responder
    def on_JM_FILL(self, amount, commitment, revelation, filled_offers):
        show_receipt("JMFILL", amount, commitment, revelation, filled_offers)
        d = self.callRemote(JMFillResponse,
                                success=True,
                                ioauth_data = json.dumps(['dummy', 'list']))
        return {'accepted': True}

    @JMMakeTx.responder
    def on_JM_MAKE_TX(self, nick_list, txhex):
        show_receipt("JMMAKETX", nick_list, txhex)
        d = self.callRemote(JMSigReceived,
                               nick="dummynick",
                               sig="xxxsig")
        self.defaultCallbacks(d)
        #add dummy calls to check message sign and message verify
        d2 = self.callRemote(JMRequestMsgSig,
                                    nick="dummynickforsign",
                                    cmd="command1",
                                    msg="msgforsign",
                                    msg_to_be_signed="fullmsgforsign",
                                    hostid="hostid1")
        self.defaultCallbacks(d2)
        d3 = self.callRemote(JMRequestMsgSigVerify,
                                        msg="msgforverify",
                                        fullmsg="fullmsgforverify",
                                        sig="xxxsigforverify",
                                        pubkey="pubkey1",
                                        nick="dummynickforverify",
                                        hashlen=4,
                                        max_encoded=5,
                                        hostid="hostid2")
        self.defaultCallbacks(d3)
        d4 = self.callRemote(JMTXBroadcast, txhex="deadbeef")
        self.defaultCallbacks(d4)
        return {'accepted': True}
            

    @JMMsgSignature.responder
    def on_JM_MSGSIGNATURE(self, nick, cmd, msg_to_return, hostid):
        show_receipt("JMMSGSIGNATURE", nick, cmd, msg_to_return, hostid)
        return {'accepted': True}

    @JMMsgSignatureVerify.responder
    def on_JM_MSGSIGNATURE_VERIFY(self, verif_result, nick, fullmsg, hostid):
        show_receipt("JMMSGSIGVERIFY", verif_result, nick, fullmsg, hostid)
        return {'accepted': True}

class JMTestClientProtocol(JMBaseProtocol):

    def connectionMade(self):
        self.clientStart()

    def clientStart(self):
        d = self.callRemote(JMInit,
                            bcsource="dummyblockchain",
                            network="dummynetwork",
                            irc_configs=json.dumps(['dummy', 'irc', 'config']),
                            minmakers=7,
                            maker_timeout_sec=8)
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
                            initdata="none")
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
        d = self.callRemote(JMMakeTx,
                            nick_list= json.dumps(['nick1', 'nick2', 'nick3']),
                            txhex="deadbeef")
        self.defaultCallbacks(d)
        return {'accepted': True}

    @JMOffers.responder
    def on_JM_OFFERS(self, orderbook):
        show_receipt("JMOFFERS", orderbook)
        d = self.callRemote(JMFill,
                            amount=100,
                            commitment="dummycommitment",
                            revelation="dummyrevelation",
                            filled_offers=json.dumps(['list', 'of', 'filled', 'offers']))
        self.defaultCallbacks(d)
        return {'accepted': True}

    @JMSigReceived.responder
    def on_JM_SIG_RECEIVED(self, nick, sig):
        show_receipt("JMSIGRECEIVED", nick, sig)
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

    @JMTXBroadcast.responder
    def on_JM_TX_BROADCAST(self, txhex):
        show_receipt("JMTXBROADCAST", txhex)
        return {"accepted": True}

class JMTestClientProtocolFactory(protocol.ClientFactory):
    protocol = JMTestClientProtocol

class JMTestServerProtocolFactory(protocol.ServerFactory):
    protocol = JMTestServerProtocol

class TrialTestJMProto(unittest.TestCase):

    def setUp(self):
        print("setUp()")
        self.port = reactor.listenTCP(28184, JMTestServerProtocolFactory())
        self.addCleanup(self.port.stopListening)
        def cb(client):
            self.client = client
            self.addCleanup(self.client.transport.loseConnection)
        creator = protocol.ClientCreator(reactor, JMTestClientProtocol)
        creator.connectTCP("localhost", 28184).addCallback(cb)

    def test_waiter(self):
        print("test_main()")
        return task.deferLater(reactor, 3, self._called_by_deffered)

    def _called_by_deffered(self):
        pass
