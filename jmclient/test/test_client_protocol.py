#! /usr/bin/env python
from __future__ import absolute_import

'''test client-protocol interfacae.'''

import pytest
from jmclient import (get_schedule, load_program_config, start_reactor,
                      Taker, get_log, JMClientProtocolFactory, jm_single)
from jmclient.client_protocol import JMProtocolError, JMTakerClientProtocol
import os
from twisted.python.log import startLogging, err
from twisted.python.log import msg as tmsg
from twisted.internet import protocol, reactor, task
from twisted.internet.error import (ConnectionLost, ConnectionAborted,
                                    ConnectionClosed, ConnectionDone)
from twisted.protocols.amp import UnknownRemoteError
from twisted.python import failure
from twisted.protocols import amp
from twisted.trial import unittest
from jmbase.commands import *
from taker_test_data import t_raw_signed_tx
import json
import time
import jmbitcoin as bitcoin

import twisted

twisted.internet.base.DelayedCall.debug = True

test_completed = False

clientfactory = None
runno = 0
jlog = get_log()


def dummy_taker_finished(res, fromtx, waittime=0.0):
    pass


class DummyTaker(Taker):

    def set_fail_init(self, val):
        self.failinit = val

    def set_fail_utxos(self, val):
        self.failutxos = val

    def default_taker_info_callback(self, infotype, msg):
        jlog.debug(infotype + ":" + msg)

    def initialize(self, orderbook):
        """Once the daemon is active and has returned the current orderbook,
        select offers, re-initialize variables and prepare a commitment,
        then send it to the protocol to fill offers.
        """
        if self.failinit == -1:
            return (True, -1, "aa" * 32, {'dummy': 'revelation'}, orderbook[:2])
        elif self.failinit:
            return (False,)
        else:
            return (True, 1000000, "aa" * 32, {'dummy': 'revelation'},
                    orderbook[:2])

    def receive_utxos(self, ioauth_data):
        """Triggered when the daemon returns utxo data from
        makers who responded; this is the completion of phase 1
        of the protocol
        """
        if self.failutxos:
            return (False, "dummyreason")
        else:
            return (True, [x * 64 + ":01" for x in ["a", "b", "c"]], t_raw_signed_tx)

    def on_sig(self, nick, sigb64):
        """For test, we exit 'early' on first message, since this marks the end
        of client-server communication with the daemon.
        """
        jlog.debug("We got a sig: " + sigb64)
        end_test()
        return None


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
    tmsg("Received msgtype: " + name + ", args: " + ",".join([str(x) for x in args]))


def end_client(client):
    pass


def end_test():
    global test_completed
    test_completed = True
    client = clientfactory.getClient()
    reactor.callLater(1, end_client, client)


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
        # build a huge orderbook to test BigString Argument
        orderbook = ["aaaa" for _ in range(15)]
        d = self.callRemote(JMOffers,
                            orderbook=json.dumps(orderbook))
        self.defaultCallbacks(d)
        return {'accepted': True}

    @JMFill.responder
    def on_JM_FILL(self, amount, commitment, revelation, filled_offers):
        success = False if amount == -1 else True
        show_receipt("JMFILL", amount, commitment, revelation, filled_offers)
        d = self.callRemote(JMFillResponse,
                            success=success,
                            ioauth_data=json.dumps(['dummy', 'list']))
        return {'accepted': True}

    @JMMakeTx.responder
    def on_JM_MAKE_TX(self, nick_list, txhex):
        show_receipt("JMMAKETX", nick_list, txhex)
        d = self.callRemote(JMSigReceived,
                            nick="dummynick",
                            sig="xxxsig")
        self.defaultCallbacks(d)
        # add dummy calls to check message sign and message verify
        d2 = self.callRemote(JMRequestMsgSig,
                             nick="dummynickforsign",
                             cmd="command1",
                             msg="msgforsign",
                             msg_to_be_signed="fullmsgforsign",
                             hostid="hostid1")
        self.defaultCallbacks(d2)
        # To test, this must include a valid ecdsa sig
        fullmsg = "fullmsgforverify"
        priv = "aa" * 32 + "01"
        pub = bitcoin.privkey_to_pubkey(priv)
        sig = bitcoin.ecdsa_sign(fullmsg, priv)
        d3 = self.callRemote(JMRequestMsgSigVerify,
                             msg="msgforverify",
                             fullmsg=fullmsg,
                             sig=sig,
                             pubkey=pub,
                             nick="dummynickforverify",
                             hashlen=4,
                             max_encoded=5,
                             hostid="hostid2")
        self.defaultCallbacks(d3)
        d4 = self.callRemote(JMSigReceived,
                             nick="dummynick",
                             sig="dummysig")
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


class JMTestServerProtocolFactory(protocol.ServerFactory):
    protocol = JMTestServerProtocol


class DummyClientProtocolFactory(JMClientProtocolFactory):
    def buildProtocol(self, addr):
        return JMTakerClientProtocol(self, self.client, nick_priv="aa" * 32)


class TrialTestJMClientProto(unittest.TestCase):

    def setUp(self):
        global clientfactory
        print("setUp()")
        params = [[False, False], [True, False], [False, True], [-1, False]]
        load_program_config()
        jm_single().maker_timeout_sec = 1
        self.port = reactor.listenTCP(28184, JMTestServerProtocolFactory())
        self.addCleanup(self.port.stopListening)

        def cb(client):
            self.client = client
            self.addCleanup(self.client.transport.loseConnection)

        clientfactories = []
        takers = [DummyTaker(
            None, ["a", "b"], callbacks=(
                None, None, dummy_taker_finished)) for _ in range(len(params))]
        for i, p in enumerate(params):
            takers[i].set_fail_init(p[0])
            takers[i].set_fail_utxos(p[1])
            takers[i].testflag = True
            if i != 0:
                clientfactories.append(JMClientProtocolFactory(takers[i]))
                clientconn = reactor.connectTCP("localhost", 28184,
                                                clientfactories[i])
                self.addCleanup(clientconn.disconnect)
            else:
                clientfactories.append(DummyClientProtocolFactory(takers[i]))
                clientfactory = clientfactories[0]
                clientconn = reactor.connectTCP("localhost", 28184,
                                                clientfactories[0])
                self.addCleanup(clientconn.disconnect)

    def test_waiter(self):
        print("test_main()")
        return task.deferLater(reactor, 3, self._called_by_deffered)

    def _called_by_deffered(self):
        pass
