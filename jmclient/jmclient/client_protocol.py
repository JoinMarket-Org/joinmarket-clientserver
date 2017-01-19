#! /usr/bin/env python
from __future__ import print_function
from twisted.python.log import startLogging, err
from twisted.internet import protocol, reactor, ssl
from twisted.internet.task import LoopingCall
from twisted.internet.error import (ConnectionLost, ConnectionAborted,
                                    ConnectionClosed, ConnectionDone)
from twisted.python import failure
from twisted.protocols import amp
from twisted.internet.protocol import ClientFactory
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.ssl import ClientContextFactory
from jmbase import commands
from sys import stdout

import json
import random
import string
import time
import hashlib
import os
from jmclient import (Taker, Wallet, jm_single, get_irc_mchannels,
                        load_program_config, get_log)

import btc

jlog = get_log()

class JMProtocolError(Exception):
    pass

class JMTakerClientProtocol(amp.AMP):

    def __init__(self, factory, taker, nick_priv=None):
        self.taker = taker
        self.factory = factory
        self.orderbook = None
        self.supported_messages = ["JM_UP", "JM_SETUP_DONE", "JM_FILL_RESPONSE",
                                   "JM_OFFERS", "JM_SIG_RECEIVED",
                                   "JM_REQUEST_MSGSIG",
                                   "JM_REQUEST_MSGSIG_VERIFY", "JM_INIT_PROTO"]
        if not nick_priv:
            self.nick_priv = hashlib.sha256(os.urandom(16)).hexdigest() + '01'
        else:
            self.nick_priv = nick_priv

        self.shutdown_requested = False

    def checkClientResponse(self, response):
        """A generic check of client acceptance; any failure
        is considered criticial.
        """
        if 'accepted' not in response or not response['accepted']:
            #Unintended client shutdown cannot be tested easily in twisted
            reactor.stop() #pragma: no cover

    def defaultErrback(self, failure):
        #see testing note above
        failure.trap(ConnectionAborted, ConnectionClosed, ConnectionDone,
                     ConnectionLost) #pragma: no cover

    def defaultCallbacks(self, d):
        d.addCallback(self.checkClientResponse)
        d.addErrback(self.defaultErrback)

    def connectionMade(self):
        self.factory.setClient(self)
        self.clientStart()

    def clientStart(self):
        """Upon confirmation of network connection
        to daemon, request message channel initialization
        with relevant config data for our message channels
        """
        #needed only for naming convention in IRC currently
        blockchain_source = jm_single().config.get("BLOCKCHAIN",
                                                   "blockchain_source")
        #needed only for channel naming convention
        network = jm_single().config.get("BLOCKCHAIN", "network")
        irc_configs = get_irc_mchannels()
        minmakers = jm_single().config.getint("POLICY", "minimum_makers")
        maker_timeout_sec = jm_single().maker_timeout_sec
        d = self.callRemote(commands.JMInit,
                            bcsource=blockchain_source,
                            network=network,
                            irc_configs=json.dumps(irc_configs),
                            minmakers=minmakers,
                            maker_timeout_sec=maker_timeout_sec)
        self.defaultCallbacks(d)

    def set_nick(self):
        self.nick_pubkey = btc.privtopub(self.nick_priv)
        self.nick_pkh_raw = hashlib.sha256(self.nick_pubkey).digest()[
                    :self.nick_hashlen]
        self.nick_pkh = btc.changebase(self.nick_pkh_raw, 256, 58)
        #right pad to maximum possible; b58 is not fixed length.
        #Use 'O' as one of the 4 not included chars in base58.
        self.nick_pkh += 'O' * (self.nick_maxencoded - len(self.nick_pkh))
        #The constructed length will be 1 + 1 + NICK_MAX_ENCODED
        self.nick = self.nick_header + str(self.jm_version) + self.nick_pkh
        jm_single().nickname = self.nick

    @commands.JMInitProto.responder
    def on_JM_INIT_PROTO(self, nick_hash_length, nick_max_encoded,
                         joinmarket_nick_header, joinmarket_version):
        """Daemon indicates init-ed status and passes back protocol constants.
        Use protocol settings to set actual nick from nick private key,
        then call setup to instantiate message channel connections in the daemon.
        """
        self.nick_hashlen = nick_hash_length
        self.nick_maxencoded = nick_max_encoded
        self.nick_header = joinmarket_nick_header
        self.jm_version = joinmarket_version
        self.set_nick()
        d = self.callRemote(commands.JMStartMC,
                            nick=self.nick)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMUp.responder
    def on_JM_UP(self):
        d = self.callRemote(commands.JMSetup,
                            role="TAKER",
                            n_counterparties=4) #TODO this number should be set
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMSetupDone.responder
    def on_JM_SETUP_DONE(self):
        jlog.info("JM daemon setup complete")
        #The daemon is ready and has requested the orderbook
        #from the pit; we can request the entire orderbook
        #and filter it as we choose.
        reactor.callLater(jm_single().maker_timeout_sec, self.get_offers)
        return {'accepted': True}

    @commands.JMFillResponse.responder
    def on_JM_FILL_RESPONSE(self, success, ioauth_data):
        """Receives the entire set of phase 1 data (principally utxos)
        from the counterparties and passes through to the Taker for
        tx construction, if successful. Then passes back the phase 2
        initiating data to the daemon.
        """
        ioauth_data = json.loads(ioauth_data)
        if not success:
            jlog.info("Makers didnt respond")
            return {'accepted': True}
        else:
            jlog.info("Makers responded with: " + json.dumps(ioauth_data))
            retval = self.taker.receive_utxos(ioauth_data)
            if not retval[0]:
                jlog.info("Taker is not continuing, phase 2 abandoned.")
                jlog.info("Reason: " + str(retval[1]))
                return {'accepted': False}
            else:
                nick_list, txhex = retval[1:]
                reactor.callLater(0, self.make_tx, nick_list, txhex)
                return {'accepted': True}

    @commands.JMOffers.responder
    def on_JM_OFFERS(self, orderbook):
        self.orderbook = json.loads(orderbook)
        jlog.info("Got the orderbook: " + str(self.orderbook))
        retval = self.taker.initialize(self.orderbook)
        #format of retval is:
        #True, self.cjamount, commitment, revelation, self.filtered_orderbook)
        if not retval[0]:
            jlog.info("Taker not continuing after receipt of orderbook")
            return {'accepted': True}
        amt, cmt, rev, foffers = retval[1:]
        d = self.callRemote(commands.JMFill,
                            amount=amt,
                            commitment=str(cmt),
                            revelation=str(rev),
                            filled_offers=json.dumps(foffers))
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMSigReceived.responder
    def on_JM_SIG_RECEIVED(self, nick, sig):
        retval = self.taker.on_sig(nick, sig)
        return {'accepted': True}

    @commands.JMRequestMsgSig.responder
    def on_JM_REQUEST_MSGSIG(self, nick, cmd, msg, msg_to_be_signed, hostid):
        sig = btc.ecdsa_sign(str(msg_to_be_signed), self.nick_priv)
        msg_to_return = str(msg) + " " + self.nick_pubkey + " " + sig
        d = self.callRemote(commands.JMMsgSignature,
                            nick=nick,
                            cmd=cmd,
                            msg_to_return=msg_to_return,
                            hostid=hostid)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMRequestMsgSigVerify.responder
    def on_JM_REQUEST_MSGSIG_VERIFY(self, msg, fullmsg, sig, pubkey, nick,
                                    hashlen, max_encoded, hostid):
        verif_result = True
        if not btc.ecdsa_verify(str(msg), sig, pubkey):
            jlog.debug("nick signature verification failed, ignoring.")
            verif_result = False
        #check that nick matches hash of pubkey
        nick_pkh_raw = hashlib.sha256(pubkey).digest()[:hashlen]
        nick_stripped = nick[2:2 + max_encoded]
        #strip right padding
        nick_unpadded = ''.join([x for x in nick_stripped if x != 'O'])
        if not nick_unpadded == btc.changebase(nick_pkh_raw, 256, 58):
            jlog.debug("Nick hash check failed, expected: " + str(nick_unpadded)
                       + ", got: " + str(btc.changebase(nick_pkh_raw, 256, 58)))
            verif_result = False
        d = self.callRemote(commands.JMMsgSignatureVerify,
                            verif_result=verif_result,
                            nick=nick,
                            fullmsg=fullmsg,
                            hostid=hostid)
        self.defaultCallbacks(d)
        return {'accepted': True}

    def get_offers(self):
        d = self.callRemote(commands.JMRequestOffers)
        self.defaultCallbacks(d)

    def make_tx(self, nick_list, txhex):
        d = self.callRemote(commands.JMMakeTx,
                            nick_list= json.dumps(nick_list),
                            txhex=txhex)
        self.defaultCallbacks(d)


class JMTakerClientProtocolFactory(protocol.ClientFactory):
    protocol = JMTakerClientProtocol

    def __init__(self, taker):
        self.taker = taker
        self.proto_client = None
    def setClient(self, client):
        self.proto_client = client
    def getClient(self):
        return self.proto_client

    def buildProtocol(self, addr):
        return JMTakerClientProtocol(self, self.taker)


def start_reactor(host, port, factory, ish=True, daemon=False): #pragma: no cover
    #(Cannot start the reactor in tests)
    usessl = True if jm_single().config.get("DAEMON", "use_ssl") != 'false' else False
    if daemon:
        try:
            from jmdaemon import JMDaemonServerProtocolFactory
        except ImportError:
            jlog.error("Cannot start daemon without jmdaemon package; "
                       "either install it, and restart, or, if you want "
                       "to run the daemon separately, edit the DAEMON "
                       "section of the config. Quitting.")
            return
        dfactory = JMDaemonServerProtocolFactory()
        if usessl:
            reactor.listenSSL(port, dfactory,
                          ssl.DefaultOpenSSLContextFactory(
                              "./ssl/key.pem", "./ssl/cert.pem"))
        else:
            reactor.listenTCP(port, dfactory)

    if usessl:
        ctx = ClientContextFactory()
        reactor.connectSSL(host, port, factory, ctx)
    else:
        reactor.connectTCP(host, port, factory)
    reactor.run(installSignalHandlers=ish)
