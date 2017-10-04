#! /usr/bin/env python
from __future__ import print_function
from twisted.python.log import startLogging, err
from twisted.internet import protocol, reactor, task
from twisted.internet.task import LoopingCall
from twisted.internet.error import (ConnectionLost, ConnectionAborted,
                                    ConnectionClosed, ConnectionDone)
from twisted.python import failure
from twisted.protocols import amp
from twisted.internet.protocol import ClientFactory
from twisted.internet.endpoints import TCP4ClientEndpoint
try:
    from twisted.internet.ssl import ClientContextFactory
    from twisted.internet import ssl
except ImportError:
    pass
from jmbase import commands
from sys import stdout

import json
import random
import string
import time
import hashlib
import os
import sys
import pprint
from jmclient import (Taker, Wallet, jm_single, get_irc_mchannels,
                        load_program_config, get_log, get_p2sh_vbyte,
                        RegtestBitcoinCoreInterface)
from jmbase import _byteify
import btc

jlog = get_log()

class JMProtocolError(Exception):
    pass

class JMClientProtocol(amp.AMP):
    def __init__(self, factory, client, nick_priv=None):
            self.client = client
            self.factory = factory
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
        print('connection was made, starting client')
        self.factory.setClient(self)
        self.clientStart()

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

class JMMakerClientProtocol(JMClientProtocol):
    def __init__(self, factory, maker, nick_priv=None):
        self.factory = factory
        #used for keeping track of transactions for the unconf/conf callbacks
        self.finalized_offers = {}
        JMClientProtocol.__init__(self, factory, maker, nick_priv)

    @commands.JMUp.responder
    def on_JM_UP(self):
        #wait until ready locally to submit offers (can be delayed
        #if wallet sync is slow).
        self.offers_ready_loop_counter = 0
        self.offers_ready_loop = task.LoopingCall(self.submitOffers)
        self.offers_ready_loop.start(2.0)
        return {'accepted': True}

    def submitOffers(self):
        self.offers_ready_loop_counter += 1
        if self.offers_ready_loop_counter == 300:
            jlog.info("Failed to start after 10 minutes, giving up.")
            self.offers_ready_loop.stop()
            reactor.stop()
        if not self.client.offerlist:
            return
        self.offers_ready_loop.stop()
        d = self.callRemote(commands.JMSetup,
                            role="MAKER",
                            initdata=json.dumps(self.client.offerlist))
        self.defaultCallbacks(d)

    @commands.JMSetupDone.responder
    def on_JM_SETUP_DONE(self):
        jlog.info("JM daemon setup complete")
        return {'accepted': True}

    def clientStart(self):
        """Upon confirmation of network connection
        to daemon, request message channel initialization
        with relevant config data for our message channels
        """
        if self.client.aborted:
            return
        #needed only for naming convention in IRC currently
        blockchain_source = jm_single().config.get("BLOCKCHAIN",
                                                   "blockchain_source")
        #needed only for channel naming convention
        network = jm_single().config.get("BLOCKCHAIN", "network")
        irc_configs = get_irc_mchannels()
        #only here because Init message uses this field; not used by makers TODO
        minmakers = jm_single().config.getint("POLICY", "minimum_makers")
        maker_timeout_sec = jm_single().maker_timeout_sec

        d = self.callRemote(commands.JMInit,
                            bcsource=blockchain_source,
                            network=network,
                            irc_configs=json.dumps(irc_configs),
                            minmakers=minmakers,
                            maker_timeout_sec=maker_timeout_sec)
        self.defaultCallbacks(d)

    @commands.JMAuthReceived.responder
    def on_JM_AUTH_RECEIVED(self, nick, offer, commitment, revelation, amount,
                            kphex):
        offer = json.loads(offer)
        revelation = json.loads(revelation)
        retval = self.client.on_auth_received(nick, offer,
                                            commitment, revelation, amount, kphex)
        if not retval[0]:
            jlog.info("Maker refuses to continue on receiving auth.")
        else:
            utxos, auth_pub, cj_addr, change_addr, btc_sig = retval[1:]
            d = self.callRemote(commands.JMIOAuth,
                                nick=nick,
                                utxolist=json.dumps(utxos),
                                pubkey=auth_pub,
                                cjaddr=cj_addr,
                                changeaddr=change_addr,
                                pubkeysig=btc_sig)
            self.defaultCallbacks(d)
        return {"accepted": True}

    @commands.JMTXReceived.responder
    def on_JM_TX_RECEIVED(self, nick, txhex, offer):
        offer = _byteify(json.loads(offer))
        retval = self.client.on_tx_received(nick, txhex, offer)
        if not retval[0]:
            jlog.info("Maker refuses to continue on receipt of tx")
        else:
            sigs = retval[1]
            self.finalized_offers[nick] = offer
            tx = btc.deserialize(txhex)
            self.finalized_offers[nick]["txd"] = tx
            jm_single().bc_interface.add_tx_notify(tx, self.unconfirm_callback,
                    self.confirm_callback, offer["cjaddr"],
                    wallet_name=jm_single().bc_interface.get_wallet_name(
                        self.client.wallet),
                    txid_flag=False,
                    vb=get_p2sh_vbyte())
            d = self.callRemote(commands.JMTXSigs,
                                nick=nick,
                                sigs=json.dumps(sigs))
            self.defaultCallbacks(d)
        return {"accepted": True}

    def unconfirm_callback(self, txd, txid):
        #find the offer for this tx
        offerinfo = None
        for k,v in self.finalized_offers.iteritems():
            #Tx considered defined by its output set
            if v["txd"]["outs"] == txd["outs"]:
                offerinfo = v
                break
        if not offerinfo:
            jlog.info("Failed to find notified unconfirmed transaction: " + txid)
            return
        removed_utxos = self.client.wallet.remove_old_utxos(txd)
        jlog.info('saw tx on network, removed_utxos=\n{}'.format(
                pprint.pformat(removed_utxos)))
        to_cancel, to_announce = self.client.on_tx_unconfirmed(offerinfo,
                                                               txid, removed_utxos)
        self.client.modify_orders(to_cancel, to_announce)
        d = self.callRemote(commands.JMAnnounceOffers,
                            to_announce=json.dumps(to_announce),
                            to_cancel=json.dumps(to_cancel),
                            offerlist=json.dumps(self.client.offerlist))
        self.defaultCallbacks(d)

    def confirm_callback(self, txd, txid, confirmations):
        #find the offer for this tx
        offerinfo = None
        for k,v in self.finalized_offers.iteritems():
            #Tx considered defined by its output set
            if v["txd"]["outs"] == txd["outs"]:
                offerinfo = v
                break
        if not offerinfo:
            jlog.info("Failed to find notified unconfirmed transaction: " + txid)
            return
        jm_single().bc_interface.wallet_synced = False
        jm_single().bc_interface.sync_unspent(self.client.wallet)
        jlog.info('tx in a block: ' + txid)
        self.wait_for_sync_loop = task.LoopingCall(self.modify_orders, offerinfo,
                                                   confirmations, txid)
        self.wait_for_sync_loop.start(2.0)

    def modify_orders(self, offerinfo, confirmations, txid):
        if not jm_single().bc_interface.wallet_synced:
            return
        self.wait_for_sync_loop.stop()
        to_cancel, to_announce = self.client.on_tx_confirmed(offerinfo,
                                                             confirmations, txid)
        self.client.modify_orders(to_cancel, to_announce)
        d = self.callRemote(commands.JMAnnounceOffers,
                            to_announce=json.dumps(to_announce),
                            to_cancel=json.dumps(to_cancel),
                            offerlist=json.dumps(self.client.offerlist))
        self.defaultCallbacks(d)

class JMTakerClientProtocol(JMClientProtocol):

    def __init__(self, factory, client, nick_priv=None):
        self.orderbook = None
        JMClientProtocol.__init__(self, factory, client, nick_priv)

    def clientStart(self):
        """Upon confirmation of network connection
        to daemon, request message channel initialization
        with relevant config data for our message channels
        """
        if self.client.aborted:
            return
        #needed only for naming convention in IRC currently
        blockchain_source = jm_single().config.get("BLOCKCHAIN",
                                                   "blockchain_source")
        #needed only for channel naming convention
        network = jm_single().config.get("BLOCKCHAIN", "network")
        irc_configs = get_irc_mchannels()
        minmakers = jm_single().config.getint("POLICY", "minimum_makers")
        maker_timeout_sec = jm_single().maker_timeout_sec

        #To avoid creating yet another config variable, we set the timeout
        #to 20 * maker_timeout_sec.
        if not hasattr(self.client, 'testflag'): #pragma: no cover
            reactor.callLater(20*maker_timeout_sec, self.stallMonitor,
                          self.client.schedule_index+1)

        d = self.callRemote(commands.JMInit,
                            bcsource=blockchain_source,
                            network=network,
                            irc_configs=json.dumps(irc_configs),
                            minmakers=minmakers,
                            maker_timeout_sec=maker_timeout_sec)
        self.defaultCallbacks(d)

    def stallMonitor(self, schedule_index):
        """Diagnoses whether long wait is due to any kind of failure;
        if so, calls the taker on_finished_callback with a failure
        flag so that the transaction can be re-tried or abandoned, as desired.
        Note that this *MUST* not trigger any action once the coinjoin transaction
        is seen on the network (hence waiting_for_conf).
        The schedule index parameter tells us whether the processing has moved
        on to the next item before we were woken up.
        """
        jlog.info("STALL MONITOR:")
        if self.client.aborted:
            jlog.info("Transaction was aborted.")
            return
        if not self.client.schedule_index == schedule_index:
            #TODO pre-initialize() ?
            jlog.info("No stall detected, continuing")
            return
        if self.client.waiting_for_conf:
            #Don't restart if the tx is already on the network!
            jlog.info("No stall detected, continuing")
            return
        if not self.client.txid:
            #txid is set on pushing; if it's not there, we have failed.
            jlog.info("Stall detected. Regenerating transactions and retrying.")
            self.client.on_finished_callback(False, True, 0.0)
        else:
            #This shouldn't really happen; if the tx confirmed,
            #the finished callback should already be called.
            jlog.info("Tx was already pushed; ignoring")

    @commands.JMUp.responder
    def on_JM_UP(self):
        d = self.callRemote(commands.JMSetup,
                            role="TAKER",
                            initdata="none")
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
            nonresponders = ioauth_data
            jlog.info("Makers didnt respond: " + str(nonresponders))
            self.client.add_ignored_makers(nonresponders)
            return {'accepted': True}
        else:
            jlog.info("Makers responded with: " + json.dumps(ioauth_data))
            retval = self.client.receive_utxos(ioauth_data)
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
        #Removed for now, as judged too large, even for DEBUG:
        #jlog.debug("Got the orderbook: " + str(self.orderbook))
        retval = self.client.initialize(self.orderbook)
        #format of retval is:
        #True, self.cjamount, commitment, revelation, self.filtered_orderbook)
        if not retval[0]:
            jlog.info("Taker not continuing after receipt of orderbook")
            if len(self.client.schedule) == 1:
                #In single sendpayments, allow immediate quit.
                #This could be an optional feature also for multi-entry schedules,
                #but is not the functionality desired in general (tumbler).
                self.client.on_finished_callback(False, True, 0.0)
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
        retval = self.client.on_sig(nick, sig)
        if retval:
            nick_to_use, txhex = retval
            self.push_tx(nick_to_use, txhex)
        return {'accepted': True}

    def get_offers(self):
        d = self.callRemote(commands.JMRequestOffers)
        self.defaultCallbacks(d)

    def make_tx(self, nick_list, txhex):
        d = self.callRemote(commands.JMMakeTx,
                            nick_list= json.dumps(nick_list),
                            txhex=txhex)
        self.defaultCallbacks(d)

    def push_tx(self, nick_to_push, txhex_to_push):
        d = self.callRemote(commands.JMPushTx, nick=str(nick_to_push),
                            txhex=str(txhex_to_push))
        self.defaultCallbacks(d)

class JMClientProtocolFactory(protocol.ClientFactory):
    protocol = JMTakerClientProtocol

    def __init__(self, client, proto_type="TAKER"):
        self.client = client
        self.proto_client = None
        self.proto_type = proto_type
        if self.proto_type == "MAKER":
            self.protocol = JMMakerClientProtocol

    def setClient(self, client):
        self.proto_client = client
    def getClient(self):
        return self.proto_client

    def buildProtocol(self, addr):
        return self.protocol(self, self.client)

def start_reactor(host, port, factory, ish=True, daemon=False, rs=True, gui=False): #pragma: no cover
    #(Cannot start the reactor in tests)
    #Not used in prod (twisted logging):
    #startLogging(stdout)
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
        orgport = port
        while True:
            try:
                if usessl:
                    reactor.listenSSL(port, dfactory,
                                  ssl.DefaultOpenSSLContextFactory(
                                      "./ssl/key.pem", "./ssl/cert.pem"),
                                     interface=host)
                else:
                    reactor.listenTCP(port, dfactory, interface=host)
                jlog.info("Listening on port " + str(port))
                break
            except Exception:
                jlog.warn("Cannot listen on port " + str(port) + ", trying next port")
                if port >= (orgport + 100):
                    jlog.error("Tried 100 ports but cannot listen on any of them. Quitting.")
                    sys.exit(1)
                port += 1
    if usessl:
        ctx = ClientContextFactory()
        reactor.connectSSL(host, port, factory, ctx)
    else:
        reactor.connectTCP(host, port, factory)
    if rs:
        if not gui:
            reactor.run(installSignalHandlers=ish)
        if isinstance(jm_single().bc_interface, RegtestBitcoinCoreInterface):
            jm_single().bc_interface.shutdown_signal = True
