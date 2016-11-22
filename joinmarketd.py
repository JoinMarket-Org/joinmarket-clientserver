#! /usr/bin/env python
from __future__ import print_function
import sys
from joinmarketdaemon import (IRCMessageChannel, MessageChannelCollection,
                        OrderbookWatch, as_init_encryption, init_pubkey,
                        NaclError, init_keypair, COMMAND_PREFIX, ORDER_KEYS,
                        NICK_HASH_LENGTH, NICK_MAX_ENCODED, JM_VERSION,
                        JOINMARKET_NICK_HEADER)

from joinmarketdaemon.commands import *
from twisted.protocols import amp
from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory
from twisted.python.log import startLogging, err
from twisted.python import log
import json
import time
import threading


"""Joinmarket application protocol control flow.
For documentation on protocol (formats, message sequence) see
https://github.com/JoinMarket-Org/JoinMarket-Docs/blob/master/
Joinmarket-messaging-protocol.md
"""
"""
***
API
***
The client-daemon two-way communication is documented in commands.py
"""


class MCThread(threading.Thread):

    def __init__(self, mc):
        threading.Thread.__init__(self, name='MCThread')
        self.mc = mc
        self.daemon = True

    def run(self):
        self.mc.run()


class JMProtocolError(Exception):
    pass

class JMDaemonServerProtocol(amp.AMP, OrderbookWatch):

    def __init__(self, factory):
        self.factory = factory
        #Set of messages we can receive from a client:
        self.supported_messages = ["JM_INIT", "JM_SETUP", "JM_FILL",
                                   "JM_MAKE_TX", "JM_REQUEST_OFFERS",
                                   "JM_MAKE_TX", "JM_MSGSIGNATURE",
                                   "JM_MSGSIGNATURE_VERIFY", "JM_START_MC"]
        self.jm_state = 0

    def checkClientResponse(self, response):
        """A generic check of client acceptance; any failure
        is considered criticial.
        """
        if 'accepted' not in response or not response['accepted']:
            reactor.stop()

    @JMInit.responder
    def on_JM_INIT(self, bcsource, network, irc_configs, minmakers,
                   maker_timeout_sec):
        self.maker_timeout_sec = int(maker_timeout_sec)
        self.minmakers = int(minmakers)
        irc_configs = json.loads(irc_configs)
        mcs = [IRCMessageChannel(c,
                                 daemon=self,
                                 realname='btcint=' + bcsource)
               for c in irc_configs]
        #(bitcoin) network only referenced in channel name construction
        self.network = network
        self.mcc = MessageChannelCollection(mcs)
        OrderbookWatch.set_msgchan(self, self.mcc)
        #register taker-specific msgchan callbacks here
        self.mcc.register_taker_callbacks(self.on_error, self.on_pubkey,
                                          self.on_ioauth, self.on_sig)
        self.mcc.set_daemon(self)
        d = self.callRemote(JMInitProto,
                            nick_hash_length=NICK_HASH_LENGTH,
                            nick_max_encoded=NICK_MAX_ENCODED,
                            joinmarket_nick_header=JOINMARKET_NICK_HEADER,
                            joinmarket_version=JM_VERSION)
        d.addCallback(self.checkClientResponse)
        return {'accepted': True}

    @JMStartMC.responder
    def on_JM_START_MC(self, nick):
        """Starts message channel threads;
        JM_UP will be called when the welcome messages are received.
        """
        self.init_connections(nick)
        return {'accepted': True}

    def init_connections(self, nick):
        self.jm_state = 0  #uninited
        self.mcc.set_nick(nick)
        MCThread(self.mcc).start()

    def on_welcome(self):
        """Fired when channel indicated state readiness
        """
        d = self.callRemote(JMUp)
        d.addCallback(self.checkClientResponse)

    @JMSetup.responder
    def on_JM_SETUP(self, role, n_counterparties):
        assert self.jm_state == 0
        assert n_counterparties > 1
        #TODO consider MAKER role implementation here
        assert role == "TAKER"
        self.requested_counterparties = n_counterparties
        self.crypto_boxes = {}
        self.kp = init_keypair()
        print("Received setup command")
        d = self.callRemote(JMSetupDone)
        d.addCallback(self.checkClientResponse)
        #Request orderbook here, on explicit setup request from client,
        #assumes messagechannels are in "up" state. Orders are read
        #in the callback on_order_seen in OrderbookWatch.
        self.mcc.pubmsg(COMMAND_PREFIX + "orderbook")
        self.jm_state = 1
        return {'accepted': True}

    @JMRequestOffers.responder
    def on_JM_REQUEST_OFFERS(self):
        """Reports the current state of the orderbook.
        This call is stateless."""
        rows = self.db.execute('SELECT * FROM orderbook;').fetchall()
        self.orderbook = [dict([(k, o[k]) for k in ORDER_KEYS]) for o in rows]
        log.msg("About to send orderbook of size: " + str(len(self.orderbook)))
        string_orderbook = json.dumps(self.orderbook)
        d = self.callRemote(JMOffers,
                        orderbook=string_orderbook)
        d.addCallback(self.checkClientResponse)
        return {'accepted': True}

    @JMFill.responder
    def on_JM_FILL(self, amount, commitment, revelation, filled_offers):
        if not (self.jm_state == 1 and isinstance(amount, int) and amount >=0):
            return {'accepted': False}
        self.cjamount = amount
        self.commitment = commitment
        self.revelation = revelation
        #Reset utxo data to null for this new transaction
        self.ioauth_data = {}
        self.active_orders = json.loads(filled_offers)
        for nick, offer_dict in self.active_orders.iteritems():
            offer_fill_msg = " ".join([str(offer_dict["oid"]), str(amount), str(
                self.kp.hex_pk()), str(commitment)])
            self.mcc.prepare_privmsg(nick, "fill", offer_fill_msg)
        self.first_stage_timer = time.time()
        self.jm_state = 2
        return {'accepted': True}

    def on_pubkey(self, nick, maker_pk):
        """This is handled locally in the daemon; set up e2e
        encrypted messaging with this counterparty
        """
        if nick not in self.active_orders.keys():
            log.msg("Counterparty not part of this transaction. Ignoring")
            return
        try:
            self.crypto_boxes[nick] = [maker_pk, as_init_encryption(
                self.kp, init_pubkey(maker_pk))]
        except NaclError as e:
            print("Unable to setup crypto box with " + nick + ": " + repr(e))
            self.mcc.send_error(nick, "invalid nacl pubkey: " + maker_pk)
            return
        self.mcc.prepare_privmsg(nick, "auth", str(self.revelation))

    def on_ioauth(self, nick, utxo_list, auth_pub, cj_addr, change_addr,
                  btc_sig):
        """Passes through to Taker the information from counterparties once
        they've all been received; note that we must also pass back the maker_pk
        so it can be verified against the btc-sigs for anti-MITM
        """
        def respond(accepted):
            d = self.callRemote(JMFillResponse,
                                success=accepted,
                                ioauth_data = json.dumps(self.ioauth_data))
            if not accepted:
                #Client simply accepts failure TODO
                d.addCallback(self.checkClientResponse)
            else:
                #Act differently if *we* provided utxos, but
                #client does not accept for some reason
                d.addCallback(self.checkUtxosAccepted)

        if nick not in self.active_orders.keys():
            print("Got an unexpected ioauth from nick: " + str(nick))
            return
        self.ioauth_data[nick] = [utxo_list, auth_pub, cj_addr, change_addr,
                                  btc_sig, self.crypto_boxes[nick][0]]
        if self.ioauth_data.keys() == self.active_orders.keys():
            respond(True)
        else:
            time_taken = time.time() - self.first_stage_timer
            #if the timer has run out, either pass through if we have
            #at least minmakers, else return a failure condition
            if time_taken > self.maker_timeout_sec:
                if len(self.ioauth_data.keys()) >= self.minmakers:
                    respond(True)
                else:
                    respond(False)

    def checkUtxosAccepted(self, accepted):
        if not accepted:
            log.msg("Taker rejected utxos provided; resetting.")
            #TODO create re-set function to start again

    @JMMakeTx.responder
    def on_JM_MAKE_TX(self, nick_list, txhex):
        if not self.jm_state == 2:
            return {'accepted': False}
        nick_list = json.loads(nick_list)
        self.mcc.send_tx(nick_list, txhex)
        return {'accepted': True}

    def on_sig(self, nick, sig):
        """Pass signature through to Taker.
        """
        d = self.callRemote(JMSigReceived,
                        nick=nick,
                        sig=sig)
        d.addCallback(self.checkClientResponse)

    """The following functions handle requests and responses
    from client for messaging signing and verifying.
    """
    def request_signed_message(self, nick, cmd, msg, msg_to_be_signed, hostid):
        """The daemon passes the nick and cmd fields
        to the client so it can be echoed back to the privmsg
        after return (with signature); note that the cmd is already
        inside "msg" after having been parsed in MessageChannel; this
        duplication is so that the client does not need to know the
        message syntax.
        """
        d = self.callRemote(JMRequestMsgSig,
                        nick=str(nick),
                        cmd=str(cmd),
                        msg=str(msg),
                        msg_to_be_signed=str(msg_to_be_signed),
                        hostid=str(hostid))
        d.addCallback(self.checkClientResponse)

    def request_signature_verify(self, msg, fullmsg, sig, pubkey, nick, hashlen,
                                 max_encoded, hostid):
        d = self.callRemote(JMRequestMsgSigVerify,
                            msg=msg,
                            fullmsg=fullmsg,
                            sig=sig,
                            pubkey=pubkey,
                            nick=nick,
                            hashlen=hashlen,
                            max_encoded=max_encoded,
                            hostid=hostid)
        d.addCallback(self.checkClientResponse)

    @JMMsgSignature.responder
    def on_JM_MSGSIGNATURE(self, nick, cmd, msg_to_return, hostid):
        self.mcc.privmsg(nick, cmd, msg_to_return, mc=hostid)
        return {'accepted': True}

    @JMMsgSignatureVerify.responder
    def on_JM_MSGSIGNATURE_VERIFY(self, verif_result, nick, fullmsg, hostid):
        if not verif_result:
            log.msg("Verification failed for nick: " + str(nick))
        else:
            self.mcc.on_verified_privmsg(nick, fullmsg, hostid)
        return {'accepted': True}

    def get_crypto_box_from_nick(self, nick):
        if nick in self.crypto_boxes and self.crypto_boxes[nick] != None:
            return self.crypto_boxes[nick][1]  # libsodium encryption object
        else:
            log.msg('something wrong, no crypto object, nick=' + nick +
                      ', message will be dropped')
            return None

    def on_error(self):
        log.msg("Unimplemented on_error")

    def mc_shutdown(self):
        log.msg("Message channels shut down in proto")
        self.mcc.shutdown()


class JMDaemonServerProtocolFactory(ServerFactory):
    protocol = JMDaemonServerProtocol

    def buildProtocol(self, addr):
        return JMDaemonServerProtocol(self)

def startup_joinmarketd(port, finalizer=None, finalizer_args=None):
    """Start event loop for joinmarket daemon here.
    Args:
    port : port over which to serve the daemon
    finalizer: a function which is called after the reactor has shut down.
    finalizer_args : arguments to finalizer function.
    """
    log.startLogging(sys.stdout)
    factory = JMDaemonServerProtocolFactory()
    reactor.listenTCP(port, factory)
    if finalizer:
        reactor.addSystemEventTrigger("after", "shutdown", finalizer,
                                      finalizer_args)
    reactor.run()


if __name__ == "__main__":
    port = int(sys.argv[1])
    startup_joinmarketd(port)
