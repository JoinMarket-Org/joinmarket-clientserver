#! /usr/bin/env python

from .message_channel import MessageChannelCollection
from .orderbookwatch import OrderbookWatch
from .enc_wrapper import (as_init_encryption, init_keypair, init_pubkey,
                          NaclError)
from .protocol import (COMMAND_PREFIX, ORDER_KEYS, NICK_HASH_LENGTH,
                       NICK_MAX_ENCODED, JM_VERSION, JOINMARKET_NICK_HEADER,
                       COMMITMENT_PREFIXES)
from .irc import IRCMessageChannel

from jmbase.commands import *
from twisted.protocols import amp
from twisted.internet import reactor, ssl
from twisted.internet.protocol import ServerFactory
from twisted.internet.error import (ConnectionLost, ConnectionAborted,
                                    ConnectionClosed, ConnectionDone)
from twisted.python import log
import json
import threading
import os
import copy
from functools import wraps
from numbers import Integral

"""Joinmarket application protocol control flow.
For documentation on protocol (formats, message sequence) see
https://github.com/JoinMarket-Org/JoinMarket-Docs/blob/master/
Joinmarket-messaging-protocol.md
"""
"""
***
API
***
The client-daemon two-way communication is documented in jmbase.commands.py
"""

"""Decorators for limiting which
inbound callbacks trigger in the DaemonProtocol
object.
"""

def maker_only(func):
    @wraps(func)
    def func_wrapper(inst, *args, **kwargs):
        if inst.role == "MAKER":
            return func(inst, *args, **kwargs)
        return None
    return func_wrapper

def taker_only(func):
    @wraps(func)
    def func_wrapper(inst, *args, **kwargs):
        if inst.role == "TAKER":
            return func(inst, *args, **kwargs)
        return None
    return func_wrapper

def check_utxo_blacklist(commitment, persist=False):
    """Compare a given commitment with the persisted blacklist log file,
    which is hardcoded to this directory and name 'commitmentlist' (no
    security or privacy issue here).
    If the commitment has been used before, return False (disallowed),
    else return True.
    If flagged, persist the usage of this commitment to the above file.
    """
    #TODO format error checking?
    fname = "commitmentlist"
    if os.path.isfile(fname):
        with open(fname, "rb") as f:
            blacklisted_commitments = [x.decode('ascii').strip() for x in f.readlines()]
    else:
        blacklisted_commitments = []
    if commitment in blacklisted_commitments:
        return False
    elif persist:
        blacklisted_commitments += [commitment]
        with open(fname, "wb") as f:
            f.write('\n'.join(blacklisted_commitments).encode('ascii'))
            f.flush()
    #If the commitment is new and we are *not* persisting, nothing to do
    #(we only add it to the list on sending io_auth, which represents actual
    #usage).
    return True

class JMProtocolError(Exception):
    pass

class JMDaemonServerProtocol(amp.AMP, OrderbookWatch):

    def __init__(self, factory):
        self.factory = factory
        self.jm_state = 0
        self.restart_mc_required = False
        self.irc_configs = None
        self.mcc = None
        #Default role is TAKER; must be overriden to MAKER in JMSetup message.
        self.role = "TAKER"
        self.crypto_boxes = {}
        self.sig_lock = threading.Lock()
        self.active_orders = {}

    def checkClientResponse(self, response):
        """A generic check of client acceptance; any failure
        is considered criticial.
        """
        if 'accepted' not in response or not response['accepted']:
            reactor.stop() #pragma: no cover

    def defaultErrback(self, failure):
        """TODO better network error handling.
	"""
        failure.trap(ConnectionAborted, ConnectionClosed,
                     ConnectionDone, ConnectionLost)

    def defaultCallbacks(self, d):
        d.addCallback(self.checkClientResponse)
        d.addErrback(self.defaultErrback)

    @JMInit.responder
    def on_JM_INIT(self, bcsource, network, irc_configs, minmakers,
                   maker_timeout_sec):
        """Reads in required configuration from client for a new
        session; feeds back joinmarket messaging protocol constants
        (required for nick creation).
        If a new message channel configuration is required, the current
        one is shutdown in preparation.
        """
        self.maker_timeout_sec = int(maker_timeout_sec)
        self.minmakers = int(minmakers)
        irc_configs = json.loads(irc_configs)
        #(bitcoin) network only referenced in channel name construction
        self.network = network
        if irc_configs == self.irc_configs:
            self.restart_mc_required = False
            log.msg("New init received did not require a new message channel"
                    " setup.")
        else:
            if self.irc_configs:
                #close the existing connections
                self.mc_shutdown()
            self.irc_configs = irc_configs
            self.restart_mc_required = True
            mcs = [IRCMessageChannel(c,
                                     daemon=self,
                                     realname='btcint=' + bcsource)
                   for c in self.irc_configs]
            self.mcc = MessageChannelCollection(mcs)
            OrderbookWatch.set_msgchan(self, self.mcc)
            #register taker-specific msgchan callbacks here
            self.mcc.register_taker_callbacks(self.on_error, self.on_pubkey,
                                              self.on_ioauth, self.on_sig)
            self.mcc.register_maker_callbacks(self.on_orderbook_requested,
                                              self.on_order_fill,
                                              self.on_seen_auth,
                                              self.on_seen_tx,
                                              self.on_push_tx,
                                              self.on_commitment_seen,
                                              self.on_commitment_transferred)
            self.mcc.set_daemon(self)
        d = self.callRemote(JMInitProto,
                            nick_hash_length=NICK_HASH_LENGTH,
                            nick_max_encoded=NICK_MAX_ENCODED,
                            joinmarket_nick_header=JOINMARKET_NICK_HEADER,
                            joinmarket_version=JM_VERSION)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @JMStartMC.responder
    def on_JM_START_MC(self, nick):
        """Starts message channel threads, if we are working with
        a new message channel configuration. Sets new nick if required.
        JM_UP will be called when the welcome messages are received.
        """
        self.init_connections(nick)
        return {'accepted': True}

    @JMSetup.responder
    def on_JM_SETUP(self, role, initdata):
        assert self.jm_state == 0
        self.role = role
        self.crypto_boxes = {}
        self.kp = init_keypair()
        d = self.callRemote(JMSetupDone)
        self.defaultCallbacks(d)
        #Request orderbook here, on explicit setup request from client,
        #assumes messagechannels are in "up" state. Orders are read
        #in the callback on_order_seen in OrderbookWatch.
        #TODO: pubmsg should not (usually?) fire if already up from previous run.
        if self.role == "TAKER":
            self.mcc.pubmsg(COMMAND_PREFIX + "orderbook")
        elif self.role == "MAKER":
            self.offerlist = json.loads(initdata)
            self.mcc.announce_orders(self.offerlist)
        self.jm_state = 1
        return {'accepted': True}

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

    """Taker specific responders
    """

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
        self.defaultCallbacks(d)
        return {'accepted': True}

    @JMFill.responder
    def on_JM_FILL(self, amount, commitment, revelation, filled_offers):
        """Takes the necessary data from the Taker and initiates the Stage 1
        interaction with the Makers.
        """
        if not (self.jm_state == 1 and isinstance(amount, Integral)
                and amount >= 0):
            return {'accepted': False}
        self.cjamount = amount
        self.commitment = commitment
        self.revelation = revelation
        #Reset utxo data to null for this new transaction
        self.ioauth_data = {}
        self.active_orders = json.loads(filled_offers)
        for nick, offer_dict in self.active_orders.items():
            offer_fill_msg = " ".join([str(offer_dict["oid"]), str(amount),
                self.kp.hex_pk().decode('ascii'), str(commitment)])
            self.mcc.prepare_privmsg(nick, "fill", offer_fill_msg)
        reactor.callLater(self.maker_timeout_sec, self.completeStage1)
        self.jm_state = 2
        return {'accepted': True}

    @JMMakeTx.responder
    def on_JM_MAKE_TX(self, nick_list, txhex):
        """Taker sends the prepared unsigned transaction
	to all the Makers in nick_list
	"""
        if not self.jm_state == 4:
            log.msg("Make tx was called in wrong state, rejecting")
            return {'accepted': False}
        nick_list = json.loads(nick_list)
        self.mcc.send_tx(nick_list, txhex)
        return {'accepted': True}

    @JMPushTx.responder
    def on_JM_PushTx(self, nick, txhex):
        self.mcc.push_tx(nick, txhex)
        return {'accepted': True}

    """Maker specific responders
    """

    @JMAnnounceOffers.responder
    def on_JM_ANNOUNCE_OFFERS(self, to_announce, to_cancel, offerlist):
        """Called by Maker to reset his current offerlist;
	Daemon decides what messages (cancel, announce) to
	send to the message channel.
	"""
        if self.role != "MAKER":
            return
        to_announce = json.loads(to_announce)
        to_cancel = json.loads(to_cancel)
        self.offerlist = json.loads(offerlist)
        if len(to_cancel) > 0:
            self.mcc.cancel_orders(to_cancel)
        if len(to_announce) > 0:
            self.mcc.announce_orders(to_announce, None, None)
        return {"accepted": True}

    @JMIOAuth.responder
    def on_JM_IOAUTH(self, nick, utxolist, pubkey, cjaddr, changeaddr, pubkeysig):
        """Daemon constructs full !ioauth message to be sent on message
	channel based on data from Maker. Relevant data (utxos, addresses)
	are stored in the active_orders dict keyed by the nick of the Taker.
	"""
        if not self.role == "MAKER":
            return
        if not nick in self.active_orders:
            return
        utxos= json.loads(utxolist)
        #completed population of order/offer object
        self.active_orders[nick]["cjaddr"] = cjaddr
        self.active_orders[nick]["changeaddr"] = changeaddr
        self.active_orders[nick]["utxos"] = utxos
        msg = str(",".join(utxos.keys())) + " " + " ".join(
            [pubkey, cjaddr, changeaddr, pubkeysig])
        self.mcc.prepare_privmsg(nick, "ioauth", msg)
        #In case of *blacklisted (ie already used) commitments, we already
        #broadcasted them on receipt; in case of valid, and now used commitments,
        #we broadcast them here, and not early - to avoid accidentally
        #blacklisting commitments that are broadcast between makers in real time
        #for the same transaction.
        self.transfer_commitment(self.active_orders[nick]["commit"])
        #now persist the fact that the commitment is actually used.
        check_utxo_blacklist(self.active_orders[nick]["commit"], persist=True)
        return {"accepted": True}

    @JMTXSigs.responder
    def on_JM_TX_SIGS(self, nick, sigs):
        """Signatures that the Maker has produced
	are passed here to the daemon as a list and
	broadcast one by one. TODO: could shorten this,
	have more than one sig per message.
	"""
        sigs = json.loads(sigs)
        for sig in sigs:
            self.mcc.prepare_privmsg(nick, "sig", sig)
        return {"accepted": True}

    """Message channel callbacks
    """

    def on_welcome(self):
        """Fired when channel indicated state readiness
        """
        d = self.callRemote(JMUp)
        self.defaultCallbacks(d)

    @maker_only
    def on_orderbook_requested(self, nick, mc=None):
        """Dealt with by daemon, assuming offerlist is up to date
        """
        self.mcc.announce_orders(self.offerlist, nick, mc)

    @maker_only
    def on_order_fill(self, nick, oid, amount, taker_pk, commit):
        """Handled locally in daemon. This is the start of
        communication with the Taker. Does the following:

        * Immediately rejects if commitment is invalid or already used.
        * Checks that the fill is against a valid offer.
        * Establishes encryption with a new ephemeral keypair
        * Creates the amount, commitment and keypair fields in
          active_orders[nick] (or resets if already existing).

        Processing will only return to the Maker once the conversation
        up to !ioauth is complete.
        """
        if nick in self.active_orders:
            log.msg("Restarting transaction for nick: " + nick)
        if not commit[0] in COMMITMENT_PREFIXES:
            self.mcc.send_error(nick,
                                "Unsupported commitment type: " + str(commit[0]))
            return
        scommit = commit[1:]
        if not check_utxo_blacklist(scommit):
            log.msg("Taker utxo commitment is blacklisted, rejecting.")
            self.mcc.send_error(nick, "Commitment is blacklisted: " + str(scommit))
            #Note that broadcast is happening here to reflect an already
            #consumed commitment; it can also be broadcast separately (earlier) on
            #valid usage
            self.transfer_commitment(scommit)
            return
        offer_s = [o for o in self.offerlist if o['oid'] == oid]
        if len(offer_s) == 0:
            self.mcc.send_error(nick, 'oid not found')
        offer = offer_s[0]
        if amount < offer['minsize'] or amount > offer['maxsize']:
            self.mcc.send_error(nick, 'amount out of range')
        #prepare a pubkey for this valid transaction
        kp = init_keypair()
        try:
            crypto_box = as_init_encryption(kp, init_pubkey(taker_pk))
        except NaclError as e:
            log.msg("Unable to set up cryptobox with counterparty: " + repr(e))
            self.mcc.send_error(nick, "Invalid nacl pubkey: " + taker_pk)
            return
        #Note this sets the *whole* dict, old entries (e.g. changeaddr)
        #are removed, so we can't have a conflict between old and new
        #versions of active_orders[nick]
        self.active_orders[nick] = {"crypto_box": crypto_box,
                                        "kp": kp,
                                        "offer": offer,
                                        "amount": amount,
                                        "commit": scommit}
        self.mcc.prepare_privmsg(nick, "pubkey", kp.hex_pk().decode('ascii'))

    @maker_only
    def on_seen_auth(self, nick, commitment_revelation):
        """Passes to Maker the !auth message from the Taker,
	for processing. This will include validating the PoDLE
	commitment revelation against the existing commitment,
	which was already stored in active_orders[nick].
	"""
        if not nick in self.active_orders:
            return
        ao =self.active_orders[nick]
        #ask the client to validate the commitment and prepare the utxo data
        d = self.callRemote(JMAuthReceived,
                            nick=nick,
                            offer=json.dumps(ao["offer"]),
                            commitment=ao["commit"],
                            revelation=json.dumps(commitment_revelation),
                            amount=ao["amount"],
                            kphex=ao["kp"].hex_pk().decode('ascii'))
        self.defaultCallbacks(d)

    @maker_only
    def on_commitment_seen(self, nick, commitment):
        """Triggered when we see a commitment for blacklisting
	appear in the public pit channel.
	"""
        #just add if necessary, ignore return value.
        check_utxo_blacklist(commitment, persist=True)
        log.msg("Received commitment broadcast by other maker: " + str(
            commitment) + ", now blacklisted.")

    @maker_only
    def on_commitment_transferred(self, nick, commitment):
        """Triggered when a privmsg is received from another maker
	with a commitment to announce in public (obfuscation of source).
        We simply post it in public (not affected by whether we ourselves
        are *accepting* commitment broadcasts.
	"""
        self.mcc.pubmsg("!hp2 " + commitment)

    @maker_only
    def on_push_tx(self, nick, txhex):
        """Not yet implemented; ignore rather than raise.
	"""
        log.msg('received pushtx message, ignoring, TODO')

    @maker_only
    def on_seen_tx(self, nick, txhex):
        """Passes the txhex to the Maker for verification
	and signing. Note the security checks occur in Maker.
	"""
        if nick not in self.active_orders:
            return
        #we send a copy of the entire "active_orders" entry except the cryptobox,
        #so make a temporary copy
        ao = copy.deepcopy(self.active_orders[nick])
        del ao["crypto_box"]
        del ao["kp"]
        d = self.callRemote(JMTXReceived,
                            nick=nick,
                            txhex=txhex,
                            offer=json.dumps(ao))
        self.defaultCallbacks(d)

    @taker_only
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

    @taker_only
    def on_ioauth(self, nick, utxo_list, auth_pub, cj_addr, change_addr,
                  btc_sig):
        """Passes through to Taker the information from counterparties once
        they've all been received; note that we must also pass back the maker_pk
        so it can be verified against the btc-sigs for anti-MITM
        """
        if nick not in self.active_orders.keys():
            print("Got an unexpected ioauth from nick: " + str(nick))
            return
        self.ioauth_data[nick] = [utxo_list, auth_pub, cj_addr, change_addr,
                                  btc_sig, self.crypto_boxes[nick][0]]
        if self.ioauth_data.keys() == self.active_orders.keys():
            #Finish early if we got all
            self.respondToIoauths(True)

    @taker_only
    def on_sig(self, nick, sig):
        """Pass signature through to Taker.
        """
        d = self.callRemote(JMSigReceived,
                        nick=nick,
                        sig=sig)
        self.defaultCallbacks(d)

    def on_error(self, msg):
        log.msg("Received error: " + str(msg))

    """The following 2 functions handle requests and responses
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
        with self.sig_lock:
            d = self.callRemote(JMRequestMsgSig,
                            nick=str(nick),
                            cmd=str(cmd),
                            msg=str(msg),
                            msg_to_be_signed=str(msg_to_be_signed),
                            hostid=str(hostid))
            self.defaultCallbacks(d)

    def request_signature_verify(self, msg, fullmsg, sig, pubkey, nick, hashlen,
                                 max_encoded, hostid):
        with self.sig_lock:
            d = self.callRemote(JMRequestMsgSigVerify,
                                msg=msg,
                                fullmsg=fullmsg,
                                sig=sig,
                                pubkey=pubkey,
                                nick=nick,
                                hashlen=hashlen,
                                max_encoded=max_encoded,
                                hostid=hostid)
            self.defaultCallbacks(d)

    def init_connections(self, nick):
        """Sets up message channel connections
        if they are not already up; re-sets joinmarket state to 0
        for a new transaction; effectively means any previous
        incomplete transaction is wiped.
        """
        self.jm_state = 0  #uninited
        if self.restart_mc_required:
            self.mcc.run()
            self.restart_mc_required = False
        else:
            #if we are not restarting the MC,
            #we must simulate the on_welcome message:
            self.on_welcome()
        self.mcc.set_nick(nick)

    def transfer_commitment(self, commit):
        """Send this commitment via privmsg to one (random)
	other maker.
	"""
        crow = self.db.execute(
                        'SELECT DISTINCT counterparty FROM orderbook ORDER BY ' +
                        'RANDOM() LIMIT 1;'
                    ).fetchone()
        if crow is None:
            return
        counterparty = crow['counterparty']
        #TODO de-hardcode hp2
        log.msg("Sending commitment to: " + str(counterparty))
        self.mcc.prepare_privmsg(counterparty, 'hp2', commit)

    def respondToIoauths(self, accepted):
        """Sends the full set of data from the Makers to the
        Taker after processing of first stage is completed,
        using the JMFillResponse command. But if the responses
        were not accepted (including, not sufficient number
        of responses), we send the list of Makers who did not
        respond to the Taker, instead of the ioauth data,
        so that the Taker can keep track of non-responders
        (although note this code is not yet quite ideal, see
        comments below).
        """
        if self.jm_state != 2:
            #this can be called a second time on timeout, in which case we
            #do nothing
            return
        self.jm_state = 3
        if not accepted:
            #use ioauth data field to return the list of non-responsive makers
            nonresponders = [x for x in self.active_orders.keys() if x not
                             in self.ioauth_data.keys()]
        ioauth_data = self.ioauth_data if accepted else nonresponders
        d = self.callRemote(JMFillResponse,
                                success=accepted,
                                ioauth_data = json.dumps(ioauth_data))
        if not accepted:
            #Client simply accepts failure TODO
            self.defaultCallbacks(d)
        else:
            #Act differently if *we* provided utxos, but
            #client does not accept for some reason
            d.addCallback(self.checkUtxosAccepted)
            d.addErrback(self.defaultErrback)

    def completeStage1(self):
        """Timeout of stage 1 requests;
        either send success + ioauth data if enough makers,
        else send failure to client.
        """
        response = True if len(self.ioauth_data.keys()) >= self.minmakers else False
        self.respondToIoauths(response)

    def checkUtxosAccepted(self, accepted):
        if not accepted:
            log.msg("Taker rejected utxos provided; resetting.")
            #TODO create re-set function to start again
        else:
            #only update state if client accepted
            self.jm_state = 4

    def get_crypto_box_from_nick(self, nick):
        """Retrieve the libsodium box object for the counterparty;
        stored differently for Taker and Maker
        """
        if nick in self.crypto_boxes and self.crypto_boxes[nick] != None:
            return self.crypto_boxes[nick][1]
        elif nick in self.active_orders and self.active_orders[nick] != None \
             and "crypto_box" in self.active_orders[nick]:
            return self.active_orders[nick]["crypto_box"]
        else:
            log.msg('something wrong, no crypto object, nick=' + nick +
                      ', message will be dropped')
            return None

    def mc_shutdown(self):
        log.msg("Message channels being shutdown by daemon")
        if self.mcc:
            self.mcc.shutdown()

class JMDaemonServerProtocolFactory(ServerFactory):
    protocol = JMDaemonServerProtocol

    def buildProtocol(self, addr):
        return JMDaemonServerProtocol(self)

def start_daemon(host, port, factory, usessl=False, sslkey=None, sslcert=None):
    if usessl:
        assert sslkey
        assert sslcert
        reactor.listenSSL(
            port, factory, ssl.DefaultOpenSSLContextFactory(sslkey, sslcert),
            interface=host)
    else:
        reactor.listenTCP(port, factory, interface=host)
