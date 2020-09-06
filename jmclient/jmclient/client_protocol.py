#! /usr/bin/env python
from twisted.internet import protocol, reactor, task
from twisted.internet.error import (ConnectionLost, ConnectionAborted,
                                    ConnectionClosed, ConnectionDone)
from twisted.protocols import amp
try:
    from twisted.internet.ssl import ClientContextFactory
except ImportError:
    pass
from jmbase import commands
import binascii
import json
import hashlib
import os
import sys
from jmbase import (get_log, EXIT_FAILURE, hextobin, bintohex,
                    utxo_to_utxostr)
from jmclient import (jm_single, get_irc_mchannels,
                      RegtestBitcoinCoreInterface)
import jmbitcoin as btc


jlog = get_log()

class JMProtocolError(Exception):
    pass

class JMClientProtocol(amp.AMP):
    def __init__(self, factory, client, nick_priv=None):
            self.client = client
            self.factory = factory
            if not nick_priv:
                self.nick_priv = hashlib.sha256(
                    os.urandom(16)).digest() + b"\x01"
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
        jlog.debug('connection was made, starting client.')
        self.factory.setClient(self)
        self.clientStart()

    def set_nick(self):
        """ Algorithm: take pubkey and hex-serialized it;
        then SHA2(hexpub) but truncate output to nick_hashlen.
        Then encode to a base58 string (no check).
        Then prepend J and version char (e.g. '5').
        Finally append padding to nick_maxencoded (+2).
        """
        self.nick_pubkey = btc.privkey_to_pubkey(self.nick_priv)
        # note we use binascii hexlify directly here because input
        # to hashing must be encoded.
        self.nick_pkh_raw = hashlib.sha256(binascii.hexlify(
            self.nick_pubkey)).digest()[:self.nick_hashlen]
        self.nick_pkh = btc.base58.encode(self.nick_pkh_raw)
        #right pad to maximum possible; b58 is not fixed length.
        #Use 'O' as one of the 4 not included chars in base58.
        self.nick_pkh += 'O' * (self.nick_maxencoded - len(self.nick_pkh))
        #The constructed length will be 1 + 1 + NICK_MAX_ENCODED
        self.nick = self.nick_header + str(self.jm_version) + self.nick_pkh
        jm_single().nickname = self.nick
        informuser = getattr(self.client, "inform_user_details", None)
        if callable(informuser):
            informuser()

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
        msg_to_return = str(msg) + " " + bintohex(self.nick_pubkey) + " " + sig
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
        pubkey_bin = hextobin(pubkey)
        verif_result = True
        if not btc.ecdsa_verify(str(msg), sig, pubkey_bin):
            # workaround for hostid, which sometimes is lowercase-only for some IRC connections
            if not btc.ecdsa_verify(str(msg[:-len(hostid)] + hostid.lower()), sig, pubkey_bin):
                jlog.debug("nick signature verification failed, ignoring: " + str(nick))
                verif_result = False
        #check that nick matches hash of pubkey
        nick_pkh_raw = hashlib.sha256(pubkey.encode("ascii")).digest()[:hashlen]
        nick_stripped = nick[2:2 + max_encoded]
        #strip right padding
        nick_unpadded = ''.join([x for x in nick_stripped if x != 'O'])
        if not nick_unpadded == btc.base58.encode(nick_pkh_raw):
            jlog.debug("Nick hash check failed, expected: " + str(nick_unpadded)
                       + ", got: " + str(btc.base58.encode(nick_pkh_raw)))
            verif_result = False
        d = self.callRemote(commands.JMMsgSignatureVerify,
                            verif_result=verif_result,
                            nick=nick,
                            fullmsg=fullmsg,
                            hostid=hostid)
        self.defaultCallbacks(d)
        return {'accepted': True}

    def make_tx(self, nick_list, txhex):
        d = self.callRemote(commands.JMMakeTx,
                            nick_list= json.dumps(nick_list),
                            txhex=txhex)
        self.defaultCallbacks(d)

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
            # json does not allow non-string keys:
            utxos_strkeyed = {}
            for k in utxos:
                success, u = utxo_to_utxostr(k)
                assert success
                utxos_strkeyed[u] = {"value": utxos[k]["value"],
                                     "address": utxos[k]["address"]}
            auth_pub_hex = bintohex(auth_pub)
            d = self.callRemote(commands.JMIOAuth,
                                nick=nick,
                                utxolist=json.dumps(utxos_strkeyed),
                                pubkey=auth_pub_hex,
                                cjaddr=cj_addr,
                                changeaddr=change_addr,
                                pubkeysig=btc_sig)
            self.defaultCallbacks(d)
        return {"accepted": True}

    @commands.JMTXReceived.responder
    def on_JM_TX_RECEIVED(self, nick, txhex, offer):
        offer = json.loads(offer)
        retval = self.client.on_tx_received(nick, txhex, offer)
        if not retval[0]:
            jlog.info("Maker refuses to continue on receipt of tx")
        else:
            sigs = retval[1]
            self.finalized_offers[nick] = offer
            tx = btc.CMutableTransaction.deserialize(hextobin(txhex))
            self.finalized_offers[nick]["txd"] = tx
            txid = tx.GetTxid()[::-1]
            # we index the callback by the out-set of the transaction,
            # because the txid is not known until all scriptSigs collected
            # (hence this is required for Makers, but not Takers).
            # For more info see WalletService.transaction_monitor():
            txinfo = tuple((x.scriptPubKey, x.nValue) for x in tx.vout)
            self.client.wallet_service.register_callbacks([self.unconfirm_callback],
                                              txinfo, "unconfirmed")
            self.client.wallet_service.register_callbacks([self.confirm_callback],
                                              txinfo, "confirmed")

            task.deferLater(reactor, float(jm_single().config.getint("TIMEOUT",
                            "unconfirm_timeout_sec")),
                            self.client.wallet_service.check_callback_called,
                            txinfo, self.unconfirm_callback, "unconfirmed",
                "transaction with outputs: " + str(txinfo) + " not broadcast.")

            d = self.callRemote(commands.JMTXSigs,
                                nick=nick,
                                sigs=json.dumps(sigs))
            self.defaultCallbacks(d)
        return {"accepted": True}

    def tx_match(self, txd):
        for k,v in self.finalized_offers.items():
            # Tx considered defined by its output set
            if v["txd"].vout == txd.vout:
                offerinfo = v
                break
        else:
            return False
        return offerinfo

    def unconfirm_callback(self, txd, txid):
        #find the offer for this tx
        offerinfo = self.tx_match(txd)
        if not offerinfo:
            return False
        to_cancel, to_announce = self.client.on_tx_unconfirmed(offerinfo,
                                                               txid)
        self.client.modify_orders(to_cancel, to_announce)

        txinfo = tuple((x.scriptPubKey, x.nValue) for x in txd.vout)
        confirm_timeout_sec = float(jm_single().config.get(
            "TIMEOUT", "confirm_timeout_hours")) * 3600
        task.deferLater(reactor, confirm_timeout_sec,
                        self.client.wallet_service.check_callback_called,
                        txinfo, self.confirm_callback, "confirmed",
        "transaction with outputs " + str(txinfo) + " not confirmed.")

        d = self.callRemote(commands.JMAnnounceOffers,
                            to_announce=json.dumps(to_announce),
                            to_cancel=json.dumps(to_cancel),
                            offerlist=json.dumps(self.client.offerlist))
        self.defaultCallbacks(d)
        return True

    def confirm_callback(self, txd, txid, confirms):
        #find the offer for this tx
        offerinfo = self.tx_match(txd)
        if not offerinfo:
            return False
        jlog.info('tx in a block: ' + txid + ' with ' + str(
            confirms) + ' confirmations.')
        to_cancel, to_announce = self.client.on_tx_confirmed(offerinfo,
                                                     txid, confirms)
        self.client.modify_orders(to_cancel, to_announce)
        d = self.callRemote(commands.JMAnnounceOffers,
                        to_announce=json.dumps(to_announce),
                        to_cancel=json.dumps(to_cancel),
                        offerlist=json.dumps(self.client.offerlist))
        self.defaultCallbacks(d)
        return True

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
        tx construction. If there were sufficient makers, data is passed
        over for exactly those makers that responded. If not, the list
        of non-responsive makers is added to the permanent "ignored_makers"
        list, but the Taker processing is bypassed and the transaction
        is abandoned here (so will be picked up as stalled in multi-join
        schedules).
        In the first of the above two cases, after the Taker processes
        the ioauth data and returns the proposed
        transaction, passes the phase 2 initiating data to the daemon.
        """
        ioauth_data = json.loads(ioauth_data)
        if not success:
            jlog.info("Makers who didnt respond: " + str(ioauth_data))
            self.client.add_ignored_makers(ioauth_data)
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
                self.client.on_finished_callback(False, False, 0.0)
            return {'accepted': True}
        elif retval[0] == "commitment-failure":
            #This case occurs if we cannot find any utxos for reasons
            #other than age, which is a permanent failure
            self.client.on_finished_callback(False, False, 0.0)
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

def start_reactor(host, port, factory, ish=True, daemon=False, rs=True,
                  gui=False): #pragma: no cover
    #(Cannot start the reactor in tests)
    #Not used in prod (twisted logging):
    #startLogging(stdout)
    usessl = True if jm_single().config.get("DAEMON", "use_ssl") != 'false' else False
    if daemon:
        try:
            from jmdaemon import JMDaemonServerProtocolFactory, start_daemon
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
                start_daemon(host, port, dfactory, usessl,
                             './ssl/key.pem', './ssl/cert.pem')
                jlog.info("Listening on port " + str(port))
                break
            except Exception:
                jlog.warn("Cannot listen on port " + str(port) + ", trying next port")
                if port >= (orgport + 100):
                    jlog.error("Tried 100 ports but cannot listen on any of them. Quitting.")
                    sys.exit(EXIT_FAILURE)
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
