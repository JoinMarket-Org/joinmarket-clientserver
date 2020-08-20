from zope.interface import implementer
from twisted.internet import reactor
from twisted.web.client import (Agent, readBody, ResponseFailed,
                                BrowserLikePolicyForHTTPS)
from twisted.web.iweb import IPolicyForHTTPS
from twisted.internet.ssl import CertificateOptions
from twisted.internet.error import ConnectionRefusedError
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.web.http_headers import Headers
from txtorcon.web import tor_agent
from txtorcon.socks import HostUnreachableError
import urllib.parse as urlparse
from urllib.parse import urlencode
import json
from pprint import pformat
from jmbase import BytesProducer
from .configure import get_log, jm_single
import jmbitcoin as btc
from .wallet import PSBTWalletMixin, SegwitLegacyWallet, SegwitWallet
from .wallet_service import WalletService
from .taker_utils import direct_send
from jmclient import RegtestBitcoinCoreInterface

"""
For some documentation see:
    https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki
    and an earlier document:
    https://github.com/btcpayserver/btcpayserver-doc/blob/master/Payjoin-spec.md
    and even earlier:
    https://github.com/bitcoin/bips/blob/master/bip-0079.mediawiki
"""
log = get_log()

""" This whitelister allows us to accept any cert for a specific
    domain, and is to be used for testing only; the default Agent
    behaviour of twisted.web.client.Agent for https URIs is
    the correct one in production (i.e. uses local trust store).
"""
@implementer(IPolicyForHTTPS)
class WhitelistContextFactory(object):
    def __init__(self, good_domains=None):
        """
        :param good_domains: List of domains. The URLs must be in bytes
        """
        if not good_domains:
            self.good_domains = []
        else:
            self.good_domains = good_domains
        # by default, handle requests like a browser would
        self.default_policy = BrowserLikePolicyForHTTPS()

    def creatorForNetloc(self, hostname, port):
        # check if the hostname is in the the whitelist,
        # otherwise return the default policy
        if hostname in self.good_domains:
            return CertificateOptions(verify=False)
        return self.default_policy.creatorForNetloc(hostname, port)

class JMPayjoinManager(object):
    """ An encapsulation of state for an
    ongoing Payjoin payment. Allows reporting
    details of the outcome of a Payjoin attempt.
    """

    # enum such that progress can be
    # reported
    JM_PJ_NONE = 0
    JM_PJ_INIT = 1
    JM_PJ_PAYMENT_CREATED = 2
    JM_PJ_PAYMENT_SENT = 3
    JM_PJ_PARTIAL_RECEIVED = 4
    JM_PJ_PARTIAL_REJECTED = 5
    JM_PJ_PAYJOIN_COSIGNED = 6
    JM_PJ_PAYJOIN_BROADCAST = 7
    JM_PJ_PAYJOIN_BROADCAST_FAILED = 8

    pj_state = JM_PJ_NONE

    def __init__(self, wallet_service, mixdepth, destination,
                 amount, server, disable_output_substitution=False,
                 mode="command-line"):
        assert isinstance(wallet_service, WalletService)
        # payjoin is not supported for non-segwit wallets:
        assert isinstance(wallet_service.wallet,
                          (SegwitWallet, SegwitLegacyWallet))
        # our payjoin implementation requires PSBT
        assert isinstance(wallet_service.wallet, PSBTWalletMixin)
        self.wallet_service = wallet_service
        # mixdepth from which payment is sourced
        assert isinstance(mixdepth, int)
        self.mixdepth = mixdepth
        assert isinstance(destination, btc.CCoinAddress)
        self.destination = destination
        assert isinstance(amount, int)
        assert amount > 0
        self.amount = amount
        self.server = server
        self.disable_output_substitution = disable_output_substitution
        self.pj_state = self.JM_PJ_INIT
        self.payment_tx = None
        self.initial_psbt = None
        self.payjoin_psbt = None
        self.final_psbt = None
        # change is initialized as None
        # in case there is no change:
        self.change_out = None
        self.change_out_index = None
        # payment mode is "command-line" for one-shot
        # processing, shutting down on completion.
        self.mode = mode

        # to be able to cancel the timeout fallback broadcast
        # in case of success:
        self.timeout_fallback_dc = None

    def set_payment_tx_and_psbt(self, in_psbt):
        assert isinstance(in_psbt, btc.PartiallySignedTransaction)
        self.initial_psbt = in_psbt
        # any failure here is a coding error, as it is fully
        # under our control.
        assert self.sanity_check_initial_payment()
        self.pj_state = self.JM_PJ_PAYMENT_CREATED

    def sanity_check_initial_payment(self):
        """ These checks are motivated by the checks specified
        for the *receiver* in the btcpayserver implementation doc.
        We want to make sure our payment isn't rejected.
        We also sanity check that the payment details match
        the initialization of this Manager object.
        """
        # failure to extract tx should throw an error;
        # this PSBT must be finalized and sane.
        self.payment_tx = self.initial_psbt.extract_transaction()

        # inputs must all have witness utxo populated
        for inp in self.initial_psbt.inputs:
            if not isinstance(inp.witness_utxo, btc.CTxOut):
                return False

        # check that there is no xpub or derivation info
        if self.initial_psbt.xpubs:
            return False
        for inp in self.initial_psbt.inputs:
            # derivation_map is an OrderedDict, if empty
            # it will be counted as false:
            if inp.derivation_map:
                return False
        for out in self.initial_psbt.outputs:
            if out.derivation_map:
                return False

        # TODO we can replicate the mempool check here for
        # Core versions sufficiently high, also encapsulate
        # it in bc_interface.

        # our logic requires no more than one change output
        # for now:
        found_payment = 0
        assert len(self.payment_tx.vout) in [1, 2]
        for i, out in enumerate(self.payment_tx.vout):
            if out.nValue == self.amount and \
               btc.CCoinAddress.from_scriptPubKey(
                   out.scriptPubKey) == self.destination:
                found_payment += 1
            else:
                # store this for our balance check
                # for receiver proposal
                self.change_out = out
                self.change_out_index = i
        if not found_payment == 1:
            return False

        return True

    def check_receiver_proposal(self, in_pbst, signed_psbt_for_fees):
        """ This is the most security critical part of the
        business logic of the payjoin. We must check in detail
        that what the server proposes does not unfairly take money
        from us, and also conforms to acceptable structure.
        See https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#senders-payjoin-proposal-checklist
        We perform the following checks of the receiver proposal:
         1. Does it contain our inputs, unchanged?
         2. if output substitution was disabled:
              check that the payment output (same scriptPubKey) has
              amount equal to or greater than original tx.
            if output substition is not disabled:
              no check here (all of index, sPK and amount may be altered)
         3. Are the other inputs (if they exist) finalized, and of the correct type?
         4. Is the absolute fee >= fee of original tx?
         5. Check that the feerate of the transaction is not less than our minfeerate
            (after signing - we have the signed version here).
         6. If we have a change output, check that:
            - the change output still exists, exactly once
            - amount subtracted from self.change_out is less than or equal to
              maxadditionalfeecontribution.
            - Check that the MAFC is only going to fee: check difference between
              new fee and old fee is >= MAFC
            We do not need to further check against number of new inputs, since
            we already insisted on only paying for one.
         7. Does it contain no xpub information or derivation information?
         8. Are the sequence numbers unchanged (and all the same) for the inputs?
         9. Is the nLockTime and version unchanged?

        If all the above checks pass we will consider this valid, and cosign.
        Returns:
        (False, "reason for failure")
        (True, None)
        """
        assert isinstance(in_pbst, btc.PartiallySignedTransaction)
        orig_psbt = self.initial_psbt
        assert isinstance(orig_psbt, btc.PartiallySignedTransaction)
        # 1
        ourins = [(i.prevout.hash, i.prevout.n) for i in orig_psbt.unsigned_tx.vin]
        found = [0] * len(ourins)
        receiver_input_indices = []
        for i, inp in enumerate(in_pbst.unsigned_tx.vin):
            for j, inp2 in enumerate(ourins):
                if (inp.prevout.hash, inp.prevout.n) == inp2:
                    found[j] += 1
                else:
                    receiver_input_indices.append(i)

        if any([f != 1 for f in found]):
            return (False, "Receiver proposed PSBT does not contain our inputs.")
        # 2
        if self.disable_output_substitution:
            found_payment = 0
            for out in in_pbst.unsigned_tx.vout:
                if btc.CCoinAddress.from_scriptPubKey(out.scriptPubKey) == \
                   self.destination and out.nValue >= self.amount:
                    found_payment += 1
            if found_payment != 1:
                return (False, "Our payment output not found exactly once or "
                        "with wrong amount.")
        # 3
        for ind in receiver_input_indices:
            # check the input is finalized
            if not self.wallet_service.is_input_finalized(in_pbst.inputs[ind]):
                return (False, "receiver input is not finalized.")
            # check the utxo field of the input and see if the
            # scriptPubKey is of the right type.
            # TODO this can be genericized to arbitrary wallets in future.
            spk = in_pbst.inputs[ind].utxo.scriptPubKey
            if isinstance(self.wallet_service.wallet, SegwitLegacyWallet):
                try:
                    btc.P2SHCoinAddress.from_scriptPubKey(spk)
                except btc.P2SHCoinAddressError:
                    return (False,
                            "Receiver input type does not match ours.")
            elif isinstance(self.wallet_service.wallet, SegwitWallet):
                try:
                    btc.P2WPKHCoinAddress.from_scriptPubKey(spk)
                except btc.P2WPKHCoinAddressError:
                    return (False,
                            "Receiver input type does not match ours.")
            else:
                assert False
        # 4, 5
        # To get the feerate of the psbt proposed, we use the already-signed
        # version (so all witnesses filled in) to calculate its size,
        # then compare that with the fee, and do the same for the
        # pre-existing non-payjoin.
        try:
            proposed_tx_fee = signed_psbt_for_fees.get_fee()
        except ValueError:
            return (False, "receiver proposed tx has negative fee.")
        nonpayjoin_tx_fee = self.initial_psbt.get_fee()
        if proposed_tx_fee < nonpayjoin_tx_fee:
            return (False, "receiver proposed transaction has lower fee.")
        proposed_tx_size = signed_psbt_for_fees.extract_transaction(
            ).get_virtual_size()
        proposed_fee_rate = proposed_tx_fee / float(proposed_tx_size)
        log.debug("proposed fee rate: " + str(proposed_fee_rate))
        if proposed_fee_rate < float(
            jm_single().config.get("PAYJOIN", "min_fee_rate")):
            return (False, "receiver proposed transaction has too low "
                    "feerate: " + str(proposed_fee_rate))
        # 6
        if self.change_out:
            found_change = 0
            for out in in_pbst.unsigned_tx.vout:
                if out.scriptPubKey == self.change_out.scriptPubKey:
                    found_change += 1
                    actual_contribution = self.change_out.nValue - out.nValue
                    if actual_contribution > in_pbst.get_fee(
                        ) - self.initial_psbt.get_fee():
                        return (False, "Our change output is reduced more"
                                " than the fee is bumped.")
                    mafc = get_max_additional_fee_contribution(self)
                    if actual_contribution > mafc:
                        return (False, "Proposed transactions requires "
                                "us to pay more additional fee that we "
                                "agreed to: " + str(mafc) + " sats.")
            # note this check is only if the initial tx had change:
            if found_change != 1:
                return (False, "Our change output was not found "
                        "exactly once.")
        # 7
        if in_pbst.xpubs:
            return (False, "Receiver proposal contains xpub information.")
        # 8
        seqno = self.initial_psbt.unsigned_tx.vin[0].nSequence
        for inp in in_pbst.unsigned_tx.vin:
            if inp.nSequence != seqno:
                return (False, "all sequence numbers are not the same.")
        # 9
        if in_pbst.unsigned_tx.nLockTime != \
           self.initial_psbt.unsigned_tx.nLockTime:
            return (False, "receiver proposal has altered nLockTime.")
        if in_pbst.unsigned_tx.nVersion != \
           self.initial_psbt.unsigned_tx.nVersion:
            return (False, "receiver proposal has altered nVersion.")
        # all checks passed
        return (True, None)

    def set_payjoin_psbt(self, in_psbt, signed_psbt_for_fees):
        """ This is the PSBT as initially proposed
        by the receiver, so we keep a copy of it in that
        state. This must be a copy as the sig_psbt function
        will update the mutable psbt it is given.
        This must not be called until the psbt has passed
        all sanity and validation checks.
        """
        assert isinstance(in_psbt, btc.PartiallySignedTransaction)
        assert isinstance(signed_psbt_for_fees, btc.PartiallySignedTransaction)
        success, msg = self.check_receiver_proposal(in_psbt,
                                                    signed_psbt_for_fees)
        if not success:
            return (success, msg)
        self.payjoin_psbt = in_psbt
        self.pj_state = self.JM_PJ_PARTIAL_RECEIVED
        return (True, None)

    def set_final_payjoin_psbt(self, in_psbt):
        """ This is the PSBT after we have co-signed
        it. If it is in a sane state, we update our state.
        """
        assert isinstance(in_psbt, btc.PartiallySignedTransaction)
        # note that this is the simplest way to check
        # for finality and validity of PSBT:
        assert in_psbt.extract_transaction()
        self.final_psbt = in_psbt
        self.pj_state = self.JM_PJ_PAYJOIN_COSIGNED

    def set_broadcast(self, success):
        if success:
            self.pj_state = self.JM_PJ_PAYJOIN_BROADCAST
        else:
            self.pj_state = self.JM_PJ_PAYJOIN_BROADCAST_FAILED

    def report(self, jsonified=False, verbose=False):
        """ Returns a dict (optionally jsonified) containing
        the following information (if they are
        available):
        * current status of Payjoin
        * payment transaction (original, non payjoin)
        * payjoin partial (PSBT) sent by receiver
        * final payjoin transaction
        * whether or not the payjoin transaction is
          broadcast and/or confirmed.
        If verbose is True, we include the full deserialization
        of transactions and PSBTs, which is too verbose for GUI
        display.
        """
        reportdict = {"name:", "PAYJOIN STATUS REPORT"}
        reportdict["status"] = self.pj_state # TODO: string
        if self.payment_tx:
            txdata = btc.human_readable_transaction(self.payment_tx)
            if verbose:
                txdata = txdata["hex"]
            reportdict["payment-tx"] = txdata
        if self.payjoin_psbt:
            psbtdata = PSBTWalletMixin.human_readable_psbt(
                self.payjoin_psbt) if verbose else self.payjoin_psbt.to_base64()
            reportdict["payjoin-proposed"] = psbtdata
        if self.final_psbt:
            finaldata = PSBTWalletMixin.human_readable_psbt(
                self.final_psbt) if verbose else self.final_psbt.to_base64()
            reportdict["payjoin-final"] = finaldata
        if jsonified:
            return json.dumps(reportdict, indent=4)
        else:
            return reportdict

def parse_payjoin_setup(bip21_uri, wallet_service, mixdepth, mode="command-line"):
    """ Takes the payment request data from the uri and returns a
    JMPayjoinManager object initialised for that payment.
    """
    assert btc.is_bip21_uri(bip21_uri), "invalid bip21 uri: " + bip21_uri
    decoded = btc.decode_bip21_uri(bip21_uri)

    assert "amount" in decoded
    assert "address" in decoded
    assert "pj" in decoded

    amount = decoded["amount"]
    destaddr = decoded["address"]
    # this will throw for any invalid address:
    destaddr = btc.CCoinAddress(destaddr)
    server = decoded["pj"]
    disable_output_substitution = False
    if "pjos" in decoded and decoded["pjos"] == "0":
        disable_output_substitution = True
    return JMPayjoinManager(wallet_service, mixdepth, destaddr, amount, server,
                        disable_output_substitution=disable_output_substitution,
                        mode=mode)

def get_max_additional_fee_contribution(manager):
    """ See definition of maxadditionalfeecontribution in BIP 78.
    """
    max_additional_fee_contribution = jm_single(
        ).config.get("PAYJOIN", "max_additional_fee_contribution")
    if max_additional_fee_contribution == "default":
        # calculate the fee bumping allowed according to policy:
        if isinstance(manager.wallet_service.wallet, SegwitLegacyWallet):
            vsize = 91
        elif isinstance(manager.wallet_service.wallet, SegwitWallet):
            vsize = 68
        else:
            raise Exception("Payjoin only supported for segwit wallets")
        original_fee_rate = manager.initial_psbt.get_fee()/float(
            manager.initial_psbt.extract_transaction().get_virtual_size())
        log.debug("Initial nonpayjoin transaction feerate is: " + str(original_fee_rate))
        max_additional_fee_contribution = int(original_fee_rate * 1.2 * vsize)
        log.debug("From which we calculated a max additional fee "
                  "contribution of: " + str(max_additional_fee_contribution))
    return max_additional_fee_contribution

def send_payjoin(manager, accept_callback=None,
                 info_callback=None):
    """ Given a JMPayjoinManager object `manager`, initialised with the
    payment request data from the server, use its wallet_service to construct
    a payment transaction, with coins sourced from mixdepth `mixdepth`,
    then wait for the server response, parse the PSBT, perform checks and complete sign.
    The info and accept callbacks are to ask the user to confirm the creation of
    the original payment transaction (None defaults to terminal/CLI processing),
    and are as defined in `taker_utils.direct_send`.

    Returns:
    (True, None) in case of payment setup successful (response will be delivered
     asynchronously) - the `manager` object can be inspected for more detail.
    (False, errormsg) in case of failure.
    """

    # wallet should already be synced before calling here;
    # we can create a standard payment, but have it returned as a PSBT.
    assert isinstance(manager, JMPayjoinManager)
    assert manager.wallet_service.synced
    payment_psbt = direct_send(manager.wallet_service, manager.amount, manager.mixdepth,
                             str(manager.destination), accept_callback=accept_callback,
                             info_callback=info_callback,
                             with_final_psbt=True)
    if not payment_psbt:
        return (False, "could not create non-payjoin payment")

    # TLS whitelist is for regtest testing, it is treated as hostnames for
    # which tls certificate verification is ignored.
    tls_whitelist = None
    if isinstance(jm_single().bc_interface, RegtestBitcoinCoreInterface):
        tls_whitelist = [b"127.0.0.1"]

    manager.set_payment_tx_and_psbt(payment_psbt)

    # add delayed call to broadcast this after 1 minute
    manager.timeout_fallback_dc = reactor.callLater(60, fallback_nonpayjoin_broadcast,
                                                    manager, b"timeout")

    # Now we send the request to the server, with the encoded
    # payment PSBT

    # First we create a twisted web Agent object:

    # TODO genericize/move out/use library function:
    def is_hs_uri(s):
        x = urlparse.urlparse(s)
        if x.hostname.endswith(".onion"):
            return (x.scheme, x.hostname, x.port)
        return False

    tor_url_data = is_hs_uri(manager.server)
    if tor_url_data:
        # note the return value is currently unused here
        socks5_host = jm_single().config.get("PAYJOIN", "onion_socks5_host")
        socks5_port = int(jm_single().config.get("PAYJOIN", "onion_socks5_port"))
        # note: SSL not supported at the moment:
        torEndpoint = TCP4ClientEndpoint(reactor, socks5_host, socks5_port)
        agent = tor_agent(reactor, torEndpoint)
    else:
        if not tls_whitelist:
            agent = Agent(reactor)
        else:
            agent = Agent(reactor,
                contextFactory=WhitelistContextFactory(tls_whitelist))

    body = BytesProducer(payment_psbt.to_base64().encode("utf-8"))

    #Set the query parameters for the request:

    # construct the URI from the given parameters
    pj_version = jm_single().config.getint("PAYJOIN",
                                        "payjoin_version")
    params = {"v": pj_version}

    disable_output_substitution = "false"
    if manager.disable_output_substitution:
        disable_output_substitution = "true"
    else:
        if jm_single().config.getint("PAYJOIN",
                            "disable_output_substitution") == 1:
            disable_output_substitution = "true"
    params["disableoutputsubstitution"] = disable_output_substitution

    # to determine the additionalfeeoutputindex in cases where we have
    # change and we are allowing fee bump, we examine the initial tx:
    if manager.change_out:
        params["additionalfeeoutputindex"] = manager.change_out_index
        params["maxadditionalfeecontribution"] = \
            get_max_additional_fee_contribution(manager)

    min_fee_rate = float(jm_single().config.get("PAYJOIN", "min_fee_rate"))
    params["minfeerate"] = min_fee_rate

    destination_url = manager.server.encode("utf-8")
    url_parts = list(urlparse.urlparse(destination_url))
    url_parts[4] = urlencode(params).encode("utf-8")
    destination_url = urlparse.urlunparse(url_parts)
    # TODO what to use as user agent?
    d = agent.request(b"POST", destination_url,
        Headers({"User-Agent": ["Twisted Web Client Example"],
                "Content-Type": ["text/plain"]}),
        bodyProducer=body)

    d.addCallback(receive_payjoin_proposal_from_server, manager)
    # note that the errback (here "noResponse") is *not* triggered
    # by a server rejection (which is accompanied by a non-200
    # status code returned), but by failure to communicate.
    def noResponse(failure):
        failure.trap(ResponseFailed, ConnectionRefusedError, HostUnreachableError)
        log.error(failure.value)
        fallback_nonpayjoin_broadcast(manager, b"connection refused")
    d.addErrback(noResponse)
    return (True, None)

def fallback_nonpayjoin_broadcast(manager, err):
    """ Sends the non-coinjoin payment onto the network,
    assuming that the payjoin failed. The reason for failure is
    `err` and will usually be communicated by the server, and must
    be a bytestring.
    Note that the reactor is shutdown after sending the payment (one-shot
    processing).
    """
    assert isinstance(manager, JMPayjoinManager)
    def quit():
        if manager.mode == "command-line" and reactor.running:
            for dc in reactor.getDelayedCalls():
                dc.cancel()
            reactor.stop()
    log.warn("Payjoin did not succeed, falling back to non-payjoin payment.")
    log.warn("Error message was: " + err.decode("utf-8"))
    original_tx = manager.initial_psbt.extract_transaction()
    if not jm_single().bc_interface.pushtx(original_tx.serialize()):
        log.error("Unable to broadcast original payment. The payment is NOT made.")
        quit()
        return
    log.info("We paid without coinjoin. Transaction: ")
    log.info(btc.human_readable_transaction(original_tx))
    quit()

def receive_payjoin_proposal_from_server(response, manager):
    assert isinstance(manager, JMPayjoinManager)
    # if the response code is not 200 OK, we must assume payjoin
    # attempt has failed, and revert to standard payment.
    if int(response.code) != 200:
        fallback_nonpayjoin_broadcast(manager, err=response.phrase)
        return
    # for debugging; will be removed in future:
    log.debug("Response headers:")
    log.debug(pformat(list(response.headers.getAllRawHeaders())))
    # no attempt at chunking or handling incrementally is needed
    # here. The body should be a byte string containing the
    # new PSBT.
    d = readBody(response)
    d.addCallback(process_payjoin_proposal_from_server, manager)

def process_payjoin_proposal_from_server(response_body, manager):
    assert isinstance(manager, JMPayjoinManager)
    try:
        payjoin_proposal_psbt = \
            btc.PartiallySignedTransaction.from_base64(response_body)
    except Exception as e:
        log.error("Payjoin tx from server could not be parsed: " + repr(e))
        fallback_nonpayjoin_broadcast(manager, err=b"Server sent invalid psbt")
        return

    log.debug("Receiver sent us this PSBT: ")
    log.debug(manager.wallet_service.human_readable_psbt(payjoin_proposal_psbt))
    # we need to add back in our utxo information to the received psbt,
    # since the servers remove it (not sure why?)
    for i, inp in enumerate(payjoin_proposal_psbt.unsigned_tx.vin):
        for j, inp2 in enumerate(manager.initial_psbt.unsigned_tx.vin):
                    if (inp.prevout.hash, inp.prevout.n) == (
                        inp2.prevout.hash, inp2.prevout.n):
                        payjoin_proposal_psbt.set_utxo(
                            manager.initial_psbt.inputs[j].utxo, i)
    signresultandpsbt, err = manager.wallet_service.sign_psbt(
        payjoin_proposal_psbt.serialize(), with_sign_result=True)
    if err:
        log.error("Failed to sign PSBT from the receiver, error: " + err)
        fallback_nonpayjoin_broadcast(manager, err=b"Failed to sign receiver PSBT")
        return

    signresult, sender_signed_psbt = signresultandpsbt
    assert signresult.is_final
    success, msg = manager.set_payjoin_psbt(payjoin_proposal_psbt, sender_signed_psbt)
    if not success:
        log.error(msg)
        fallback_nonpayjoin_broadcast(manager, err=b"Receiver PSBT checks failed.")
        return
    # All checks have passed. We can use the already signed transaction in
    # sender_signed_psbt.
    log.info("Our final signed PSBT is:\n{}".format(
        manager.wallet_service.human_readable_psbt(sender_signed_psbt)))
    manager.set_final_payjoin_psbt(sender_signed_psbt)

    # broadcast the tx
    extracted_tx = sender_signed_psbt.extract_transaction()
    log.info("Here is the final payjoin transaction:")
    log.info(btc.human_readable_transaction(extracted_tx))
    if not jm_single().bc_interface.pushtx(extracted_tx.serialize()):
        log.info("The above transaction failed to broadcast.")
    else:
        log.info("Payjoin transaction broadcast successfully.")
        # if transaction is succesfully broadcast, remove the
        # timeout fallback to avoid confusing error messages:
        manager.timeout_fallback_dc.cancel()
    if manager.mode == "command-line" and reactor.running:
        reactor.stop()
