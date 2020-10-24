from zope.interface import implementer
from twisted.internet import reactor, task
from twisted.web.http import UNAUTHORIZED, BAD_REQUEST, NOT_FOUND
from twisted.web.client import (Agent, readBody, ResponseFailed,
                                BrowserLikePolicyForHTTPS)
from twisted.web.server import Site
from twisted.web.resource import Resource, ErrorPage
from twisted.web.iweb import IPolicyForHTTPS
from twisted.internet.ssl import CertificateOptions
from twisted.internet.error import ConnectionRefusedError, ConnectionLost
from twisted.internet.endpoints import TCP4ClientEndpoint, UNIXClientEndpoint
from twisted.web.http_headers import Headers
import txtorcon
from txtorcon.web import tor_agent
from txtorcon.socks import HostUnreachableError
import urllib.parse as urlparse
from urllib.parse import urlencode
import json
import random
from io import BytesIO
from pprint import pformat
from jmbase import BytesProducer, bintohex, jmprint
from .configure import get_log, jm_single
import jmbitcoin as btc
from .wallet import PSBTWalletMixin, SegwitLegacyWallet, SegwitWallet, estimate_tx_fee
from .wallet_service import WalletService
from .taker_utils import direct_send
from jmclient import RegtestBitcoinCoreInterface, select_one_utxo, process_shutdown

"""
For some documentation see:
    https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki
    and an earlier document:
    https://github.com/btcpayserver/btcpayserver-doc/blob/master/Payjoin-spec.md
    and even earlier:
    https://github.com/bitcoin/bips/blob/master/bip-0079.mediawiki
"""
log = get_log()

# Recommended sizes for input vsize as per BIP78
# (stored here since BIP78 specific; could be moved to jmbitcoin)
INPUT_VSIZE_LEGACY = 148
INPUT_VSIZE_SEGWIT_LEGACY = 91
INPUT_VSIZE_SEGWIT_NATIVE = 68

# txtorcon outputs erroneous warnings about hiddenservice directory strings,
# annoyingly, so we suppress it here:
import warnings
warnings.filterwarnings("ignore")

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
                 amount, server=None, disable_output_substitution=False,
                 mode="command-line", user_info_callback=None):
        assert isinstance(wallet_service, WalletService)
        # payjoin is not supported for non-segwit wallets:
        assert isinstance(wallet_service.wallet,
                          (SegwitWallet, SegwitLegacyWallet))
        # our payjoin implementation requires PSBT
        assert isinstance(wallet_service.wallet, PSBTWalletMixin)
        self.wallet_service = wallet_service
        # for convenience define wallet type here:
        if isinstance(self.wallet_service.wallet, SegwitLegacyWallet):
            self.wallet_type = "sw-legacy"
        elif isinstance(self.wallet_service.wallet, SegwitWallet):
            self.wallet_type = "sw"
        else:
            assert False
        # mixdepth from which payment is sourced
        assert isinstance(mixdepth, int)
        self.mixdepth = mixdepth
        assert isinstance(destination, btc.CCoinAddress)
        self.destination = destination
        assert isinstance(amount, int)
        assert amount > 0
        self.amount = amount
        if server is None:
            self.server = None
            self.role = "receiver"
        else:
            self.role = "sender"
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

        # fix the sequence number if the sender uses only one
        # (otherwise the receiver is free to do anything):
        self.fixed_sequence_number = None

        # to be able to cancel the timeout fallback broadcast
        # in case of success:
        self.timeout_fallback_dc = None

        # set callback for conveying info to user (takes one string arg):
        if not user_info_callback:
            self.user_info_callback = self.default_user_info_callback
        else:
            self.user_info_callback = user_info_callback

    def default_user_info_callback(self, msg):
        """ Info level message print to command line.
        """
        jmprint(msg)

    def set_payment_tx_and_psbt(self, in_psbt):
        assert isinstance(in_psbt, btc.PartiallySignedTransaction), "invalid PSBT input to JMPayjoinManager."
        self.initial_psbt = in_psbt

        success, msg = self.sanity_check_initial_payment()
        if not success:
            log.error(msg)
            assert False, msg
        self.pj_state = self.JM_PJ_PAYMENT_CREATED

    def get_payment_psbt_feerate(self):
        return self.initial_psbt.get_fee()/float(
            self.initial_psbt.extract_transaction().get_virtual_size())

    def get_vsize_for_input(self):
        if isinstance(self.wallet_service.wallet, SegwitLegacyWallet):
            vsize = INPUT_VSIZE_SEGWIT_LEGACY
        elif isinstance(self.wallet_service.wallet, SegwitWallet):
            vsize = INPUT_VSIZE_SEGWIT_NATIVE
        else:
            raise Exception("Payjoin only supported for segwit wallets")
        return vsize

    def sanity_check_initial_payment(self):
        """ These checks are those specified
        for the *receiver* in BIP78.
        However, for the sender, we want to make sure our
        payment isn't rejected. So this is not receiver-only.
        We also sanity check that the payment details match
        the initialization of this Manager object.
        Returns:
        (False, reason)
        or
        (True, None)
        """

        # failure to extract tx should throw an error;
        # this PSBT must be finalized and sane.
        self.payment_tx = self.initial_psbt.extract_transaction()
        # inputs must all have witness utxo populated
        for inp in self.initial_psbt.inputs:
            if not isinstance(inp.witness_utxo, btc.CTxOut):
                return (False, "Input utxo was not witness type.")
            # see third bullet point of:
            # https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#receivers-original-psbt-checklist
            #
            # Check that all inputs have same scriptPubKey type,
            # and that it is the same as our wallet (for sender
            # code in JM this is a no-op, for receiver, we can
            # only support payjoins fitting our wallet type, since
            # we do not use multi-wallet or output substitution:
            input_type = self.wallet_service.check_finalized_input_type(inp)
            if input_type != self.wallet_type:
                return (False, "an input was not of the same script type.")

        # check that there is no xpub or derivation info
        if self.initial_psbt.xpubs:
            return (False, "Unexpected xpubs found in PSBT.")
        for inp in self.initial_psbt.inputs:
            # derivation_map is an OrderedDict, if empty
            # it will be counted as false:
            if inp.derivation_map:
                return (False, "Unexpected derivation found in PSBT.")
        for out in self.initial_psbt.outputs:
            if out.derivation_map:
                return (False, "Unexpected derivation found in PSBT.")

        # our logic requires no more than one change output
        # for now:
        found_payment = 0
        assert len(self.payment_tx.vout) in [1, 2]
        for i, out in enumerate(self.payment_tx.vout):
            if out.nValue == self.amount and \
               btc.CCoinAddress.from_scriptPubKey(
                   out.scriptPubKey) == self.destination:
                found_payment += 1
                self.pay_out = out
                self.pay_out_index = i
            else:
                # store this for our balance check
                # for receiver proposal
                self.change_out = out
                self.change_out_index = i
        if not found_payment == 1:
            return (False, "The payment output was not found.")

        # if the sequence numbers chosen are uniform, record this:
        seqnums = [x.nSequence for x in self.payment_tx.vin]
        if seqnums.count(seqnums[0]) == len(seqnums):
            self.fixed_sequence_number = seqnums[0]

        return (True, None)

    def check_receiver_proposal(self, in_psbt, signed_psbt_for_fees):
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
        assert isinstance(in_psbt, btc.PartiallySignedTransaction)
        orig_psbt = self.initial_psbt
        assert isinstance(orig_psbt, btc.PartiallySignedTransaction)
        # 1
        ourins = [(i.prevout.hash, i.prevout.n) for i in orig_psbt.unsigned_tx.vin]
        found = [0] * len(ourins)
        receiver_input_indices = []
        for i, inp in enumerate(in_psbt.unsigned_tx.vin):
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
            for out in in_psbt.unsigned_tx.vout:
                if btc.CCoinAddress.from_scriptPubKey(out.scriptPubKey) == \
                   self.destination and out.nValue >= self.amount:
                    found_payment += 1
            if found_payment != 1:
                return (False, "Our payment output not found exactly once or "
                        "with wrong amount.")
        # 3
        for ind in receiver_input_indices:
            # check the input is finalized
            if not self.wallet_service.is_input_finalized(in_psbt.inputs[ind]):
                return (False, "receiver input is not finalized.")
            # check the utxo field of the input and see if the
            # scriptPubKey is of the right type.
            # TODO this can be genericized to arbitrary wallets in future.
            input_type = self.wallet_service.check_finalized_input_type(
                in_psbt.inputs[ind])
            if input_type != self.wallet_type:
                return (False, "receiver input does not match our script type.")
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
            for out in in_psbt.unsigned_tx.vout:
                if out.scriptPubKey == self.change_out.scriptPubKey:
                    found_change += 1
                    actual_contribution = self.change_out.nValue - out.nValue
                    if actual_contribution > in_psbt.get_fee(
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
        if in_psbt.xpubs:
            return (False, "Receiver proposal contains xpub information.")
        # 8
        seqno = self.initial_psbt.unsigned_tx.vin[0].nSequence
        for inp in in_psbt.unsigned_tx.vin:
            if inp.nSequence != seqno:
                return (False, "all sequence numbers are not the same.")
        # 9
        if in_psbt.unsigned_tx.nLockTime != \
           self.initial_psbt.unsigned_tx.nLockTime:
            return (False, "receiver proposal has altered nLockTime.")
        if in_psbt.unsigned_tx.nVersion != \
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

    def select_receiver_utxos(self):
        # Rceiver chooses own inputs:
        # For earlier ideas about more complex algorithms, see the gist comment here:
        # https://gist.github.com/AdamISZ/4551b947789d3216bacfcb7af25e029e#gistcomment-2799709
        # and also see the code in P2EPMaker in earlier versions of Joinmarket.
        #
        # For now, it is considered too complex to accurately judge the implications
        # of the UIH1/2 heuristic violations, in particular because selecting more than
        # one input has impact on fees which is undesirable and tricky to deal with.
        # So here we ONLY choose one utxo at random.

        # Returns:
        # list of utxos (currently always of length 1)
        # or
        # False if coins cannot be selected

        self.user_info_callback("Choosing one coin at random")
        try:
            my_utxos = self.wallet_service.select_utxos(
                self.mixdepth, jm_single().DUST_THRESHOLD,
                select_fn=select_one_utxo)
        except Exception as e:
            log.error("Failed to select coins, exception: " + repr(e))
            return False
        my_total_in = sum([va['value'] for va in my_utxos.values()])
        self.user_info_callback("We selected inputs worth: " + str(my_total_in))
        return my_utxos

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
    return JMPayjoinManager(wallet_service, mixdepth, destaddr, amount, server=server,
                        disable_output_substitution=disable_output_substitution,
                        mode=mode)

def get_max_additional_fee_contribution(manager):
    """ See definition of maxadditionalfeecontribution in BIP 78.
    """
    max_additional_fee_contribution = jm_single(
        ).config.get("PAYJOIN", "max_additional_fee_contribution")
    if max_additional_fee_contribution == "default":
        vsize = manager.get_vsize_for_input()
        original_fee_rate = manager.get_payment_psbt_feerate()
        log.debug("Initial nonpayjoin transaction feerate is: " + str(original_fee_rate))
        # Factor slightly higher than 1 is to allow some breathing room for
        # receiver. NB: This may not be appropriate for sender wallets that
        # use rounded fee rates, but Joinmarket does not.
        max_additional_fee_contribution = int(original_fee_rate * 1.2 * vsize)
        log.debug("From which we calculated a max additional fee "
                  "contribution of: " + str(max_additional_fee_contribution))
    return max_additional_fee_contribution

def send_payjoin(manager, accept_callback=None,
                 info_callback=None, return_deferred=False):
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
                             with_final_psbt=True, optin_rbf=True)
    if not payment_psbt:
        return (False, "could not create non-payjoin payment")

    # TLS whitelist is for regtest testing, it is treated as hostnames for
    # which tls certificate verification is ignored.
    tls_whitelist = None
    if isinstance(jm_single().bc_interface, RegtestBitcoinCoreInterface):
        tls_whitelist = [b"127.0.0.1"]

    manager.set_payment_tx_and_psbt(payment_psbt)

    # add delayed call to broadcast this after 1 minute
    manager.timeout_fallback_dc = reactor.callLater(60,
                                        fallback_nonpayjoin_broadcast,
                                        b"timeout", manager)

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
        failure.trap(ResponseFailed, ConnectionRefusedError,
                     HostUnreachableError, ConnectionLost)
        log.error(failure.value)
        fallback_nonpayjoin_broadcast(b"connection failed", manager)
    d.addErrback(noResponse)
    if return_deferred:
        return d
    return (True, None)

def fallback_nonpayjoin_broadcast(err, manager):
    """ Sends the non-coinjoin payment onto the network,
    assuming that the payjoin failed. The reason for failure is
    `err` and will usually be communicated by the server, and must
    be a bytestring.
    Note that the reactor is shutdown after sending the payment (one-shot
    processing) if this is called on the command line.
    """
    assert isinstance(manager, JMPayjoinManager)
    def quit():
        if manager.mode == "command-line" and reactor.running:
            process_shutdown()
    log.warn("Payjoin did not succeed, falling back to non-payjoin payment.")
    log.warn("Error message was: " + err.decode("utf-8"))
    original_tx = manager.initial_psbt.extract_transaction()
    if not jm_single().bc_interface.pushtx(original_tx.serialize()):
        errormsg = ("Unable to broadcast original payment. Check your wallet\n"
        "to see whether original payment was made.")
        log.error(errormsg)
        # ensure any GUI as well as command line sees the message:
        manager.user_info_callback(errormsg)
        quit()
        return
    log.info("Payment made without coinjoin. Transaction: ")
    log.info(btc.human_readable_transaction(original_tx))
    manager.set_broadcast(False)
    if manager.timeout_fallback_dc.active():
        manager.timeout_fallback_dc.cancel()
    quit()

def receive_payjoin_proposal_from_server(response, manager):
    assert isinstance(manager, JMPayjoinManager)
    # no attempt at chunking or handling incrementally is needed
    # here. The body should be a byte string containing the
    # new PSBT, or a jsonified error page.
    d = readBody(response)
    # if the response code is not 200 OK, we must assume payjoin
    # attempt has failed, and revert to standard payment.
    if int(response.code) != 200:
        log.warn("Receiver returned error code: " + str(response.code))
        d.addCallback(fallback_nonpayjoin_broadcast, manager)
        return
    d.addCallback(process_payjoin_proposal_from_server, manager)

def process_payjoin_proposal_from_server(response_body, manager):
    assert isinstance(manager, JMPayjoinManager)
    try:
        payjoin_proposal_psbt = \
            btc.PartiallySignedTransaction.from_base64(response_body)
    except Exception as e:
        log.error("Payjoin tx from server could not be parsed: " + repr(e))
        fallback_nonpayjoin_broadcast(b"Server sent invalid psbt", manager)
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
                            manager.initial_psbt.inputs[j].utxo, i,
                            force_witness_utxo=True)
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
        if manager.timeout_fallback_dc.active():
            manager.timeout_fallback_dc.cancel()
        manager.set_broadcast(True)
    if manager.mode == "command-line" and reactor.running:
        process_shutdown()

""" Receiver-specific code
"""

class PayjoinServer(Resource):
    def __init__(self, wallet_service, mixdepth, destination, amount,
                 shutdown_callback, info_callback , mode="command-line",
                 pj_version = 1):
        self.pj_version = pj_version
        self.wallet_service = wallet_service
        # a callback with no arguments and no return value,
        # to take whatever actions are needed when the payment has
        # been received:
        self.shutdown_callback = shutdown_callback
        self.info_callback = info_callback
        self.manager = JMPayjoinManager(self.wallet_service, mixdepth,
                                        destination, amount, mode=mode,
                                        user_info_callback=self.info_callback)
        super().__init__()

    isLeaf = True

    def bip78_error(self, request, error_meaning,
                    error_code="unavailable", http_code=400):
        """
        See https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#receivers-well-known-errors

        We return, to the sender, stringified json in the body as per the above.
        In case the error code is "original-psbt-rejected", we do not have
        any valid payment to broadcast, so we shut down with "not paid".
        for other cases, we schedule the fallback for 60s from now.
        """

        request.setResponseCode(http_code)
        request.setHeader(b"content-type", b"text/html; charset=utf-8")
        log.debug("Returning an error: " + str(
            error_code) + ": " + str(error_meaning))
        if error_code in ["original-psbt-rejected", "version-unsupported"]:
            # if there is a negotiation failure in the first step, we cannot
            # know whether the sender client sent a valid non-payjoin or not,
            # hence the warning below is somewhat ambiguous:
            log.warn("Negotiation failure. Payment has not yet been made,"
                     " check wallet.")
            # shutdown now but wait until response is sent.
            task.deferLater(reactor, 2.0, self.end_failure)
        else:
            reactor.callLater(60.0, fallback_nonpayjoin_broadcast,
                              error_meaning.encode("utf-8"), self.manager)
        return json.dumps({"errorCode": error_code,
                           "message": error_meaning}).encode("utf-8")

    def render_GET(self, request):
        # can be used e.g. to check if an ephemeral HS is up
        # on Tor Browser:
        return "<html>Only for testing.</html>".encode("utf-8")

    def render_POST(self, request):
        """ The sender will use POST to send the initial
        payment transaction.
        """
        log.debug("The server got this POST request: ")
        # unfortunately the twisted Request object is not
        # easily serialized:
        log.debug(request)
        log.debug(request.method)
        log.debug(request.uri)
        log.debug(request.args)
        sender_parameters = request.args
        log.debug(request.path)
        # defer logging of raw request content:
        proposed_tx = request.content

        # we only support version 1; reject others:
        if not self.pj_version == int(sender_parameters[b'v'][0]):
            return self.bip78_error(request,
                "This version of payjoin is not supported. ",
                "version-unsupported")
        if not isinstance(proposed_tx, BytesIO):
            return self.bip78_error(request, "invalid psbt format",
                                    "original-psbt-rejected")
        payment_psbt_base64 = proposed_tx.read()
        log.debug("request content: " + bintohex(payment_psbt_base64))
        try:
            payment_psbt = btc.PartiallySignedTransaction.from_base64(
            payment_psbt_base64)
        except:
            return self.bip78_error(request,
                                    "invalid psbt format",
                                    "original-psbt-rejected")

        try:
            self.manager.set_payment_tx_and_psbt(payment_psbt)
        except Exception:
            # note that Assert errors, Value errors and CheckTransaction errors
            # are all possible, so we catch all exceptions to avoid a crash.
            return self.bip78_error(request,
                                    "Proposed initial PSBT does not pass sanity checks.",
                                    "original-psbt-rejected")

        # if the sender set the additionalfeeoutputindex and maxadditionalfeecontribution
        # settings, pass them to the PayJoin manager:
        try:
            if b"additionalfeeoutputindex" in sender_parameters:
                afoi = int(sender_parameters[b"additionalfeeoutputindex"][0])
            else:
                afoi = None
            if b"maxadditionalfeecontribution" in sender_parameters:
                mafc = int(sender_parameters[b"maxadditionalfeecontribution"][0])
            else:
                mafc = None
            if b"minfeerate" in sender_parameters:
                minfeerate = float(sender_parameters[b"minfeerate"][0])
            else:
                minfeerate = None
        except Exception as e:
            return self.bip78_error(request, "Invalid request parameters.",
                              "original-psbt-rejected")

        # if sender chose a fee output it must be the change output,
        # and the mafc will be applied to that. Any more complex transaction
        # structure is not supported.
        # If they did not choose a fee output index, we must rely on the feerate
        # reduction being not too much, which is checked against minfeerate; if
        # it is too big a reduction, again we fail payjoin.
        if (afoi is not None and mafc is None) or (mafc is not None and afoi is None):
            return self.bip78_error(request, "Invalid request parameters.",
                              "original-psbt-rejected")

        if afoi and not (self.manager.change_out_index == afoi):
            return self.bip78_error(request, "additionalfeeoutputindex is "
                                    "not the change output. Joinmarket does "
                                    "not currently support this.",
                                    "original-psbt-rejected")

        # while we do not need to defend against probing attacks,
        # it is still safer to at least verify the validity of the signatures
        # at this stage, to ensure no misbehaviour with using inputs
        # that are not signed correctly:
        res = jm_single().bc_interface.rpc('testmempoolaccept', [[bintohex(
            self.manager.payment_tx.serialize())]])
        if not res[0]["allowed"]:
            return self.bip78_error(request, "Proposed transaction was "
                                    "rejected from mempool.",
                                    "original-psbt-rejected")

        # Now that the PSBT is accepted, we schedule fallback in case anything
        # fails later on in negotiation (as specified in BIP78):
        self.manager.timeout_fallback_dc = reactor.callLater(60,
                                                fallback_nonpayjoin_broadcast,
                                                b"timeout", self.manager)

        receiver_utxos = self.manager.select_receiver_utxos()
        if not receiver_utxos:
            return self.bip78_error(request,
                                    "Could not select coins for payjoin",
                                    "unavailable")

        # construct unsigned tx for payjoin-psbt:
        payjoin_tx_inputs = [(x.prevout.hash[::-1],
                    x.prevout.n) for x in payment_psbt.unsigned_tx.vin]
        payjoin_tx_inputs.extend(receiver_utxos.keys())
        pay_out = {"value": self.manager.pay_out.nValue,
                   "address": str(btc.CCoinAddress.from_scriptPubKey(
                       self.manager.pay_out.scriptPubKey))}
        if self.manager.change_out:
            change_out = {"value": self.manager.change_out.nValue,
                          "address": str(btc.CCoinAddress.from_scriptPubKey(
                              self.manager.change_out.scriptPubKey))}

        # we now know there were one/two outputs and know which is payment.
        # set the ordering of the outputs correctly.
        if change_out:
            # indices of original payment were set in JMPayjoinManager
            # sanity check:
            if self.manager.change_out_index == 0 and \
               self.manager.pay_out_index == 1:
                outs = [change_out, pay_out]
            elif self.manager.change_out_index == 1 and \
                 self.manager.pay_out_index == 0:
                outs = [pay_out, change_out]
            else:
                assert False, "More than 2 outputs is not supported."
        else:
            outs = [pay_out]
        # bump payment output with our input:
        our_inputs_val = sum([v["value"] for _, v in receiver_utxos.items()])
        pay_out["value"] += our_inputs_val
        log.debug("We bumped the payment output value by: " + str(
            our_inputs_val) + " sats.")
        log.debug("It is now: " + str(pay_out["value"]) + " sats.")

        # if the sender allowed a fee bump, we can apply it to the change output
        # now (we already checked it's the right index).
        # A note about checking `minfeerate`: it is impossible for the receiver
        # to be 100% certain on the size of the final transaction, since he does
        # not see in advance the (slightly) variable sizes of the sender's final
        # signatures; hence we do not attempt more than an estimate of the final
        # signed transaction's size and hence feerate. Very small inaccuracies
        # (< 1% typically) are possible, therefore.
        #
        # First, let's check that the user's requested minfeerate is not higher
        # than the feerate they already chose:
        if minfeerate and minfeerate > self.manager.get_payment_psbt_feerate():
            return self.bip78_error(request, "Bad request: minfeerate "
                                    "bigger than original psbt feerate.",
                                    "original-psbt-rejected")
        # set the intended virtual size of our input:
        vsize = self.manager.get_vsize_for_input()
        our_fee_bump = 0
        if afoi:
            # We plan to reduce the change_out by a fee contribution.
            # Calculate the additional fee we think we need for our input,
            # to keep the same feerate as the original transaction (this also
            # accounts for rounding as per the BIP).
            # If it is more than mafc, then bump by mafc, else bump by the
            # calculated amount.
            # This should not meaningfully change the feerate.
            our_fee_bump = int(
                self.manager.get_payment_psbt_feerate() * vsize)
            if our_fee_bump > mafc:
                our_fee_bump = mafc

        elif minfeerate:
            # In this case the change_out will remain unchanged.
            # the user has not allowed a fee bump; calculate the new fee
            # rate; if it is lower than the limit, give up.
            expected_new_tx_size = self.manager.initial_psbt.extract_transaction(
                ).get_virtual_size() + vsize
            expected_new_fee_rate = self.manager.initial_psbt.get_fee()/(
                expected_new_tx_size + vsize)
            if expected_new_fee_rate < minfeerate:
                return self.bip78_error(request, "Bad request: we cannot "
                                        "achieve minfeerate requested.",
                                        "original-psbt-rejected")

        # Having checked the sender's conditions, we can apply the fee bump
        # intended:
        outs[self.manager.change_out_index]["value"] -= our_fee_bump

        # TODO this only works for 2 input transactions, otherwise
        # reversal [::-1] will not be valid as per BIP78 ordering requirement.
        # (For outputs, we do nothing since we aren't batching in other payments).
        if random.random() < 0.5:
            payjoin_tx_inputs = payjoin_tx_inputs[::-1]
        unsigned_payjoin_tx = btc.mktx(payjoin_tx_inputs, outs,
                                    version=payment_psbt.unsigned_tx.nVersion,
                                    locktime=payment_psbt.unsigned_tx.nLockTime)

        # to create the PSBT we need the spent_outs for each input,
        # in the right order:
        spent_outs = []
        for i, inp in enumerate(unsigned_payjoin_tx.vin):
            input_found = False
            for j, inp2 in enumerate(payment_psbt.unsigned_tx.vin):
                if inp.prevout == inp2.prevout:
                    # this belongs to sender.
                    # respect sender's sequence number choice, even
                    # if they were not uniform:
                    inp.nSequence = inp2.nSequence
                    spent_outs.append(payment_psbt.inputs[j].utxo)
                    input_found = True
                    sender_index = i
                    break
            if input_found:
                continue
            # if we got here this input is ours, we must find
            # it from our original utxo choice list:
            for ru in receiver_utxos.keys():
                if (inp.prevout.hash[::-1], inp.prevout.n) == ru:
                    spent_outs.append(
                        self.wallet_service.witness_utxos_to_psbt_utxos(
                            {ru: receiver_utxos[ru]})[0])
                    input_found = True
                    break
            # there should be no other inputs:
            assert input_found

        # respect the sender's fixed sequence number, if it was used (we checked
        # in the initial sanity check)
        # TODO consider RBF if we implement it in Joinmarket payments.
        if self.manager.fixed_sequence_number:
            for inp in unsigned_payjoin_tx.vin:
                inp.nSequence = self.manager.fixed_sequence_number

        log.debug("We created this unsigned tx: ")
        log.debug(btc.human_readable_transaction(unsigned_payjoin_tx))

        r_payjoin_psbt = self.wallet_service.create_psbt_from_tx(unsigned_payjoin_tx,
                                                      spent_outs=spent_outs)
        log.debug("Receiver created payjoin PSBT:\n{}".format(
            self.wallet_service.human_readable_psbt(r_payjoin_psbt)))

        signresultandpsbt, err = self.wallet_service.sign_psbt(r_payjoin_psbt.serialize(),
                                                    with_sign_result=True)
        assert not err, err
        signresult, receiver_signed_psbt = signresultandpsbt
        assert signresult.num_inputs_final == len(receiver_utxos)
        assert not signresult.is_final

        # with signing succcessful, remove the utxo field from the
        # counterparty's input (this is required by BIP78). Note we don't
        # do this on PSBT creation as the psbt signing code throws ValueError
        # unless utxos are present.
        receiver_signed_psbt.inputs[sender_index] = btc.PSBT_Input(index=sender_index)
        log.debug("Receiver signing successful. Payjoin PSBT is now:\n{}".format(
            self.wallet_service.human_readable_psbt(receiver_signed_psbt)))
        # construct txoutset for the wallet service callback; we cannot use
        # txid as we don't have all signatures.
        txinfo = tuple((
            x.scriptPubKey, x.nValue) for x in receiver_signed_psbt.unsigned_tx.vout)
        self.wallet_service.register_callbacks([self.end_receipt],
            txinfo =txinfo,
            cb_type="unconfirmed")
        content = receiver_signed_psbt.to_base64()
        request.setHeader(b"content-length", ("%d" % len(content)).encode("ascii"))
        return content.encode("ascii")

    def end_receipt(self, txd, txid):
        if self.manager.mode == "gui":
            self.info_callback("Transaction seen on network, "
                               "view wallet tab for update.:FINAL")
        else:
            self.info_callback("Transaction seen on network: " + txid)
        # do end processing of calling object (e.g. Tor disconnect)
        self.shutdown_callback()
        # informs the wallet service transaction monitor
        # that the transaction has been processed:
        return True

    def end_failure(self):
        shutdown_msg = "Shutting down, payjoin negotiation failed."
        if self.manager.mode == "gui":
            shutdown_msg += "\nCheck wallet tab for payment."
            shutdown_msg += ":FINAL"
        self.info_callback(shutdown_msg)
        self.shutdown_callback()

class JMBIP78ReceiverManager(object):
    """ A class to encapsulate receiver construction
    """
    def __init__(self, wallet_service, mixdepth, amount, port,
                 info_callback=None, uri_created_callback=None,
                 shutdown_callback=None,
                 mode="command-line"):
        assert isinstance(wallet_service, WalletService)
        assert isinstance(mixdepth, int)
        assert isinstance(amount, int)
        assert isinstance(port, int)
        assert amount > 0
        assert port in range(65535)
        self.wallet_service = wallet_service
        self.mixdepth = mixdepth
        self.amount = amount
        self.port = port
        # info_callback has signature (str) and returns None
        if info_callback is None:
            self.info_callback = self.default_info_callback
        else:
            self.info_callback = info_callback
        # uri_created_callback is specifically to signal the
        # created BIP21 uri for transfer to sender; made distinct
        # from information messages in case it needs to be
        # handled differently, but defaults to info_callback.
        if uri_created_callback is None:
            self.uri_created_callback = self.info_callback
        else:
            self.uri_created_callback = uri_created_callback
        # This callback used by GUI as a signal that it can
        # signal the user that the dialog is close-able:
        self.shutdown_callback = shutdown_callback
        self.receiving_address = None
        self.mode = mode

    def default_info_callback(self, msg):
        jmprint(msg)

    def get_receiving_address(self):
        # the receiving address is sourced from the 'next' mixdepth
        # to avoid clustering of input and output:
        next_mixdepth = (self.mixdepth + 1) % (
            self.wallet_service.wallet.mixdepth + 1)
        self.receiving_address = btc.CCoinAddress(
            self.wallet_service.get_internal_addr(next_mixdepth))

    def start_pj_server_and_tor(self):
        """ Packages the startup of the receiver side.
        """
        self.get_receiving_address()
        self.pj_server = PayjoinServer(self.wallet_service, self.mixdepth,
                            self.receiving_address, self.amount,
                            self.shutdown, self.info_callback, mode=self.mode)
        self.site = Site(self.pj_server)
        self.site.displayTracebacks = False
        self.info_callback("Attempting to start onion service on port: " + str(
            self.port) + " ...")
        self.start_tor()

    def setup_failed(self, arg):
        errmsg = "Setup failed: " + str(arg)
        log.error(errmsg)
        self.info_callback(errmsg)
        process_shutdown()

    def create_onion_ep(self, t):
        self.tor_connection = t
        return t.create_onion_endpoint(self.port)

    def onion_listen(self, onion_ep):
        return onion_ep.listen(self.site)

    def print_host(self, ep):
        """ Callback fired once the HS is available;
        receiver user needs a BIP21 URI to pass to
        the sender:
        """
        self.info_callback("Your hidden service is available. Please\n"
                           "now pass this URI string to the sender to\n"
                           "effect the payjoin payment:")
        # Note that ep,getHost().onion_port must return the same
        # port as we chose in self.port; if not there is an error.
        assert ep.getHost().onion_port == self.port
        self.uri_created_callback(self.bip21_uri_from_onion_hostname(
            str(ep.getHost().onion_uri)))
        if self.mode == "command-line":
            self.info_callback("Keep this process running until the payment "
                           "is received.")

    def bip21_uri_from_onion_hostname(self, host):
        """ Encoding the BIP21 URI according to BIP78 specifications,
        and specifically only supporting a hidden service endpoint.
        Note: we hardcode http; no support for TLS over HS.
        Second, note we convert the amount-in-sats self.amount
        to BTC denomination as expected by BIP21.
        """
        port_str = ":" + str(self.port) if self.port != 80 else ""
        full_pj_string = "http://" + host + port_str
        bip78_btc_amount = btc.amount_to_btc(btc.amount_to_sat(self.amount))
        # "safe" option is required to encode url in url unmolested:
        return btc.encode_bip21_uri(str(self.receiving_address),
                                {"amount": bip78_btc_amount,
                                 "pj": full_pj_string.encode("utf-8")},
                                safe=":/")

    def start_tor(self):
        """ This function executes the workflow
        of starting the hidden service and returning/
        printing the BIP21 URI:
        """
        control_host = jm_single().config.get("PAYJOIN", "tor_control_host")
        control_port = int(jm_single().config.get("PAYJOIN", "tor_control_port"))
        if str(control_host).startswith('unix:'):
            control_endpoint = UNIXClientEndpoint(reactor, control_host[5:])
        else:
            control_endpoint = TCP4ClientEndpoint(reactor, control_host, control_port)
        d = txtorcon.connect(reactor, control_endpoint)
        d.addCallback(self.create_onion_ep)
        d.addErrback(self.setup_failed)
        # TODO: add errbacks to the next two calls in
        # the chain:
        d.addCallback(self.onion_listen)
        d.addCallback(self.print_host)

    def shutdown(self):
        self.tor_connection.protocol.transport.loseConnection()
        process_shutdown(self.mode)
        self.info_callback("Hidden service shutdown complete")
        if self.shutdown_callback:
            self.shutdown_callback()
