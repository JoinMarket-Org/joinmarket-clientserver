"""
Commands defining client-server (daemon)
messaging protocol (*not* Joinmarket p2p protocol).
Used for AMP asynchronous messages.
"""
from twisted.protocols.amp import Boolean, Command, Integer, Unicode
from .bigstring import BigUnicode

class DaemonNotReady(Exception):
    pass

class JMCommand(Command):
    #a default response type
    response = [(b'accepted', Boolean())]

"""COMMANDS FROM CLIENT TO DAEMON
=================================
"""

"""Messages used by both MAKER and TAKER
"""

class JMInit(JMCommand):
    """Communicates the client's required setup
    configuration.
    Blockchain source is communicated only as a naming
    tag for messagechannels (currently IRC 'realname' field).
    """
    arguments = [(b'bcsource', Unicode()),
                 (b'network', Unicode()),
                 (b'irc_configs', Unicode()),
                 (b'minmakers', Integer()),
                 (b'maker_timeout_sec', Integer())]
    errors = {DaemonNotReady: b'daemon is not ready'}

class JMStartMC(JMCommand):
    """Will restart message channel connections if config
    has changed; otherwise will only change nym/nick on MCs.
    """
    arguments = [(b'nick', Unicode())]

class JMSetup(JMCommand):
    """Communicates which of "MAKER" or "TAKER"
    roles are to be taken by this client; for MAKER
    role, passes initial offers for announcement (for TAKER, this data is "none")
    """
    arguments = [(b'role', Unicode()),
                 (b'initdata', Unicode())]

class JMMsgSignature(JMCommand):
    """A response to a request for a bitcoin signature
    on a message-channel layer message from the daemon
    """
    arguments = [(b'nick', Unicode()),
                 (b'cmd', Unicode()),
                 (b'msg_to_return', Unicode()),
                 (b'hostid', Unicode())]

class JMMsgSignatureVerify(JMCommand):
    """A response to a request to verify the bitcoin signature
    of a message-channel layer message from the daemon
    """
    arguments = [(b'verif_result', Boolean()),
                 (b'nick', Unicode()),
                 (b'fullmsg', Unicode()),
                 (b'hostid', Unicode())]

"""TAKER specific commands
"""

class JMRequestOffers(JMCommand):
    """Get orderbook from daemon
    """
    arguments = []

class JMFill(JMCommand):
    """Fill an offer/order
    """
    arguments = [(b'amount', Integer()),
                 (b'commitment', Unicode()),
                 (b'revelation', Unicode()),
                 (b'filled_offers', Unicode())]

class JMMakeTx(JMCommand):
    """Send a hex encoded raw bitcoin transaction
    to a set of counterparties
    """
    arguments = [(b'nick_list', Unicode()),
                 (b'txhex', Unicode())]

class JMPushTx(JMCommand):
    """Pass a raw hex transaction to a specific
    counterparty (maker) for pushing (anonymity feature in JM)
    """
    arguments = [(b'nick', Unicode()),
                 (b'txhex', Unicode())]

"""MAKER specific commands
"""

class JMAnnounceOffers(JMCommand):
    """Send list (actually dict) of offers
    to the daemon, along with new announcement
    and cancellation lists (deltas).
    """
    arguments = [(b'to_announce', Unicode()),
                 (b'to_cancel', Unicode()),
                 (b'offerlist', Unicode())]

class JMIOAuth(JMCommand):
    """Send contents of !ioauth message after
    verifying Taker's auth message
    """
    arguments = [(b'nick', Unicode()),
                 (b'utxolist', Unicode()),
                 (b'pubkey', Unicode()),
                 (b'cjaddr', Unicode()),
                 (b'changeaddr', Unicode()),
                 (b'pubkeysig', Unicode())]

class JMTXSigs(JMCommand):
    """Send signatures on the bitcoin transaction
    sent by TAKER
    """
    arguments = [(b'nick', Unicode()),
                 (b'sigs', Unicode())]

"""COMMANDS FROM DAEMON TO CLIENT
=================================
"""

class JMInitProto(JMCommand):
    """Pass to the client the messaging protocol parameters
    (which are defined in daemon package), required to construct
    the user nick, given the bitcoin private key used for authentication
    (that key being controlled by the client; the daemon knows nothing
    about bitcoin).
    """
    arguments = [(b'nick_hash_length', Integer()),
                 (b'nick_max_encoded', Integer()),
                 (b'joinmarket_nick_header', Unicode()),
                 (b'joinmarket_version', Integer())]

class JMUp(JMCommand):
    """Used to signal readiness of message channels to client.
    """
    arguments = []

class JMSetupDone(JMCommand):
    """Used to signal that initial setup action
    has been taken (e.g. !orderbook call).
    """
    arguments = []

class JMRequestMsgSig(JMCommand):
    """Request the client to sign a message-channel
    layer message with the bitcoin key for the nick
    """
    arguments = [(b'nick', Unicode()),
                 (b'cmd', Unicode()),
                 (b'msg', Unicode()),
                 (b'msg_to_be_signed', Unicode()),
                 (b'hostid', Unicode())]

class JMRequestMsgSigVerify(JMCommand):
    """Request the client to verify a counterparty's
    message-channel layer message against the provided nick
    """
    arguments = [(b'msg', Unicode()),
                 (b'fullmsg', Unicode()),
                 (b'sig', Unicode()),
                 (b'pubkey', Unicode()),
                 (b'nick', Unicode()),
                 (b'hashlen', Integer()),
                 (b'max_encoded', Integer()),
                 (b'hostid', Unicode())]

""" TAKER-specific commands
"""

class JMOffers(JMCommand):
    """Return the entire contents of the
    orderbook to TAKER, as a json-ified dict.
    """
    arguments = [(b'orderbook', BigUnicode())]

class JMFillResponse(JMCommand):
    """Returns ioauth data from MAKER if successful.
    """
    arguments = [(b'success', Boolean()),
                 (b'ioauth_data', Unicode())]

class JMSigReceived(JMCommand):
    """Returns an individual bitcoin transaction signature
    from a MAKER
    """
    arguments = [(b'nick', Unicode()),
                 (b'sig', Unicode())]

"""MAKER-specific commands
"""

class JMAuthReceived(JMCommand):
    """Return the commitment and revelation
    provided in !fill, !auth by the TAKER,
    allowing the MAKER to verify against btc library
    before setting up encryption and continuing.
    """
    arguments = [(b'nick', Unicode()),
                 (b'offer', Unicode()),
                 (b'commitment', Unicode()),
                 (b'revelation', Unicode()),
                 (b'amount', Integer()),
                 (b'kphex', Unicode())]

class JMTXReceived(JMCommand):
    """Send back transaction template provided
    by TAKER, along with offerdata to verify fees.
    """
    arguments = [(b'nick', Unicode()),
                 (b'txhex', Unicode()),
                 (b'offer', Unicode())]

class JMTXBroadcast(JMCommand):
    """ Accept a bitcoin transaction
    sent over the wire by a counterparty
    and relay it to the client for network
    broadcast.
    """
    arguments = [(b'txhex', Unicode())]

"""SNICKER related commands.
"""

class SNICKERReceiverInit(JMCommand):
    """ Initialization data for a SNICKER service.
    See documentation of `netconfig` in
    jmdaemon.HTTPPassThrough.on_INIT
    """
    arguments = [(b'netconfig', Unicode())]

class SNICKERProposerInit(JMCommand):
    """ As for receiver.
    """
    arguments = [(b'netconfig', Unicode())]

class SNICKERReceiverUp(JMCommand):
    arguments = []

class SNICKERProposerUp(JMCommand):
    arguments = []

class SNICKERReceiverGetProposals(JMCommand):
    arguments = []

class SNICKERReceiverProposals(JMCommand):
    """ Sends the retrieved proposal list from
    a specific server, from daemon back to client.
    """
    arguments = [(b'proposals', BigUnicode()),
                 (b'server', Unicode())]

class SNICKERProposerPostProposals(JMCommand):
    """ Sends a list of proposals to be uploaded
    to a server.
    """
    arguments = [(b'proposals', BigUnicode()),
                 (b'server', Unicode())]

class SNICKERProposalsServerResponse(JMCommand):
    arguments = [(b'response', Unicode()),
                 (b'server', Unicode())]

class SNICKERServerError(JMCommand):
    arguments = [(b'server', Unicode()),
                 (b'errorcode', Integer())]

class SNICKERRequestPowTarget(JMCommand):
    arguments = [(b'server', Unicode())]

class SNICKERReceivePowTarget(JMCommand):
    arguments = [(b'server', Unicode()),
                 (b'targetbits', Integer())]

""" Payjoin-related commands
"""
class BIP78SenderInit(JMCommand):
    """ Initialization data for a BIP78 service.
    See documentation of `netconfig` in
    jmdaemon.HTTPPassThrough.on_INIT
    """
    arguments = [(b'netconfig', Unicode())]

class BIP78SenderUp(JMCommand):
    arguments = []

class BIP78SenderOriginalPSBT(JMCommand):
    """ Sends the payjoin url and the original
    payment PSBT, base64 encoded,
    from the client to the daemon,
    to be sent as an http request to the receiver.
    """
    arguments = [(b'body', BigUnicode()),
                 (b'params', Unicode())]

class BIP78SenderReceiveProposal(JMCommand):
    """ Sends the payjoin proposal PSBT, received
    from the BIP78 Receiver, from the daemon to the client.
    """
    arguments = [(b'psbt', BigUnicode())]

class BIP78ReceiverError(JMCommand):
    """ Sends a message from daemon to client
    indicating that the BIP78 receiver did not
    accept the request, or there was a network error.
    """
    arguments = [(b'errormsg', Unicode()),
                 (b'errorcode', Integer())]
