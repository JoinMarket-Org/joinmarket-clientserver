from __future__ import print_function
"""
Commands defining client-server (daemon)
messaging protocol (*not* Joinmarket p2p protocol).
Used for AMP asynchronous messages.
"""
from twisted.protocols.amp import Integer, String, Unicode, Boolean, Command
from .bigstring import BigString

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
    arguments = [(b'bcsource', String()),
                 (b'network', String()),
                 (b'irc_configs', String()),
                 (b'minmakers', Integer()),
                 (b'maker_timeout_sec', Integer())]
    errors = {DaemonNotReady: b'daemon is not ready'}

class JMStartMC(JMCommand):
    """Will restart message channel connections if config
    has changed; otherwise will only change nym/nick on MCs.
    """
    arguments = [(b'nick', String())]

class JMSetup(JMCommand):
    """Communicates which of "MAKER" or "TAKER"
    roles are to be taken by this client; for MAKER
    role, passes initial offers for announcement (for TAKER, this data is "none")
    """
    arguments = [(b'role', String()),
                 (b'initdata', String())]

class JMMsgSignature(JMCommand):
    """A response to a request for a bitcoin signature
    on a message-channel layer message from the daemon
    """
    arguments = [(b'nick', String()),
                 (b'cmd', String()),
                 (b'msg_to_return', String()),
                 (b'hostid', String())]

class JMMsgSignatureVerify(JMCommand):
    """A response to a request to verify the bitcoin signature
    of a message-channel layer message from the daemon
    """
    arguments = [(b'verif_result', Boolean()),
                 (b'nick', String()),
                 (b'fullmsg', String()),
                 (b'hostid', String())]

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
                 (b'commitment', String()),
                 (b'revelation', String()),
                 (b'filled_offers', String())]

class JMMakeTx(JMCommand):
    """Send a hex encoded raw bitcoin transaction
    to a set of counterparties
    """
    arguments = [(b'nick_list', String()),
                 (b'txhex', String())]

class JMPushTx(JMCommand):
    """Pass a raw hex transaction to a specific
    counterparty (maker) for pushing (anonymity feature in JM)
    """
    arguments = [(b'nick', String()),
                 (b'txhex', String())]

"""MAKER specific commands
"""

class JMAnnounceOffers(JMCommand):
    """Send list (actually dict) of offers
    to the daemon, along with new announcement
    and cancellation lists (deltas).
    """
    arguments = [(b'to_announce', String()),
                 (b'to_cancel', String()),
                 (b'offerlist', String())]

class JMIOAuth(JMCommand):
    """Send contents of !ioauth message after
    verifying Taker's auth message
    """
    arguments = [(b'nick', String()),
                 (b'utxolist', String()),
                 (b'pubkey', String()),
                 (b'cjaddr', String()),
                 (b'changeaddr', String()),
                 (b'pubkeysig', String())]

class JMTXSigs(JMCommand):
    """Send signatures on the bitcoin transaction
    sent by TAKER
    """
    arguments = [(b'nick', String()),
                 (b'sigs', String())]

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
                 (b'joinmarket_nick_header', String()),
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
    arguments = [(b'nick', String()),
                 (b'cmd', String()),
                 (b'msg', String()),
                 (b'msg_to_be_signed', String()),
                 (b'hostid', String())]

class JMRequestMsgSigVerify(JMCommand):
    """Request the client to verify a counterparty's
    message-channel layer message against the provided nick
    """
    arguments = [(b'msg', String()),
                 (b'fullmsg', String()),
                 (b'sig', String()),
                 (b'pubkey', String()),
                 (b'nick', String()),
                 (b'hashlen', Integer()),
                 (b'max_encoded', Integer()),
                 (b'hostid', String())]

""" TAKER-specific commands
"""

class JMOffers(JMCommand):
    """Return the entire contents of the
    orderbook to TAKER, as a json-ified dict;
    note uses BigString because can be very large
    """
    arguments = [(b'orderbook', BigString())]

class JMFillResponse(JMCommand):
    """Returns ioauth data from MAKER if successful.
    """
    arguments = [(b'success', Boolean()),
                 (b'ioauth_data', String())]

class JMSigReceived(JMCommand):
    """Returns an individual bitcoin transaction signature
    from a MAKER
    """
    arguments = [(b'nick', String()),
                 (b'sig', String())]

"""MAKER-specific commands
"""

class JMAuthReceived(JMCommand):
    """Return the commitment and revelation
    provided in !fill, !auth by the TAKER,
    allowing the MAKER to verify against btc library
    before setting up encryption and continuing.
    """
    arguments = [(b'nick', String()),
                 (b'offer', String()),
                 (b'commitment', String()),
                 (b'revelation', String()),
                 (b'amount', Integer()),
                 (b'kphex', String())]

class JMTXReceived(JMCommand):
    """Send back transaction template provided
    by TAKER, along with offerdata to verify fees.
    """
    arguments = [(b'nick', String()),
                 (b'txhex', String()),
                 (b'offer', String())]
