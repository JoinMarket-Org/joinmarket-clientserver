from __future__ import print_function
"""
Commands defining client-server (daemon)
messaging protocol (*not* Joinmarket p2p protocol).
Used for AMP asynchronous messages.
"""
from twisted.protocols.amp import Integer, String, Unicode, Boolean, Command
from bigstring import BigString

class DaemonNotReady(Exception):
    pass

class JMCommand(Command):
    #a default response type
    response = [('accepted', Boolean())]

#commands from client to daemon

class JMInit(JMCommand):
    """Communicates the client's required setup
    configuration.
    Blockchain source is communicated only as a naming
    tag for messagechannels (currently IRC 'realname' field).
    """
    arguments = [('bcsource', String()),
                 ('network', String()),
                 ('irc_configs', String()),
                 ('minmakers', Integer()),
                 ('maker_timeout_sec', Integer())]
    errors = {DaemonNotReady: 'daemon is not ready'}

class JMStartMC(JMCommand):
    """Will restart message channel connections if config
    has changed; otherwise will only change nym/nick on MCs.
    """
    arguments = [('nick', String())]

class JMSetup(JMCommand):
    arguments = [('role', String()),
                 ('initdata', String())]

"""Taker specific commands
"""

class JMRequestOffers(JMCommand):
    arguments = []

class JMFill(JMCommand):
    arguments = [('amount', Integer()),
                 ('commitment', String()),
                 ('revelation', String()),
                 ('filled_offers', String())]

class JMMakeTx(JMCommand):
    arguments = [('nick_list', String()),
                 ('txhex', String())]

class JMPushTx(JMCommand):
    arguments = [('nick', String()),
                 ('txhex', String())]

class JMMsgSignature(JMCommand):
    arguments = [('nick', String()),
                 ('cmd', String()),
                 ('msg_to_return', String()),
                 ('hostid', String())]

class JMMsgSignatureVerify(JMCommand):
    arguments = [('verif_result', Boolean()),
                 ('nick', String()),
                 ('fullmsg', String()),
                 ('hostid', String())]

"""Maker specific commands
"""

class JMAnnounceOffers(JMCommand):
    arguments = [('offerlist', String())]

class JMMakerPubkey(JMCommand):
    arguments = [('nick', String()),
                 ('pubkey', String())]

class JMIOAuth(JMCommand):
    arguments = [('nick', String()),
                 ('utxolist', String()),
                 ('pubkey', String()),
                 ('cjaddr', String()),
                 ('changeaddr', String()),
                 ('pubkeysig', String())]

class JMTXSigs(JMCommand):
    arguments = [('nick', String()),
                 ('sigs', String())]
    
#commands from daemon to client

class JMInitProto(JMCommand):
    arguments = [('nick_hash_length', Integer()),
                 ('nick_max_encoded', Integer()),
                 ('joinmarket_nick_header', String()),
                 ('joinmarket_version', Integer())]

class JMUp(JMCommand):
    arguments = []

class JMSetupDone(JMCommand):
    arguments = []

class JMOffers(JMCommand):
    arguments = [('orderbook', BigString())]

class JMFillResponse(JMCommand):
    arguments = [('success', Boolean()),
                 ('ioauth_data', String())]

class JMSigReceived(JMCommand):
    arguments = [('nick', String()),
                 ('sig', String())]

"""Maker specific daemon-client messages
"""

class JMCommitmentOpen(JMCommand):
    arguments = [('nick', String()),
                 ('revelation', String())]

class JMAuthReceived(JMCommand):
    arguments = [('nick', String()),
                 ('offer', String()),
                 ('commitment', String()),
                 ('revelation', String()),
                 ('amount', Integer()),
                 ('kphex', String())]

class JMTXReceived(JMCommand):
    arguments = [('nick', String()),
                 ('txhex', String()),
                 ('offer', String())]

class JMRequestMsgSig(JMCommand):
    arguments = [('nick', String()),
                 ('cmd', String()),
                 ('msg', String()),
                 ('msg_to_be_signed', String()),
                 ('hostid', String())]

class JMRequestMsgSigVerify(JMCommand):
    arguments = [('msg', String()),
                 ('fullmsg', String()),
                 ('sig', String()),
                 ('pubkey', String()),
                 ('nick', String()),
                 ('hashlen', Integer()),
                 ('max_encoded', Integer()),
                 ('hostid', String())]