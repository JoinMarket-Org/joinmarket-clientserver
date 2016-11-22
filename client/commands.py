from twisted.protocols.amp import Integer, String, Unicode, Boolean, Command

class DaemonNotReady(Exception):
    pass

class JMCommand(Command):
    #a default response type
    response = [('accepted', Boolean())]

#commands from client to daemon

class JMInit(JMCommand):   
    arguments = [('bcsource', String()),
                 ('network', String()),
                 ('irc_configs', String()),
                 ('minmakers', Integer()),
                 ('maker_timeout_sec', Integer())]
    errors = {DaemonNotReady: 'daemon is not ready'}

class JMStartMC(JMCommand):
    arguments = [('nick', String())]

class JMSetup(JMCommand):
    arguments = [('role', String()),
                 ('n_counterparties', Integer())]

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
    arguments = [('orderbook', String())]

class JMFillResponse(JMCommand):
    arguments = [('success', Boolean()),
                 ('ioauth_data', String())]

class JMSigReceived(JMCommand):
    arguments = [('nick', String()),
                 ('sig', String())]

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