
import logging
from .protocol import *
from .enc_wrapper import as_init_encryption, decode_decrypt, \
    encrypt_encode, init_keypair, init_pubkey, get_pubkey, NaclError
from .irc import IRCMessageChannel
from jmbase.support import get_log
from .message_channel import MessageChannel, MessageChannelCollection
from .orderbookwatch import OrderbookWatch
from jmbase import commands
from .daemon_protocol import (JMDaemonServerProtocolFactory, JMDaemonServerProtocol,
                              start_daemon, SNICKERDaemonServerProtocolFactory,
                              BIP78ServerProtocolFactory, BIP78ServerProtocol)
from .protocol import (COMMAND_PREFIX, ORDER_KEYS, NICK_HASH_LENGTH,
                       NICK_MAX_ENCODED, JM_VERSION, JOINMARKET_NICK_HEADER)
from .message_channel import MessageChannelCollection
# Set default logging handler to avoid "No handler found" warnings.
try:
    from logging import NullHandler
except ImportError: #pragma: no cover
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

logging.getLogger(__name__).addHandler(NullHandler())

