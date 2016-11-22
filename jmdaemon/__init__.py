from __future__ import print_function

import logging
from protocol import *
from .enc_wrapper import as_init_encryption, decode_decrypt, \
    encrypt_encode, init_keypair, init_pubkey, get_pubkey, NaclError
from .irc import IRCMessageChannel, B_PER_SEC
from jmbase.support import get_log
from .message_channel import MessageChannel, MessageChannelCollection
from .orderbookwatch import OrderbookWatch
from jmbase import commands

# Set default logging handler to avoid "No handler found" warnings.
try:
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

logging.getLogger(__name__).addHandler(NullHandler())

