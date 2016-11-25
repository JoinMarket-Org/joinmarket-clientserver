from __future__ import print_function

import logging

#Full joinmarket uses its own bitcoin module;
#other implementations (like wallet plugins)
#can optionally include their own, which must
#be implemented as an interface in btc.py
from btc import *

from .support import (calc_cj_fee, choose_sweep_orders, choose_orders,
                      pick_order, cheapest_order_choose, weighted_order_choose,
                      rand_norm_array, rand_pow_array, rand_exp_array)
from .jsonrpc import JsonRpcError, JsonRpcConnectionError, JsonRpc
from .old_mnemonic import mn_decode, mn_encode
from .slowaes import decryptData, encryptData
from .taker import Taker
from .wallet import AbstractWallet, BitcoinCoreInterface, Wallet, \
    BitcoinCoreWallet, estimate_tx_fee, ElectrumWrapWallet
from .configure import load_program_config, jm_single, get_p2pk_vbyte, \
    get_network, jm_single, get_network, validate_address, get_irc_mchannels, \
    check_utxo_blacklist
from .blockchaininterface import (BlockrInterface, BlockchainInterface, sync_wallet,
                                  RegtestBitcoinCoreInterface, BitcoinCoreInterface)
from .client_protocol import JMTakerClientProtocolFactory, start_reactor
from .podle import set_commitment_file, get_commitment_file
from .commands import *
from .schedule import get_schedule
# Set default logging handler to avoid "No handler found" warnings.

try:
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

logging.getLogger(__name__).addHandler(NullHandler())

