from __future__ import print_function

import logging

#Full joinmarket uses its own bitcoin module;
#other implementations (like wallet plugins)
#can optionally include their own, which must
#be implemented as an interface in btc.py
from btc import *

from .support import (calc_cj_fee, choose_sweep_orders, choose_orders,
                      cheapest_order_choose, weighted_order_choose,
                      rand_norm_array, rand_pow_array, rand_exp_array, select,
                      select_gradual, select_greedy, select_greediest)
from .jsonrpc import JsonRpcError, JsonRpcConnectionError, JsonRpc
from .old_mnemonic import mn_decode, mn_encode
from .slowaes import decryptData, encryptData
from .taker import Taker
from .wallet import AbstractWallet, BitcoinCoreInterface, Wallet, \
    BitcoinCoreWallet, estimate_tx_fee
from .configure import load_program_config, jm_single, get_p2pk_vbyte, \
    get_network, jm_single, get_network, validate_address, get_irc_mchannels, \
    check_utxo_blacklist
from .blockchaininterface import (BlockrInterface, BlockchainInterface, sync_wallet,
                                  RegtestBitcoinCoreInterface, BitcoinCoreInterface)
from .client_protocol import JMTakerClientProtocolFactory, start_reactor
from .podle import (set_commitment_file, get_commitment_file,
                    generate_podle_error_string, add_external_commitments,
                    PoDLE, generate_podle, get_podle_commitments,
                    update_commitments)
from .schedule import get_schedule
from .commitment_utils import get_utxo_info, validate_utxo_data, quit
# Set default logging handler to avoid "No handler found" warnings.

try:
    from logging import NullHandler
except ImportError: #pragma: no cover
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

logging.getLogger(__name__).addHandler(NullHandler())

