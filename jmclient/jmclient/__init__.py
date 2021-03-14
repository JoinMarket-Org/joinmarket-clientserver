
import logging

from .support import (calc_cj_fee, choose_sweep_orders, choose_orders,
                      cheapest_order_choose, weighted_order_choose,
                      rand_norm_array, rand_pow_array, rand_exp_array,
                      rand_weighted_choice, select,
                      select_gradual, select_greedy, select_greediest,
                      get_random_bytes, random_under_max_order_choose,
                      select_one_utxo, NotEnoughFundsException)
from .jsonrpc import JsonRpcError, JsonRpcConnectionError, JsonRpc
from .old_mnemonic import mn_decode, mn_encode
from .taker import Taker
from .wallet import (Mnemonic, estimate_tx_fee, WalletError, BaseWallet, ImportWalletMixin,
                     BIP39WalletMixin, BIP32Wallet, BIP49Wallet, LegacyWallet,
                     SegwitWallet, SegwitLegacyWallet, FidelityBondMixin,
                     FidelityBondWatchonlyWallet, SegwitLegacyWalletFidelityBonds,
                     UTXOManager, WALLET_IMPLEMENTATIONS, compute_tx_locktime)
from .storage import (Argon2Hash, Storage, StorageError, RetryableStorageError,
                      StoragePasswordError, VolatileStorage)
from .cryptoengine import (BTCEngine, BTC_P2PKH, BTC_P2SH_P2WPKH, BTC_P2WPKH, EngineError,
                           TYPE_P2PKH, TYPE_P2SH_P2WPKH, TYPE_P2WPKH)
from .configure import (load_test_config, process_shutdown,
    load_program_config, jm_single, get_network, update_persist_config,
    validate_address, is_burn_destination, get_irc_mchannels,
    get_blockchain_interface_instance, set_config, is_segwit_mode,
    is_native_segwit_mode, JMPluginService)
from .blockchaininterface import (BlockchainInterface,
                                  RegtestBitcoinCoreInterface, BitcoinCoreInterface)
from .snicker_receiver import SNICKERError, SNICKERReceiver
from .client_protocol import (JMTakerClientProtocol, JMClientProtocolFactory,
                              start_reactor, SNICKERClientProtocolFactory,
                              BIP78ClientProtocolFactory)
from .podle import (set_commitment_file, get_commitment_file,
                    add_external_commitments,
                    PoDLE, generate_podle, get_podle_commitments,
                    update_commitments)
from .output import generate_podle_error_string, fmt_utxos, fmt_utxo,\
    fmt_tx_data
from .schedule import (get_schedule, get_tumble_schedule, schedule_to_text,
                       tweak_tumble_schedule, human_readable_schedule_entry,
                       schedule_to_text, NO_ROUNDING)
from .commitment_utils import get_utxo_info, validate_utxo_data, quit
from .taker_utils import (tumbler_taker_finished_update, restart_waiter,
                             restart_wait, get_tumble_log, direct_send,
                             tumbler_filter_orders_callback, direct_send)
from .cli_options import (add_base_options, add_common_options,
                          get_tumbler_parser, get_max_cj_fee_values,
                          check_regtest, get_sendpayment_parser,
                          get_default_max_absolute_fee,
                          get_default_max_relative_fee)
from .wallet_utils import (
    wallet_tool_main, wallet_generate_recover_bip39, open_wallet,
    open_test_wallet_maybe, create_wallet, get_wallet_cls, get_wallet_path,
    wallet_display, get_utxos_enabled_disabled, wallet_gettimelockaddress,
    wallet_change_passphrase)
from .wallet_service import WalletService
from .maker import Maker
from .yieldgenerator import YieldGenerator, YieldGeneratorBasic, ygmain
from .payjoin import (parse_payjoin_setup, send_payjoin, PayjoinServer,
                      JMBIP78ReceiverManager)
# Set default logging handler to avoid "No handler found" warnings.

try:
    from logging import NullHandler
except ImportError: #pragma: no cover
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

logging.getLogger(__name__).addHandler(NullHandler())

