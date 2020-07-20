import coincurve as secp256k1

# If user has compiled and installed libsecp256k1 via
# JM installation script install.sh, use that;
# if not, it is assumed to be present at the system level
# See: https://github.com/Simplexum/python-bitcointx/commit/79333106eeb55841df2935781646369b186d99f7#diff-1ea6586127522e62d109ec5893a18850R301-R310
# note that the Windows finding mechanism is specific to pre-built binaries (PyInstaller) and will not work
# for a from-source installation; for that, add libsecp256k1-0.dll to the system path.
import os, sys
if sys.platform in ('windows', 'win32'):
    expected_secp_location = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'libsecp256k1-0.dll')
else:
    if sys.platform == "darwin":
        secp_name = "libsecp256k1.dylib"
    else:
        secp_name = "libsecp256k1.so"
    expected_secp_location = os.path.join(sys.prefix, "lib", secp_name)
if os.path.exists(expected_secp_location):
    import bitcointx
    bitcointx.set_custom_secp256k1_path(expected_secp_location)

from jmbitcoin.secp256k1_main import *
from jmbitcoin.secp256k1_transaction import *
from jmbitcoin.secp256k1_deterministic import *
from jmbitcoin.snicker import *
from jmbitcoin.amount import *
from jmbitcoin.bip21 import *
from bitcointx import select_chain_params
from bitcointx.core import (x, b2x, b2lx, lx, COutPoint, CTxOut, CTxIn,
                            CTxInWitness, CTxWitness, CTransaction,
                            CMutableTransaction, Hash160,
                            coins_to_satoshi, satoshi_to_coins)
from bitcointx.core.key import KeyStore
from bitcointx.wallet import (P2SHCoinAddress, P2SHCoinAddressError,
                              P2WPKHCoinAddress, P2WPKHCoinAddressError,
                              CBitcoinKey)
from bitcointx.core.script import (CScript, OP_0, SignatureHash, SIGHASH_ALL,
                                   SIGVERSION_WITNESS_V0, CScriptWitness)
from bitcointx.core.psbt import (PartiallySignedTransaction, PSBT_Input,
                                 PSBT_Output)
from bitcointx.signmessage import SignMessage
from .blocks import get_transactions_in_block

