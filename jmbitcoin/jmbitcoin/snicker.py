# Implementation of proposal as per
# https://gist.github.com/AdamISZ/2c13fb5819bd469ca318156e2cf25d79
# (BIP SNICKER)
# TODO: BIP69 is removed in this implementation, will update BIP draft.

from jmbitcoin.secp256k1_ecies import *
from jmbitcoin.secp256k1_main import *
from jmbitcoin.secp256k1_transaction import *

SNICKER_MAGIC_BYTES = b'SNICKER'

# Flags may be added in future versions
SNICKER_FLAG_NONE = b"\x00"

def snicker_pubkey_tweak(pub, tweak):
    """ use secp256k1 library to perform tweak.
    Both `pub` and `tweak` are expected as byte strings
    (33 and 32 bytes respectively).
    Return value is also a 33 byte string serialization
    of the resulting pubkey (compressed).
    """
    base_pub = secp256k1.PublicKey(pub)
    return base_pub.add(tweak).format()

def snicker_privkey_tweak(priv, tweak):
    """ use secp256k1 library to perform tweak.
    Both `priv` and `tweak` are expected as byte strings
    (32 or 33 and 32 bytes respectively).
    Return value isa 33 byte string serialization
    of the resulting private key/secret (with compression flag).
    """
    if len(priv) == 33 and priv[-1] == 1:
        priv = priv[:-1]
    base_priv = secp256k1.PrivateKey(priv)
    return base_priv.add(tweak).secret + b'\x01'

def verify_snicker_output(tx, pub, tweak, spk_type='p2sh-p2wpkh'):
    """ A convenience function to check that one output address in a transaction
    is a SNICKER-type tweak of an existing key. Returns the index of the output
    for which this is True (and there must be only 1), and the derived spk,
    or -1 and None if it is not found exactly once.
    TODO Add support for other scriptPubKey types.
    """
    assert isinstance(tx, btc.CTransaction)
    expected_destination_pub = snicker_pubkey_tweak(pub, tweak)
    expected_destination_spk = pubkey_to_p2sh_p2wpkh_script(expected_destination_pub)
    found = 0
    for i, o in enumerate(tx.vout):
        if o.scriptPubKey == expected_destination_spk:
            found += 1
            found_index = i
    if found != 1:
        return -1, None
    return found_index, expected_destination_spk
