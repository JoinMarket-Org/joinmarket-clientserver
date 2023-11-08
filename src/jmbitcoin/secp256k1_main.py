import base64
import struct
from typing import List, Tuple, Union

from jmbase import bintohex
from bitcointx import base58
from bitcointx.core import Hash
from bitcointx.core.secp256k1 import _secp256k1 as secp_lib
from bitcointx.core.secp256k1 import secp256k1_context_verify
from bitcointx.core.key import CKey, CKeyBase, CPubKey
from bitcointx.signmessage import BitcoinMessage

# This extra function definition, not present in the
# underlying bitcointx library, is to allow
# multiplication of pubkeys by scalars, as is required
# for PoDLE.
import ctypes
secp_lib.secp256k1_ec_pubkey_tweak_mul.restype = ctypes.c_int
secp_lib.secp256k1_ec_pubkey_tweak_mul.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

#Required only for PoDLE calculation:
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337

BTC_P2PK_VBYTE = {"mainnet": b'\x00', "testnet": b'\x6f', "signet": b'\x6f',
    "regtest": 100}
BTC_P2SH_VBYTE = {"mainnet": b'\x05', "testnet": b'\xc4', "signet": b'\xc4'}

"""PoDLE related primitives
"""
def getG(compressed: bool = True) -> CPubKey:
    """Returns the public key binary
    representation of secp256k1 G;
    note that CPubKey is of type bytes.
    """
    priv = b"\x00"*31 + b"\x01"
    k = CKey(priv, compressed=compressed)
    G = k.pub
    return G

podle_PublicKey_class = CPubKey
podle_PrivateKey_class = CKey

def podle_PublicKey(P: bytes) -> CPubKey:
    """Returns a PublicKey object from a binary string
    """
    return CPubKey(P)

def podle_PrivateKey(priv: bytes) -> CKey:
    """Returns a PrivateKey object from a binary string
    """
    return CKey(priv)

def read_privkey(priv: bytes) -> Tuple[bool, bytes]:
    if len(priv) == 33:
        if priv[-1:] == b'\x01':
            compressed = True
        else:
            raise Exception("Invalid private key")
    elif len(priv) == 32:
        compressed = False
    else:
        raise Exception("Invalid private key")
    return (compressed, priv[:32])

def privkey_to_pubkey(priv: bytes) -> CPubKey:
    '''Take 32/33 byte raw private key as input.
    If 32 bytes, return as uncompressed raw public key.
    If 33 bytes and the final byte is 01, return
    compresse public key. Else throws Exception.'''
    compressed, priv = read_privkey(priv)
    # CKey checks for validity of key value;
    # any invalidity throws ValueError.
    newpriv = CKey(priv, compressed=compressed)
    return newpriv.pub

# b58check wrapper functions around bitcointx.base58 functions:
# (avoids complexity of key management structure)

def bin_to_b58check(inp: bytes,
                    magicbyte: Union[bytes, int] = b'\x00') -> str:
    """ The magic byte (prefix byte) should be passed either
    as a single byte or an integer. What is returned is a string
    in base58 encoding, with the prefix and the checksum.
    """
    if not isinstance(magicbyte, int):
        magicbyte = struct.unpack(b'B', magicbyte)[0]
    assert(0 <= magicbyte <= 0xff)
    if magicbyte == 0:
        inp_fmtd = struct.pack(b'B', magicbyte) + inp
    while magicbyte > 0:
        inp_fmtd = struct.pack(b'B', magicbyte % 256) + inp
        magicbyte //= 256
    checksum = Hash(inp_fmtd)[:4]
    return base58.encode(inp_fmtd + checksum)

def b58check_to_bin(s: str) -> bytes:
    data = base58.decode(s)
    assert Hash(data[:-4])[:4] == data[-4:]
    return struct.pack(b"B", data[0]), data[1:-4]

def get_version_byte(s: str) -> bytes:
    return b58check_to_bin(s)[0]

def ecdsa_sign(msg: str, priv: bytes) -> str:
    hashed_msg = BitcoinMessage(msg).GetHash()
    sig = ecdsa_raw_sign(hashed_msg, priv, rawmsg=True)
    return base64.b64encode(sig).decode('ascii')

def ecdsa_verify(msg: str, sig: str, pub: bytes) -> bool:
    hashed_msg = BitcoinMessage(msg).GetHash()
    sig = base64.b64decode(sig)
    return ecdsa_raw_verify(hashed_msg, pub, sig, rawmsg=True)

def is_valid_pubkey(pubkey: bytes, require_compressed: bool = False) -> bool:
    """ Returns True if the serialized pubkey is a valid secp256k1
    pubkey serialization or False if not; returns False for an
    uncompressed encoding if require_compressed is True.
    """
    # sanity check for public key
    # see https://github.com/bitcoin/bitcoin/blob/master/src/pubkey.h
    if require_compressed:
        valid_uncompressed = False
    elif len(pubkey) == 65 and pubkey[:1] in (b'\x04', b'\x06', b'\x07'):
        valid_uncompressed = True
    else:
        valid_uncompressed = False

    if not ((len(pubkey) == 33 and pubkey[:1] in (b'\x02', b'\x03')) or
    valid_uncompressed):
        return False
    # serialization is valid, but we must ensure it corresponds
    # to a valid EC point. The CPubKey constructor calls the pubkey_parse
    # operation from the libsecp256k1 library:
    dummy = CPubKey(pubkey)
    if not dummy.is_fullyvalid():
        return False
    return True


def multiply(s: bytes, pub: bytes, return_serialized: bool = True) -> bytes:
    '''Input binary compressed pubkey P(33 bytes)
    and scalar s(32 bytes), return s*P.
    The return value is a binary compressed public key,
    or a PublicKey object if return_serialized is False.
    Note that the called function does the type checking
    of the scalar s.
    ('raw' options passed in)
    '''
    try:
        CKey(s)
    except ValueError:
        raise ValueError("Invalid tweak for libsecp256k1 "
                         "multiply: {}".format(bintohex(s)))

    pub_obj = CPubKey(pub)
    if not pub_obj.is_fullyvalid():
        raise ValueError("Invalid pubkey for multiply: {}".format(
            bintohex(pub)))

    privkey_arg = ctypes.c_char_p(s)
    pubkey_buf = pub_obj._to_ctypes_char_array()
    ret = secp_lib.secp256k1_ec_pubkey_tweak_mul(
        secp256k1_context_verify, pubkey_buf, privkey_arg)
    if ret != 1:
        assert ret == 0
        raise ValueError('Multiplication failed')
    if not return_serialized:
        return CPubKey._from_ctypes_char_array(pubkey_buf)
    return bytes(CPubKey._from_ctypes_char_array(pubkey_buf))

def add_pubkeys(pubkeys: List[bytes]) -> CPubKey:
    '''Input a list of binary compressed pubkeys
    and return their sum as a binary compressed pubkey.'''
    pubkey_list = [CPubKey(x) for x in pubkeys]
    if not all([x.is_compressed() for x in pubkey_list]):
        raise ValueError("Only compressed pubkeys can be added.")
    if not all([x.is_fullyvalid() for x in pubkey_list]):
        raise ValueError("Invalid pubkey format.")
    return CPubKey.combine(*pubkey_list)

def add_privkeys(priv1: bytes, priv2: bytes) -> bytes:
    '''Add privkey 1 to privkey 2.
    Input keys must be in binary either compressed or not.
    Returned key will have the same compression state.
    Error if compression state of both input keys is not the same.'''
    y, z = [read_privkey(x) for x in [priv1, priv2]]
    if y[0] != z[0]:
        raise Exception("cannot add privkeys, mixed compression formats")
    else:
        compressed = y[0]
    newpriv1, newpriv2 = (y[1], z[1])
    res = CKey.add(CKey(newpriv1), CKey(newpriv2)).secret_bytes
    if compressed:
        res += b'\x01'
    return res

def ecdh(privkey: bytes, pubkey: bytes) -> bytes:
    """ Take a privkey in raw byte serialization,
    and a pubkey serialized in compressed, binary format (33 bytes),
    and output the shared secret as a 32 byte hash digest output.
    The exact calculation is:
    shared_secret = SHA256(compressed_serialization_of_pubkey(privkey * pubkey))
    .. where * is elliptic curve scalar multiplication.
    See https://github.com/bitcoin/bitcoin/blob/master/src/secp256k1/src/modules/ecdh/main_impl.h
    for implementation details.
    """
    _, priv = read_privkey(privkey)
    return CKey(priv).ECDH(CPubKey(pubkey))

def ecdsa_raw_sign(msg: Union[bytes, bytearray],
                   priv: bytes,
                   rawmsg: bool = False) -> bytes:
    '''Take the binary message msg and sign it with the private key
    priv.
    If rawmsg is True, no sha256 hash is applied to msg before signing.
    In this case, msg must be a precalculated hash (256 bit).
    If rawmsg is False, the secp256k1 lib will hash the message as part
    of the ECDSA-SHA256 signing algo.
    Return value: the calculated signature.'''
    if rawmsg and len(msg) != 32:
        raise Exception("Invalid hash input to ECDSA raw sign.")
    compressed, p = read_privkey(priv)
    newpriv = CKey(p, compressed=compressed)
    if rawmsg:
        sig = newpriv.sign(msg, _ecdsa_sig_grind_low_r=False)
    else:
        sig = newpriv.sign(Hash(msg), _ecdsa_sig_grind_low_r=False)
    return sig

def ecdsa_raw_verify(msg: bytes,
                     pub: bytes,
                     sig: bytes,
                     rawmsg: bool = False) -> bool:
    '''Take the binary message msg and binary signature sig,
    and verify it against the pubkey pub.
    If rawmsg is True, no sha256 hash is applied to msg before verifying.
    In this case, msg must be a precalculated hash (256 bit).
    If rawmsg is False, the secp256k1 lib will hash the message as part
    of the ECDSA-SHA256 verification algo.
    Return value: True if the signature is valid for this pubkey, False
    otherwise.
    Since the arguments may come from external messages their content is
    not guaranteed, so return False on any parsing exception.
    '''
    try:
        if rawmsg:
            assert len(msg) == 32
        newpub = CPubKey(pub)
        if rawmsg:
            retval = newpub.verify(msg, sig)
        else:
            retval = newpub.verify(Hash(msg), sig)
    except Exception:
        return False
    return retval

class JMCKey(bytes, CKeyBase):
    """An encapsulated private key.
    This subclasses specifically for JM's own signing code.

    Attributes:

    pub           - The corresponding CPubKey for this private key
    secret_bytes  - Secret data, 32 bytes (needed because subclasses may have trailing data)

    is_compressed() - True if compressed

    """

    def __init__(self, b):
        CKeyBase.__init__(self, b, compressed=True)

    def sign(self, hash: Union[bytes, bytearray]) -> bytes:
        assert isinstance(hash, (bytes, bytearray))
        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')
        # TODO: non default sighash flag.
        return ecdsa_raw_sign(hash, self.secret_bytes + b"\x01", rawmsg=True)
