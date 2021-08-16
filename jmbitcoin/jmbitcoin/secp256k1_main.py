import base64
import struct
import coincurve as secp256k1

from bitcointx import base58
from bitcointx.core import Hash
from bitcointx.core.key import CKeyBase
from bitcointx.signmessage import BitcoinMessage

#Required only for PoDLE calculation:
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337

BTC_P2PK_VBYTE = {"mainnet": b'\x00', "testnet": b'\x6f', "signet": b'\x6f',
    "regtest": 100}
BTC_P2SH_VBYTE = {"mainnet": b'\x05', "testnet": b'\xc4', "signet": b'\xc4'}

"""PoDLE related primitives
"""
def getG(compressed=True):
    """Returns the public key binary
    representation of secp256k1 G
    """
    priv = b"\x00"*31 + b"\x01"
    G = secp256k1.PrivateKey(priv).public_key.format(compressed)
    return G

podle_PublicKey_class = secp256k1.PublicKey
podle_PrivateKey_class = secp256k1.PrivateKey

def podle_PublicKey(P):
    """Returns a PublicKey object from a binary string
    """
    return secp256k1.PublicKey(P)

def podle_PrivateKey(priv):
    """Returns a PrivateKey object from a binary string
    """
    return secp256k1.PrivateKey(priv)

def read_privkey(priv):
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

def privkey_to_pubkey(priv):
    '''Take 32/33 byte raw private key as input.
    If 32 bytes, return compressed (33 byte) raw public key.
    If 33 bytes, read the final byte as compression flag,
    and return compressed/uncompressed public key as appropriate.'''
    compressed, priv = read_privkey(priv)
    #secp256k1 checks for validity of key value.
    newpriv = secp256k1.PrivateKey(secret=priv)
    return newpriv.public_key.format(compressed)

# b58check wrapper functions around bitcointx.base58 functions:
# (avoids complexity of key management structure)

def bin_to_b58check(inp, magicbyte=b'\x00'):
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

def b58check_to_bin(s):
    data = base58.decode(s)
    assert Hash(data[:-4])[:4] == data[-4:]
    return struct.pack(b"B", data[0]), data[1:-4]

def get_version_byte(s):
    return b58check_to_bin(s)[0]

def ecdsa_sign(msg, priv, formsg=False):
    hashed_msg = BitcoinMessage(msg).GetHash()
    sig = ecdsa_raw_sign(hashed_msg, priv, rawmsg=True, formsg=formsg)
    return base64.b64encode(sig).decode('ascii')

def ecdsa_verify(msg, sig, pub):
    hashed_msg = BitcoinMessage(msg).GetHash()
    sig = base64.b64decode(sig)
    return ecdsa_raw_verify(hashed_msg, pub, sig, rawmsg=True)

def is_valid_pubkey(pubkey, require_compressed=False):
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
    # to a valid EC point:
    try:
        dummy = secp256k1.PublicKey(pubkey)
    except:
        return False
    return True


def multiply(s, pub, return_serialized=True):
    '''Input binary compressed pubkey P(33 bytes)
    and scalar s(32 bytes), return s*P.
    The return value is a binary compressed public key,
    or a PublicKey object if return_serialized is False.
    Note that the called function does the type checking
    of the scalar s.
    ('raw' options passed in)
    '''
    newpub = secp256k1.PublicKey(pub)
    #see note to "tweak_mul" function in podle.py
    res = newpub.multiply(s)
    if not return_serialized:
        return res
    return res.format()

def add_pubkeys(pubkeys):
    '''Input a list of binary compressed pubkeys
    and return their sum as a binary compressed pubkey.'''
    pubkey_list = [secp256k1.PublicKey(x) for x in pubkeys]
    r = secp256k1.PublicKey.combine_keys(pubkey_list)
    return r.format()

def add_privkeys(priv1, priv2):
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
    p1 = secp256k1.PrivateKey(newpriv1)
    res = p1.add(newpriv2).secret
    if compressed:
        res += b'\x01'
    return res

def ecdh(privkey, pubkey):
    """ Take a privkey in raw byte serialization,
    and a pubkey serialized in compressed, binary format (33 bytes),
    and output the shared secret as a 32 byte hash digest output.
    The exact calculation is:
    shared_secret = SHA256(privkey * pubkey)
    .. where * is elliptic curve scalar multiplication.
    See https://github.com/bitcoin/bitcoin/blob/master/src/secp256k1/src/modules/ecdh/main_impl.h
    for implementation details.
    """
    secp_privkey = secp256k1.PrivateKey(privkey)
    return secp_privkey.ecdh(pubkey)

def ecdsa_raw_sign(msg,
                   priv,
                   rawmsg=False,
                   formsg=False):
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
    newpriv = secp256k1.PrivateKey(p)
    if formsg:
        sig = newpriv.sign_recoverable(msg)
        return sig
    else:
        if rawmsg:
            sig = newpriv.sign(msg, hasher=None)
        else:
            sig = newpriv.sign(msg)
    return sig

def ecdsa_raw_verify(msg, pub, sig, rawmsg=False):
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
        newpub = secp256k1.PublicKey(pub)
        if rawmsg:
            retval = newpub.verify(sig, msg, hasher=None)
        else:
            retval = newpub.verify(sig, msg)
    except Exception as e:
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

    def sign(self, hash):
        assert isinstance(hash, (bytes, bytearray))
        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')
        # TODO: non default sighash flag.
        return ecdsa_raw_sign(hash, self.secret_bytes + b"\x01", rawmsg=True)
