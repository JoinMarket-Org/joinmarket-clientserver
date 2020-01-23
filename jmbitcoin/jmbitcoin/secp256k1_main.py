#!/usr/bin/python
from future.utils import native_bytes, bytes_to_native_str
import binascii
import hashlib
import sys
import base64
import struct
import coincurve as secp256k1

#Required only for PoDLE calculation:
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337

BTC_P2PK_VBYTE = {"mainnet": b'\x00', "testnet": b'\x6f', "regtest": 100}
BTC_P2SH_VBYTE = {"mainnet": b'\x05', "testnet": b'\xc4'}

#Standard prefix for Bitcoin message signing.
BITCOIN_MESSAGE_MAGIC = b'\x18' + b'Bitcoin Signed Message:\n'

string_types = (str)
string_or_bytes_types = (str, bytes)
int_types = (int, float)

# Base switching
code_strings = {
    2: '01',
    10: '0123456789',
    16: '0123456789abcdef',
    32: 'abcdefghijklmnopqrstuvwxyz234567',
    58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    256: ''.join([chr(x) for x in range(256)])
}

def lpad(msg, symbol, length):
    if len(msg) >= length:
        return msg
    return symbol * (length - len(msg)) + msg

def get_code_string(base):
    if base in code_strings:
        return code_strings[base]
    else:
        raise ValueError("Invalid base!")

def bin_to_b58check(inp, magicbyte=b'\x00'):
    if not isinstance(magicbyte, int):
        magicbyte = struct.unpack(b'B', magicbyte)[0]
    assert(0 <= magicbyte <= 0xff)
    if magicbyte == 0:
        inp_fmtd = struct.pack(b'B', magicbyte) + inp
    while magicbyte > 0:
        inp_fmtd = struct.pack(b'B', magicbyte % 256) + inp
        magicbyte //= 256
    checksum = bin_dbl_sha256(inp_fmtd)[:4]
    return b58encode(inp_fmtd + checksum)

def safe_from_hex(s):
    return binascii.unhexlify(s)

def from_int_to_byte(a):
    return struct.pack(b'B', a)

def from_byte_to_int(a):
    return struct.unpack(b'B', a)[0]

def from_string_to_bytes(a):
    return a if isinstance(a, bytes) else bytes(a, 'utf-8')

def safe_hexlify(a):
    return binascii.hexlify(a).decode('ascii')

class SerializationError(Exception):
    """Base class for serialization errors"""


class SerializationTruncationError(SerializationError):
    """Serialized data was truncated
    Thrown by deserialize() and stream_deserialize()
    """

def ser_read(f, n):
    """Read from a stream safely
    Raises SerializationError and SerializationTruncationError appropriately.
    Use this instead of f.read() in your classes stream_(de)serialization()
    functions.
    """
    MAX_SIZE = 0x02000000
    if n > MAX_SIZE:
        raise SerializationError('Asked to read 0x%x bytes; MAX_SIZE exceeded' % n)
    r = f.read(n)
    if len(r) < n:
        raise SerializationTruncationError('Asked to read %i bytes, but only got %i' % (n, len(r)))
    return r

B58_DIGITS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

class Base58Error(Exception):
    pass

class InvalidBase58Error(Base58Error):
    """Raised on generic invalid base58 data, such as bad characters.
    Checksum failures raise Base58ChecksumError specifically.
    """
    pass

def b58encode(b):
    """Encode bytes to a base58-encoded string"""

    # Convert big-endian bytes to integer
    n = int('0x0' + binascii.hexlify(b).decode('ascii'), 16)

    # Divide that integer into bas58
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(B58_DIGITS[r])
    res = ''.join(res[::-1])

    # Encode leading zeros as base58 zeros
    czero = b'\x00'
    if sys.version_info >= (3,0):
        # In Python3 indexing a bytes returns numbers, not characters.
        czero = 0
    pad = 0
    for c in b:
        if c == czero:
            pad += 1
        else:
            break
    return B58_DIGITS[0] * pad + res

def b58decode(s):
    """Decode a base58-encoding string, returning bytes"""
    if not s:
        return b''

    # Convert the string to an integer
    n = 0
    for c in s:
        n *= 58
        if c not in B58_DIGITS:
            raise InvalidBase58Error('Character %r is not a valid base58 character' % c)
        digit = B58_DIGITS.index(c)
        n += digit

    # Convert the integer to bytes
    h = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = bytes(binascii.unhexlify(h.encode('utf8')))

    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == B58_DIGITS[0]: pad += 1
        else: break
    return b'\x00' * pad + res

def uint256encode(s):
    """Convert bytes to uint256"""
    r = 0
    t = struct.unpack(b"<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r

def uint256decode(u):
    r = b""
    for i in range(8):
        r += struct.pack(b'<I', u >> (i * 32) & 0xffffffff)
    return r

def encode(val, base, minlen=0):
    base, minlen = int(base), int(minlen)
    code_string = get_code_string(base)
    result_bytes = bytes()
    while val > 0:
        curcode = code_string[val % base]
        result_bytes = bytes([ord(curcode)]) + result_bytes
        val //= base

    pad_size = minlen - len(result_bytes)

    padding_element = b'\x00' if base == 256 else b'1' \
        if base == 58 else b'0'
    if (pad_size > 0):
        result_bytes = padding_element*pad_size + result_bytes

    result_string = ''.join([chr(y) for y in result_bytes])
    result = result_bytes if base == 256 else result_string

    return result

def decode(string, base):
    if base == 256 and isinstance(string, str):
        string = bytes(bytearray.fromhex(string))
    base = int(base)
    code_string = get_code_string(base)
    result = 0
    if base == 256:
        def extract(d, cs):
            if isinstance(d, int):
                return d
            else:
                return struct.unpack(b'B', d)[0]
    else:
        def extract(d, cs):
            return cs.find(d if isinstance(d, str) else chr(d))

    if base == 16:
        string = string.lower()
    while len(string) > 0:
        result *= base
        result += extract(string[0], code_string)
        string = string[1:]
    return result

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


def privkey_to_address(priv, from_hex=True, magicbyte=0):
    return pubkey_to_address(privkey_to_pubkey(priv, from_hex), magicbyte)

privtoaddr = privkey_to_address

# Hashes
def bin_hash160(string):
    intermed = hashlib.sha256(string).digest()
    return hashlib.new('ripemd160', intermed).digest()

def hash160(string):
    if not isinstance(string, bytes):
        string = string.encode('utf-8')
    return safe_hexlify(bin_hash160(string))

def bin_sha256(string):
    binary_data = string if isinstance(string, bytes) else bytes(string,
                                                                 'utf-8')
    return hashlib.sha256(binary_data).digest()

def sha256(string):
    return safe_hexlify(bin_sha256(string))

def bin_dbl_sha256(bytes_to_hash):
    if not isinstance(bytes_to_hash, bytes):
        bytes_to_hash = bytes_to_hash.encode('utf-8')
    return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()

def dbl_sha256(string):
    return hashlib.sha256(hashlib.sha256(string).digest()).hexdigest()

def hash_to_int(x):
    if len(x) in [40, 64]:
        return decode(x, 16)
    return decode(x, 256)

def num_to_var_int(x):
    if not isinstance(x, int):
        if len(x) == 0:
            return b'\x00'
        x = struct.unpack(b'B', x)[0]
    if x < 253: return from_int_to_byte(x)
    elif x < 65536: return from_int_to_byte(253) + struct.pack(b'<H', x)
    elif x < 4294967296: return from_int_to_byte(254) + struct.pack(b'<I', x)
    else: return from_int_to_byte(255) + struct.pack(b'<Q', x)

def message_sig_hash(message):
    """Used for construction of signatures of
    messages, intended to be compatible with Bitcoin Core.
    """
    padded = BITCOIN_MESSAGE_MAGIC + num_to_var_int(len(
        message)) + from_string_to_bytes(message)
    return bin_dbl_sha256(padded)

# Encodings
def b58check_to_bin(inp):
    data = b58decode(inp)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return data[1:-4]

def get_version_byte(inp):
    data = b58decode(inp)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return data[:1]

def hex_to_b58check(inp, magicbyte=b'\x00'):
    return bin_to_b58check(binascii.unhexlify(inp), magicbyte)

def b58check_to_hex(inp):
    return binascii.hexlify(b58check_to_bin(inp)).decode('ascii')

def pubkey_to_address(pubkey, magicbyte=0):
    if len(pubkey) in [66, 130]:
        return bin_to_b58check(
            bin_hash160(binascii.unhexlify(pubkey)), magicbyte)
    return bin_to_b58check(bin_hash160(pubkey), magicbyte)

pubtoaddr = pubkey_to_address

def wif_compressed_privkey(priv, vbyte=b'\x00'):
    """Convert privkey in hex compressed to WIF compressed
    """
    if not isinstance(vbyte, int):
        vbyte = struct.unpack(b'B', vbyte)[0]
    if len(priv) != 66:
        raise Exception("Wrong length of compressed private key")
    if priv[-2:] != '01':
        raise Exception("Private key has wrong compression byte")
    return bin_to_b58check(binascii.unhexlify(priv), 128 + int(vbyte))


def from_wif_privkey(wif_priv, compressed=True, vbyte=b'\x00'):
    """Convert WIF compressed privkey to hex compressed.
    Caller specifies the network version byte (0 for mainnet, 0x6f
    for testnet) that the key should correspond to; if there is
    a mismatch an error is thrown. WIF encoding uses 128+ this number.
    """
    if isinstance(vbyte, int):
        vbyte = struct.pack(b'B', vbyte)
    bin_key = b58check_to_bin(wif_priv)
    claimed_version_byte = get_version_byte(wif_priv)
    if not from_int_to_byte(128+from_byte_to_int(vbyte)) == claimed_version_byte:
        raise Exception(
            "WIF key version byte is wrong network (mainnet/testnet?)")
    if compressed and not len(bin_key) == 33:
        raise Exception("Compressed private key is not 33 bytes")
    if compressed and not bin_key[-1:] == b'\x01':
        raise Exception("Private key has incorrect compression byte")
    return safe_hexlify(bin_key)

def ecdsa_sign(msg, priv, formsg=False, usehex=True):
    hashed_msg = message_sig_hash(msg)
    if usehex:
        #arguments to raw sign must be consistently hex or bin
        hashed_msg = binascii.hexlify(hashed_msg).decode('ascii')
    sig = ecdsa_raw_sign(hashed_msg, priv, usehex, rawmsg=True, formsg=formsg)
    #note those functions only handles binary, not hex
    if usehex:
        sig = binascii.unhexlify(sig)
    return base64.b64encode(sig).decode('ascii')

def ecdsa_verify(msg, sig, pub, usehex=True):
    hashed_msg = message_sig_hash(msg)
    sig = base64.b64decode(sig)
    if usehex:
        #arguments to raw_verify must be consistently hex or bin
        hashed_msg = binascii.hexlify(hashed_msg).decode('ascii')
        sig = binascii.hexlify(sig).decode('ascii')
    return ecdsa_raw_verify(hashed_msg, pub, sig, usehex, rawmsg=True)

#Use secp256k1 to handle all EC and ECDSA operations.
#Data types: only hex and binary.
#Compressed and uncompressed private and public keys.
def hexbin(func):
    '''To enable each function to 'speak' either hex or binary,
    requires that the decorated function's final positional argument
    is a boolean flag, True for hex and False for binary.
    '''

    def func_wrapper(*args, **kwargs):
        if args[-1]:
            newargs = []
            for arg in args[:-1]:
                if isinstance(arg, (list, tuple)):
                    newargs += [[binascii.unhexlify(x) for x in arg]]
                else:
                    newargs += [binascii.unhexlify(arg)]
            newargs += [False]
            returnval = func(*newargs, **kwargs)
            if isinstance(returnval, bool):
                return returnval
            else:
                return binascii.hexlify(returnval).decode('ascii')
        else:
            return func(*args, **kwargs)

    return func_wrapper

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

@hexbin
def privkey_to_pubkey_inner(priv, usehex):
    '''Take 32/33 byte raw private key as input.
    If 32 bytes, return compressed (33 byte) raw public key.
    If 33 bytes, read the final byte as compression flag,
    and return compressed/uncompressed public key as appropriate.'''
    compressed, priv = read_privkey(priv)
    #secp256k1 checks for validity of key value.
    if sys.version_info >= (3,0):
        newpriv = secp256k1.PrivateKey(secret=native_bytes(priv))
    else:
        newpriv = secp256k1.PrivateKey(secret=bytes_to_native_str(priv))
    return newpriv.public_key.format(compressed)

def privkey_to_pubkey(priv, usehex=True):
    '''To avoid changing the interface from the legacy system,
    allow an *optional* hex argument here (called differently from
    maker/taker code to how it's called in bip32 code), then
    pass to the standard hexbin decorator under the hood.
    '''
    return privkey_to_pubkey_inner(priv, usehex)

privtopub = privkey_to_pubkey

@hexbin
def is_valid_pubkey(pubkey, usehex, require_compressed=False):
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

@hexbin
def multiply(s, pub, usehex, rawpub=True, return_serialized=True):
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
    if sys.version_info >= (3,0):
        res = newpub.multiply(native_bytes(s))
    else:
        res = newpub.multiply(bytes_to_native_str(s))
    if not return_serialized:
        return res
    return res.format()

@hexbin
def add_pubkeys(pubkeys, usehex):
    '''Input a list of binary compressed pubkeys
    and return their sum as a binary compressed pubkey.'''
    pubkey_list = [secp256k1.PublicKey(x) for x in pubkeys]
    r = secp256k1.PublicKey.combine_keys(pubkey_list)
    return r.format()

@hexbin
def add_privkeys(priv1, priv2, usehex):
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

@hexbin
def ecdsa_raw_sign(msg,
                   priv,
                   usehex,
                   rawpriv=True,
                   rawmsg=False,
                   usenonce=None,
                   formsg=False):
    '''Take the binary message msg and sign it with the private key
    priv.
    By default priv is just a 32 byte string, if rawpriv is false
    it is assumed to be hex encoded (note only works if usehex=False).
    If rawmsg is True, no sha256 hash is applied to msg before signing.
    In this case, msg must be a precalculated hash (256 bit).
    If rawmsg is False, the secp256k1 lib will hash the message as part
    of the ECDSA-SHA256 signing algo.
    If usenonce is not None, its value is passed to the secp256k1 library
    sign() function as the ndata value, which is then used in conjunction
    with a custom nonce generating function, such that the nonce used in the ECDSA
    sign algorithm is exactly that value (ndata there, usenonce here). 32 bytes.
    Return value: the calculated signature.'''
    if rawmsg and len(msg) != 32:
        raise Exception("Invalid hash input to ECDSA raw sign.")
    if rawpriv:
        compressed, p = read_privkey(priv)
        newpriv = secp256k1.PrivateKey(p)
    else:
        newpriv = secp256k1.PrivateKey.from_hex(priv)
    if formsg:
        sig = newpriv.sign_recoverable(msg)
        return sig
    #Donations, thus custom nonce, currently disabled, hence not covered.
    elif usenonce: #pragma: no cover
        raise NotImplementedError
        #if len(usenonce) != 32:
        #    raise ValueError("Invalid nonce passed to ecdsa_sign: " + str(
        #        usenonce))
        #nf = ffi.addressof(_noncefunc.lib, "nonce_function_rand")
        #ndata = ffi.new("char [32]", usenonce)
        #usenonce = (nf, ndata)
        #sig = newpriv.ecdsa_sign(msg, raw=rawmsg, custom_nonce=usenonce)
    else:
        #partial fix for secp256k1-transient not including customnonce;
        #partial because donations will crash on windows in the "if".
        if rawmsg:
            sig = newpriv.sign(msg, hasher=None)
        else:
            sig = newpriv.sign(msg)
    return sig

@hexbin
def ecdsa_raw_verify(msg, pub, sig, usehex, rawmsg=False):
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
    except:
        return False
    return retval

def estimate_tx_size(ins, outs, txtype='p2pkh'):
    '''Estimate transaction size.
    The txtype field as detailed below is used to distinguish
    the type, but there is at least one source of meaningful roughness:
    we assume the output types are the same as the input (to be fair,
    outputs only contribute a little to the overall total). This combined
    with a few bytes variation in signature sizes means we will expect,
    say, 10% inaccuracy here.

    Assuming p2pkh:
    out: 8+1+3+2+20=34, in: 1+32+4+1+1+~73+1+1+33=147,
    ver:4,seq:4, +2 (len in,out)
    total ~= 34*len_out + 147*len_in + 10 (sig sizes vary slightly)
    Assuming p2sh M of N multisig:
    "ins" must contain M, N so ins= (numins, M, N) (crude assuming all same)
    74*M + 34*N + 45 per input, so total ins ~ len_ins * (45+74M+34N)
    so total ~ 34*len_out + (45+74M+34N)*len_in + 10
    Assuming p2sh-p2wpkh:
    witness are roughly 3+~73+33 for each input
    (txid, vin, 4+20 for witness program encoded as scriptsig, 4 for sequence)
    non-witness input fields are roughly 32+4+4+20+4=64, so total becomes
    n_in * 64 + 4(ver) + 4(locktime) + n_out*34
    Assuming p2wpkh native:
    witness as previous case
    non-witness loses the 24 witnessprogram, replaced with 1 zero,
    in the scriptSig, so becomes:
    n_in * 41 + 4(ver) + 4(locktime) +2 (len in, out) + n_out*34
    '''
    if txtype == 'p2pkh':
        return 10 + ins * 147 + 34 * outs
    elif txtype == 'p2sh-p2wpkh':
        #return the estimate for the witness and non-witness
        #portions of the transaction, assuming that all the inputs
        #are of segwit type p2sh-p2wpkh
        # Note as of Jan19: this misses 2 bytes (trivial) for len in, out
        # and also overestimates output size by 2 bytes.
        witness_estimate = ins*109
        non_witness_estimate = 4 + 4 + outs*34 + ins*64
        return (witness_estimate, non_witness_estimate)
    elif txtype == 'p2wpkh':
        witness_estimate = ins*109
        non_witness_estimate = 4 + 4 + 2 + outs*31 + ins*41
        return (witness_estimate, non_witness_estimate)
    elif txtype == 'p2shMofN':
        ins, M, N = ins
        return 10 + (45 + 74*M + 34*N) * ins + 34 * outs
    else:
        raise NotImplementedError("Transaction size estimation not" +
                                  "yet implemented for type: " + txtype)
