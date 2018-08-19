#!/usr/bin/python
from __future__ import print_function
import binascii
import hashlib
import re
import sys
import base64
import secp256k1

#Required only for PoDLE calculation:
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
#Global context for secp256k1 operations (helps with performance)
ctx = secp256k1.lib.secp256k1_context_create(secp256k1.ALL_FLAGS)
#required for point addition
dummy_pub = secp256k1.PublicKey(ctx=ctx)

#Standard prefix for Bitcoin message signing.
BITCOIN_MESSAGE_MAGIC = '\x18' + 'Bitcoin Signed Message:\n'

if sys.version_info.major == 2:
    string_types = (str, unicode)
    string_or_bytes_types = string_types
    int_types = (int, float, long)

    # Base switching
    code_strings = {
        2: '01',
        10: '0123456789',
        16: '0123456789abcdef',
        32: 'abcdefghijklmnopqrstuvwxyz234567',
        58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
        256: ''.join([chr(x) for x in range(256)])
    }

    def bin_dbl_sha256(s):
        bytes_to_hash = from_string_to_bytes(s)
        return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()

    def lpad(msg, symbol, length):
        if len(msg) >= length:
            return msg
        return symbol * (length - len(msg)) + msg

    def get_code_string(base):
        if base in code_strings:
            return code_strings[base]
        else:
            raise ValueError("Invalid base!")

    def changebase(string, frm, to, minlen=0):
        if frm == to:
            return lpad(string, get_code_string(frm)[0], minlen)
        return encode(decode(string, frm), to, minlen)

    def bin_to_b58check(inp, magicbyte=0):
        inp_fmtd = chr(int(magicbyte)) + inp
        leadingzbytes = len(re.match('^\x00*', inp_fmtd).group(0))
        checksum = bin_dbl_sha256(inp_fmtd)[:4]
        return '1' * leadingzbytes + changebase(inp_fmtd + checksum, 256, 58)

    def bytes_to_hex_string(b):
        return b.encode('hex')

    def safe_from_hex(s):
        return s.decode('hex')

    def from_int_to_byte(a):
        return chr(a)

    def from_byte_to_int(a):
        return ord(a)

    def from_string_to_bytes(a):
        return a

    def safe_hexlify(a):
        return binascii.hexlify(a)

    def encode(val, base, minlen=0):
        base, minlen = int(base), int(minlen)
        code_string = get_code_string(base)
        result = ""
        while val > 0:
            result = code_string[val % base] + result
            val //= base
        return code_string[0] * max(minlen - len(result), 0) + result

    def decode(string, base):
        base = int(base)
        code_string = get_code_string(base)
        result = 0
        if base == 16:
            string = string.lower()
        while len(string) > 0:
            result *= base
            result += code_string.find(string[0])
            string = string[1:]
        return result

else:
    raise NotImplementedError("Only Python2 currently supported by btc interface") #pragma: no cover

"""PoDLE related primitives
"""
def getG(compressed=True):
    """Returns the public key binary
    representation of secp256k1 G
    """
    priv = "\x00"*31 + "\x01"
    G = secp256k1.PrivateKey(priv, ctx=ctx).pubkey.serialize(compressed)
    return G

podle_PublicKey_class = secp256k1.PublicKey
podle_PrivateKey_class = secp256k1.PrivateKey

def podle_PublicKey(P):
    """Returns a PublicKey object from a binary string
    """
    return secp256k1.PublicKey(P, raw=True, ctx=ctx)

def podle_PrivateKey(priv):
    """Returns a PrivateKey object from a binary string
    """
    return secp256k1.PrivateKey(priv, ctx=ctx)


def privkey_to_address(priv, from_hex=True, magicbyte=0):
    return pubkey_to_address(privkey_to_pubkey(priv, from_hex), magicbyte)

privtoaddr = privkey_to_address

# Hashes
def bin_hash160(string):
    intermed = hashlib.sha256(string).digest()
    return hashlib.new('ripemd160', intermed).digest()

def hash160(string):
    return safe_hexlify(bin_hash160(string))

def bin_sha256(string):
    binary_data = string if isinstance(string, bytes) else bytes(string,
                                                                 'utf-8')
    return hashlib.sha256(binary_data).digest()

def sha256(string):
    return bytes_to_hex_string(bin_sha256(string))

def bin_dbl_sha256(s):
    bytes_to_hash = from_string_to_bytes(s)
    return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()

def dbl_sha256(string):
    return safe_hexlify(bin_dbl_sha256(string))

def hash_to_int(x):
    if len(x) in [40, 64]:
        return decode(x, 16)
    return decode(x, 256)

def num_to_var_int(x):
    x = int(x)
    if x < 253: return from_int_to_byte(x)
    elif x < 65536: return from_int_to_byte(253) + encode(x, 256, 2)[::-1]
    elif x < 4294967296: return from_int_to_byte(254) + encode(x, 256, 4)[::-1]
    else: return from_int_to_byte(255) + encode(x, 256, 8)[::-1]

def message_sig_hash(message):
    """Used for construction of signatures of
    messages, intended to be compatible with Bitcoin Core.
    """
    padded = BITCOIN_MESSAGE_MAGIC + num_to_var_int(len(
        message)) + from_string_to_bytes(message)
    return bin_dbl_sha256(padded)

# Encodings
def b58check_to_bin(inp):
    leadingzbytes = len(re.match('^1*', inp).group(0))
    data = b'\x00' * leadingzbytes + changebase(inp, 58, 256)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return data[1:-4]

def get_version_byte(inp):
    leadingzbytes = len(re.match('^1*', inp).group(0))
    data = b'\x00' * leadingzbytes + changebase(inp, 58, 256)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return ord(data[0])

def hex_to_b58check(inp, magicbyte=0):
    return bin_to_b58check(binascii.unhexlify(inp), magicbyte)

def b58check_to_hex(inp):
    return safe_hexlify(b58check_to_bin(inp))

def pubkey_to_address(pubkey, magicbyte=0):
    if len(pubkey) in [66, 130]:
        return bin_to_b58check(
            bin_hash160(binascii.unhexlify(pubkey)), magicbyte)
    return bin_to_b58check(bin_hash160(pubkey), magicbyte)

pubtoaddr = pubkey_to_address

def wif_compressed_privkey(priv, vbyte=0):
    """Convert privkey in hex compressed to WIF compressed
    """
    if len(priv) != 66:
        raise Exception("Wrong length of compressed private key")
    if priv[-2:] != '01':
        raise Exception("Private key has wrong compression byte")
    return bin_to_b58check(binascii.unhexlify(priv), 128 + int(vbyte))


def from_wif_privkey(wif_priv, compressed=True, vbyte=0):
    """Convert WIF compressed privkey to hex compressed.
    Caller specifies the network version byte (0 for mainnet, 0x6f
    for testnet) that the key should correspond to; if there is
    a mismatch an error is thrown. WIF encoding uses 128+ this number.
    """
    bin_key = b58check_to_bin(wif_priv)
    claimed_version_byte = get_version_byte(wif_priv)
    if not 128+vbyte == claimed_version_byte:
        raise Exception(
            "WIF key version byte is wrong network (mainnet/testnet?)")
    if compressed and not len(bin_key) == 33:
        raise Exception("Compressed private key is not 33 bytes")
    if compressed and not bin_key[-1] == '\x01':
        raise Exception("Private key has incorrect compression byte")
    return safe_hexlify(bin_key)

def ecdsa_sign(msg, priv, formsg=False, usehex=True):
    hashed_msg = message_sig_hash(msg)
    if usehex:
        #arguments to raw sign must be consistently hex or bin
        hashed_msg = binascii.hexlify(hashed_msg)
    sig = ecdsa_raw_sign(hashed_msg, priv, usehex, rawmsg=True, formsg=formsg)
    #note those functions only handles binary, not hex
    if usehex:
        sig = binascii.unhexlify(sig)
    return base64.b64encode(sig)

def ecdsa_verify(msg, sig, pub, usehex=True):
    hashed_msg = message_sig_hash(msg)
    sig = base64.b64decode(sig)
    if usehex:
        #arguments to raw_verify must be consistently hex or bin
        hashed_msg = binascii.hexlify(hashed_msg)
        sig = binascii.hexlify(sig)
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
                    newargs += [[x.decode('hex') for x in arg]]
                else:
                    newargs += [arg.decode('hex')]
            newargs += [False]
            returnval = func(*newargs, **kwargs)
            if isinstance(returnval, bool):
                return returnval
            else:
                return binascii.hexlify(returnval)
        else:
            return func(*args, **kwargs)

    return func_wrapper

def read_privkey(priv):
    if len(priv) == 33:
        if priv[-1] == '\x01':
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
    newpriv = secp256k1.PrivateKey(privkey=priv, ctx=ctx)
    return newpriv.pubkey.serialize(compressed=compressed)

def privkey_to_pubkey(priv, usehex=True):
    '''To avoid changing the interface from the legacy system,
    allow an *optional* hex argument here (called differently from
    maker/taker code to how it's called in bip32 code), then
    pass to the standard hexbin decorator under the hood.
    '''
    return privkey_to_pubkey_inner(priv, usehex)

privtopub = privkey_to_pubkey

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
    newpub = secp256k1.PublicKey(pub, raw=rawpub, ctx=ctx)
    #see note to "tweak_mul" function in podle.py
    res = secp256k1._tweak_public(newpub,
                                   secp256k1.lib.secp256k1_ec_pubkey_tweak_mul,
                                   s)
    if not return_serialized:
        return res
    return res.serialize()

@hexbin
def add_pubkeys(pubkeys, usehex):
    '''Input a list of binary compressed pubkeys
    and return their sum as a binary compressed pubkey.'''
    r = secp256k1.PublicKey(ctx=ctx)  #dummy holding object
    pubkey_list = [secp256k1.PublicKey(x,
                                       raw=True,
                                       ctx=ctx).public_key for x in pubkeys]
    r.combine(pubkey_list)
    return r.serialize()

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
    p1 = secp256k1.PrivateKey(newpriv1, raw=True, ctx=ctx)
    res = p1.tweak_add(newpriv2)
    if compressed:
        res += '\x01'
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
        newpriv = secp256k1.PrivateKey(p, raw=True, ctx=ctx)
    else:
        newpriv = secp256k1.PrivateKey(priv, raw=False, ctx=ctx)
    if formsg:
        sig = newpriv.ecdsa_sign_recoverable(msg, raw=rawmsg)
        s, rid = newpriv.ecdsa_recoverable_serialize(sig)
        return chr(31+rid) + s
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
        sig = newpriv.ecdsa_sign(msg, raw=rawmsg)
    return newpriv.ecdsa_serialize(sig)

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
        newpub = secp256k1.PublicKey(pubkey=pub, raw=True, ctx=ctx)
        sigobj = newpub.ecdsa_deserialize(sig)
        retval = newpub.ecdsa_verify(msg, sigobj, raw=rawmsg)
    except:
        return False
    return retval

def estimate_tx_size(ins, outs, txtype='p2pkh'):
    '''Estimate transaction size.
    Assuming p2pkh:
    out: 8+1+3+2+20=34, in: 1+32+4+1+1+~73+1+1+33=147,
    ver:4,seq:4, +2 (len in,out)
    total ~= 34*len_out + 147*len_in + 10 (sig sizes vary slightly)
    Assuming p2sh M of N multisig:
    "ins" must contain M, N so ins= (numins, M, N) (crude assuming all same)
    74*M + 34*N + 45 per input, so total ins ~ len_ins * (45+74M+34N)
    so total ~ 34*len_out + (45+74M+34N)*len_in + 10
    '''
    if txtype == 'p2pkh':
        return 10 + ins * 147 + 34 * outs
    elif txtype == 'p2sh-p2wpkh':
        #return the estimate for the witness and non-witness
        #portions of the transaction, assuming that all the inputs
        #are of segwit type p2sh-p2wpkh
        #witness are roughly 3+~73+33 for each input
        #non-witness input fields are roughly 32+4+4+20+4=64, so total becomes
        #n_in * 64 + 4(ver) + 4(locktime) + n_out*34 + n_in * 109
        witness_estimate = ins*109
        non_witness_estimate = 4 + 4 + outs*34 + ins*64
        return (witness_estimate, non_witness_estimate)
    elif txtype == 'p2shMofN':
        ins, M, N = ins
        return 10 + (45 + 74*M + 34*N) * ins + 34 * outs
    else:
        raise NotImplementedError("Transaction size estimation not" +
                                  "yet implemented for type: " + txtype)
