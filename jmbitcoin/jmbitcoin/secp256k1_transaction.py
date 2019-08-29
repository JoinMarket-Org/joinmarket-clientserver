#!/usr/bin/python
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import *
from past.builtins import basestring
from io import BytesIO
import binascii
import copy
import re
import os
import struct
from jmbitcoin.secp256k1_main import *
from jmbitcoin.bech32 import *

P2PKH_PRE, P2PKH_POST = b'\x76\xa9\x14', b'\x88\xac'
P2SH_P2WPKH_PRE, P2SH_P2WPKH_POST = b'\xa9\x14', b'\x87'
P2WPKH_PRE = b'\x00\x14'
P2WSH_PRE = b'\x00\x16'

# Transaction serialization and deserialization

def read_as_int(bytez, tx):
    if bytez == 2:
        return struct.unpack(b'<H', ser_read(tx, 2))[0]
    elif bytez == 4:
        return struct.unpack(b'<I', ser_read(tx, 4))[0]
    elif bytez == 1:
        return struct.unpack(b'B', ser_read(tx, 1))[0]
    elif bytez == 8:
        return struct.unpack(b'<Q', ser_read(tx, 8))[0]
    else:
        raise SerializationError('Asked to read unsupported %x bytes; bytez can only be 1, 2, 4 or 8' % bytez)

def read_var_int(tx):
    val = from_byte_to_int(ser_read(tx, 1))
    if val < 253:
        return val
    return read_as_int(pow(2, val - 252), tx)

def read_var_string(tx):
    size = read_var_int(tx)
    return ser_read(tx, size)

def deserialize(txinp):
    if isinstance(txinp, basestring) and not isinstance(txinp, bytes):
        tx = BytesIO(binascii.unhexlify(txinp))
        hexout = True
    else:
        tx = BytesIO(txinp)
        hexout = False

    def hex_string(scriptbytes, hexout):
        if hexout:
            return binascii.hexlify(scriptbytes).decode('ascii')
        else:
            return scriptbytes

    def read_flag_byte(val):
        last = tx.tell()
        flag = ser_read(tx, 1)
        if from_byte_to_int(flag)==val:
            return True
        else:
            tx.seek(last)
            return False

    obj = {"ins": [], "outs": []}
    obj["version"] = read_as_int(4, tx)
    segwit = False
    if read_flag_byte(0): segwit = True
    if segwit:
        if not read_flag_byte(1):
            #BIP141 is currently "MUST" ==1
            #A raise is a DOS vector in some contexts
            return None

    ins = read_var_int(tx)
    for i in range(ins):
        obj["ins"].append({
            "outpoint": {
                "hash": hex_string(ser_read(tx, 32)[::-1], hexout),
                "index": read_as_int(4, tx)
            },
            #TODO this will probably crap out on null for segwit
            "script": hex_string(read_var_string(tx), hexout),
            "sequence": read_as_int(4, tx)
        })
    outs = read_var_int(tx)
    for i in range(outs):
        obj["outs"].append({
            "value": read_as_int(8, tx),
            "script": hex_string(read_var_string(tx), hexout)
        })
    #segwit flag is only set if at least one txinwitness exists,
    #in other words it would have to be at least partially signed;
    #and, if it is, the witness section must be properly created
    #including "00" for any input that either does not YET or will not
    #have a witness attached.
    if segwit:
        #read witness data
        #there must be one witness object for each txin
        #technically, we could parse the contents of the witness
        #into objects, but we'll just replicate the behaviour of the
        #rpc decoderawtx, and attach a "txinwitness" for each in, with
        #the items in the witness space separated
        for i in range(ins):
            num_items = read_var_int(tx)
            items = []
            for ni in range(num_items):
                items.append(hex_string(read_var_string(tx), hexout))
            obj["ins"][i]["txinwitness"] = items

    obj["locktime"] = read_as_int(4, tx)
    return obj

def serialize(tx):
    """ Accepts a dict in which the "outpoint","hash"
    "script" and "txinwitness" entries can be in binary
    or hex. If any "hash" field is in hex, the serialized
    output is in hex, otherwise the serialization output
    is in binary. Below table assumes all hex.
    Table of dictionary keys and type for the value:
    ================================================
    version: int
    ins: list
    ins[0]["outpoint"]["hash"]: hex encoded string
    ins[0]["outpoint"]["index"]: int
    ins[0]["script"]: hex encoded string
    ins[0]["sequence"]: int
    ins[0]["txinwitness"]: list (optional, may not exist)
    ins[0]["txinwitness"][0]: hex encoded string
    outs: list
    outs[0]["script"]: hex encoded string
    outs[0]["value"]: int
    locktime: int
    =================================================
    Returned serialized transaction is a byte string,
    or a hex encoded string, according to the above
    hash check.
    """
    #Because we are manipulating the dict in-place, need
    #to work on a copy
    txobj = copy.deepcopy(tx)
    o = BytesIO()
    hexout = False
    o.write(struct.pack(b'<I', txobj["version"]))
    segwit = False
    if any("txinwitness" in x for x in txobj["ins"]):
        segwit = True
    if segwit:
        #append marker and flag
        o.write(b'\x00')
        o.write(b'\x01')
    o.write(num_to_var_int(len(txobj["ins"])))
    for inp in txobj["ins"]:
        if len(inp["outpoint"]["hash"]) == 64:
            o.write(binascii.unhexlify(inp["outpoint"]["hash"])[::-1])
            hexout = True
        elif len(inp["outpoint"]["hash"]) == 32:
            o.write(inp["outpoint"]["hash"][::-1])
        else:
            raise SerializationError('Hash has unsupported length: %x bytes; must be 64 or 32 bytes' % len(inp["outpoint"]["hash"]))
        o.write(struct.pack(b'<I', inp["outpoint"]["index"]))
        if len(inp["script"]) == 0:
            o.write(b'\x00')
        elif isinstance(inp["script"], basestring) and not isinstance(inp["script"], bytes):
            o.write(num_to_var_int(len(binascii.unhexlify(inp["script"]))))
            o.write(binascii.unhexlify(inp["script"]))
        else:
            o.write(num_to_var_int(len(inp["script"])))
            o.write(inp["script"])
        o.write(struct.pack(b'<I', inp["sequence"]))
    o.write(num_to_var_int(len(txobj["outs"])))
    for out in txobj["outs"]:
        o.write(struct.pack(b'<Q', out["value"]))
        if len(out["script"]) == 0:
            o.write(b'\x00')
        elif isinstance(out["script"], basestring) and not isinstance(out["script"], bytes):
            o.write(num_to_var_int(len(binascii.unhexlify(out["script"]))))
            o.write(binascii.unhexlify(out["script"]))
        else:
            o.write(num_to_var_int(len(out["script"])))
            o.write(out["script"])
    if segwit:
        #number of witnesses is not explicitly encoded;
        #it's implied by txin length
        for inp in txobj["ins"]:
            if "txinwitness" not in inp:
                o.write(b'\x00')
                continue
            items = inp["txinwitness"]
            o.write(num_to_var_int(len(items)))
            for item in items:
                if item is None:
                    o.write(b'\x00')
                    continue
                if isinstance(item, basestring) and not isinstance(item, bytes):
                    item = binascii.unhexlify(item)
                o.write(num_to_var_int(len(item)) + item)
    o.write(struct.pack(b'<I', txobj["locktime"]))

    if hexout:
        return binascii.hexlify(o.getvalue()).decode('ascii')
    else:
        return o.getvalue()

# Hashing transactions for signing

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80

def segwit_signature_form(txobj, i, script, amount, hashcode=SIGHASH_ALL,
                          decoder_func=binascii.unhexlify):
    """ Given a deserialized transaction txobj, an input index i,
    which spends from a witness,
    a script for redemption and an amount in satoshis, prepare
    the version of the transaction to be hashed and signed.
    """
    #if isinstance(txobj, string_or_bytes_types):
    #    return serialize(segwit_signature_form(deserialize(txobj), i, script,
    #                                           amount, hashcode))
    script = decoder_func(script)
    nVersion = struct.pack(b'<I', txobj["version"])
    if not isinstance(hashcode, int):
        hashcode = struct.unpack(b'B', hashcode)[0]
    #create hashPrevouts
    if hashcode & SIGHASH_ANYONECANPAY:
        hashPrevouts = b"\x00"*32
    else:
        pi = b""
        for inp in txobj["ins"]:
            pi += decoder_func(inp["outpoint"]["hash"])[::-1]
            pi += struct.pack(b'<I', inp["outpoint"]["index"])
        hashPrevouts = bin_dbl_sha256(pi)
    #create hashSequence
    if not hashcode & SIGHASH_ANYONECANPAY and not (
        hashcode & 0x1f == SIGHASH_SINGLE) and not (hashcode & 0x1f == SIGHASH_NONE):
        pi = b""
        for inp in txobj["ins"]:
            pi += struct.pack(b'<I', inp["sequence"])
        hashSequence = bin_dbl_sha256(pi)
    else:
        hashSequence = b"\x00"*32
    #add this input's outpoint
    thisOut = decoder_func(txobj["ins"][i]["outpoint"]["hash"])[::-1]
    thisOut += struct.pack(b'<I', txobj["ins"][i]["outpoint"]["index"])
    scriptCode = num_to_var_int(len(script)) + script
    amt = struct.pack(b'<Q', amount)
    thisSeq = struct.pack(b'<I', txobj["ins"][i]["sequence"])
    #create hashOutputs
    if not (hashcode & 0x1f == SIGHASH_SINGLE) and not (hashcode & 0x1f == SIGHASH_NONE):
        pi = b""
        for out in txobj["outs"]:
            pi += struct.pack(b'<Q', out["value"])
            pi += (num_to_var_int(len(decoder_func(out["script"]))) + \
                   decoder_func(out["script"]))
        hashOutputs = bin_dbl_sha256(pi)
    elif hashcode & 0x1f == SIGHASH_SINGLE and i < len(txobj['outs']):
        pi = struct.pack(b'<Q', txobj["outs"][i]["value"])
        pi += (num_to_var_int(len(decoder_func(txobj["outs"][i]["script"]))) +
               decoder_func(txobj["outs"][i]["script"]))
        hashOutputs = bin_dbl_sha256(pi)
    else:
        hashOutputs = b"\x00"*32
    nLockTime = struct.pack(b'<I', txobj["locktime"])
    return nVersion + hashPrevouts + hashSequence + thisOut + scriptCode + amt + \
           thisSeq + hashOutputs + nLockTime

def signature_form(tx, i, script, hashcode=SIGHASH_ALL):
    if not isinstance(hashcode, int):
        hashcode = struct.unpack(b'B', hashcode)[0]
    if isinstance(tx, basestring) and not isinstance(tx, bytes):
        tx = deserialize(tx)
    elif isinstance(tx, basestring):
        tx = deserialize(binascii.hexlify(tx).decode('ascii'))
    if isinstance(script, basestring) and isinstance(script, bytes):
        script = binascii.hexlify(script).decode('ascii')
    newtx = copy.deepcopy(tx)
    for inp in newtx["ins"]:
        #If tx is passed in in segwit form, it must be switched to non-segwit.
        if "txinwitness" in inp:
            del inp["txinwitness"]
        inp["script"] = ""
    newtx["ins"][i]["script"] = script
    if hashcode & 0x1f == SIGHASH_NONE:
        newtx["outs"] = []
        for j, inp in enumerate(newtx["ins"]):
            if j != i:
                inp["sequence"] = 0
    elif hashcode & 0x1f == SIGHASH_SINGLE:
        if len(newtx["ins"]) > len(newtx["outs"]):
            raise Exception(
                "Transactions with sighash single should have len in <= len out")
        newtx["outs"] = newtx["outs"][:i+1]
        for out in newtx["outs"][:i]:
            out['value'] = 2**64 - 1
            out['script'] = ""
        for j, inp in enumerate(newtx["ins"]):
            if j != i:
                inp["sequence"] = 0
    if hashcode & SIGHASH_ANYONECANPAY:
        newtx["ins"] = [newtx["ins"][i]]
    else:
        pass
    return newtx

def segwit_txid(tx, hashcode=None):
    #An easy way to construct the old-style hash (which is the real txid,
    #the one without witness or marker/flag, is to remove all txinwitness
    #entries from the deserialized form of the full tx, then reserialize,
    #because serialize uses that as a flag to decide which serialization
    #style to apply.
    dtx = deserialize(tx)
    for vin in dtx["ins"]:
        if "txinwitness" in vin:
            del vin["txinwitness"]
            reserialized_tx = serialize(dtx)
    return txhash(reserialized_tx, hashcode)

def txhash(tx, hashcode=None, check_sw=True):
    """ Creates the appropriate sha256 hash as required
    either for signing or calculating txids.
    The hashcode argument is used to distinguish the case
    where we are hashing for signing (sighashing); by default
    it is None, and this indicates we are calculating a txid.
    If check_sw is True it checks the serialized format for
    segwit flag bytes, and produces the correct form for txid (not wtxid).
    """
    if not isinstance(tx, basestring):
        tx = serialize(tx)
    if isinstance(tx, basestring) and not isinstance(tx, bytes):
        tx = binascii.unhexlify(tx)
    if check_sw and from_byte_to_int(tx[4:5]) == 0:
        if not from_byte_to_int(tx[5:6]) == 1:
            #This invalid, but a raise is a DOS vector in some contexts.
            return None
        return segwit_txid(tx, hashcode)
    if hashcode:
        if not isinstance(hashcode, int):
            hashcode = struct.unpack(b'B', hashcode)[0]
        return dbl_sha256(from_string_to_bytes(tx) + struct.pack(b'<I', hashcode))
    else:
        return safe_hexlify(bin_dbl_sha256(tx)[::-1])


def bin_txhash(tx, hashcode=None):
    return binascii.unhexlify(txhash(tx, hashcode))


def ecdsa_tx_sign(tx, priv, hashcode=SIGHASH_ALL, usenonce=None):
    sig = ecdsa_raw_sign(
        txhash(tx, hashcode, check_sw=False),
        priv,
        True,
        rawmsg=True,
        usenonce=usenonce)
    return sig + encode(hashcode, 16, 2)


def ecdsa_tx_verify(tx, sig, pub, hashcode=SIGHASH_ALL):
    return ecdsa_raw_verify(
        txhash(tx, hashcode, check_sw=False),
        pub,
        sig[:-2],
        True,
        rawmsg=True)

# Scripts

def mk_pubkey_script(addr):
    return '76a914' + b58check_to_hex(addr) + '88ac'


def mk_scripthash_script(addr):
    return 'a914' + b58check_to_hex(addr) + '87'

def segwit_scriptpubkey(witver, witprog):
    """ Construct a Segwit scriptPubKey for a given witness program.
    """
    return bytes([witver + 0x50 if witver else 0, len(witprog)] + witprog)

def mk_native_segwit_script(hrp, addr):
    """ Returns scriptPubKey as hex encoded string,
    given a valid bech32 address and human-readable-part,
    else throws an Exception if the arguments do not
    match this pattern.
    """
    ver, prog =  bech32addr_decode(hrp, addr)
    if ver is None:
        # This error cannot occur if this function is
        # called from `address_to_script`
        raise Exception("Invalid native segwit script")
    scriptpubkey = segwit_scriptpubkey(ver, prog)
    return binascii.hexlify(scriptpubkey).decode('ascii')

# Address representation to output script

def address_to_script(addr):
    """ Returns scriptPubKey as a hex-encoded string for
    a given Bitcoin address.
    """
    x = bech32_decode(addr)
    # Any failure (because it's not a bech32 address)
    # returns (None, None)
    if x[0] and x[1]:
        return mk_native_segwit_script(x[0], addr)

    if addr[0] == '3' or addr[0] == '2':
        return mk_scripthash_script(addr)
    else:
        return mk_pubkey_script(addr)

# Output script to address representation

def is_p2pkh_script(script):
    """ Given a script as bytes, returns True if the script
    matches the pay-to-pubkey-hash pattern (using opcodes),
    otherwise returns False.
    """
    if not isinstance(script, bytes):
        script = binascii.unhexlify(script)
    if script[:3] == P2PKH_PRE and script[-2:] == P2PKH_POST and len(
            script) == 25:
        return True
    return False

def is_segwit_native_script(script):
    """Is script, as bytes, of form P2WPKH or P2WSH;
    see BIP141 for definitions of 2 current valid scripts.
    """
    if not isinstance(script, bytes):
        script = binascii.unhexlify(script)

    if (script[:2] == P2WPKH_PRE and len(script) == 22) or (
        script[:2] == P2WSH_PRE and len(script) == 34):
        return True
    return False

def script_to_address(script, vbyte=b'\x00', witver=0):
    """ Given a hex or bytes script, and optionally a version byte
    (for P2SH) and/or a witness version (for native segwit witness
    programs), convert to a valid address (either bech32 or Base58CE).
    An important tacit assumption: anything which does not match
    the parsing rules of native segwit, or pay-to-pubkey-hash, is
    assumed to be p2sh.
    Note also that this translates scriptPubKeys to addresses, not
    redeemscripts to p2sh addresses; for that, use p2sh_scriptaddr.
    """
    if not isinstance(script, bytes):
        script = binascii.unhexlify(script)
    if is_segwit_native_script(script):
        #hrp interpreted from the vbyte entry, TODO: better way?
        if vbyte in [b'\x00', b'\x05']:
            hrp = 'bc'
        elif vbyte == 100:
            hrp = 'bcrt'
        else:
            hrp = 'tb'
        return bech32addr_encode(hrp=hrp, witver=witver,
        witprog=struct.unpack('{}B'.format(len(script[2:])).encode(
            'ascii'), script[2:]))
    if is_p2pkh_script(script):
        return bin_to_b58check(script[3:-2], vbyte)
    else:
        # BIP0016 scripthash addresses: requires explicit vbyte set
        if vbyte == b'\x00': raise Exception("Invalid version byte for P2SH")
        return bin_to_b58check(script[2:-1], vbyte)

def pubkey_to_script(pubkey, script_pre, script_post=b'',
                     require_compressed=False):
    """ Generic conversion from a binary pubkey serialization
    to a corresponding binary scriptPubKey for the pubkeyhash case.
    """
    if not is_valid_pubkey(pubkey, False,
                           require_compressed=require_compressed):
        raise Exception("Invalid pubkey.")
    h = bin_hash160(pubkey)
    assert len(h) == 0x14
    assert script_pre[-1:] == b'\x14'
    return script_pre + h + script_post

def p2sh_scriptaddr(script, magicbyte=5):
    if not isinstance(script, bytes):
        script = binascii.unhexlify(script)
    return hex_to_b58check(hash160(script), magicbyte)

def pubkey_to_p2pkh_script(pub, require_compressed=False):
    """ Construct a pay-to-pubkey-hash scriptPubKey
    given a single pubkey. Script returned in binary.
    The require compressed flag may be used to disallow
    uncompressed keys, e.g. in constructing a segwit
    scriptCode field.
    """
    if not isinstance(pub, bytes):
        pub = binascii.unhexlify(pub)
    return pubkey_to_script(pub, P2PKH_PRE, P2PKH_POST)

def pubkey_to_p2sh_p2wpkh_script(pub):
    """ Construct a nested-pay-to-witness-pubkey-hash
    scriptPubKey given a single pubkey.
    Script returned in binary.
    """
    if not isinstance(pub, bytes):
        pub = binascii.unhexlify(pub)
    wscript = pubkey_to_p2wpkh_script(pub)
    return P2SH_P2WPKH_PRE + bin_hash160(wscript) + P2SH_P2WPKH_POST

def pubkey_to_p2sh_p2wpkh_address(pub, magicbyte=5):
    """ Construct a nested-pay-to-witness-pubkey-hash
    address given a single pubkey; magicbyte defines
    network as for any p2sh address.
    """    
    if not isinstance(pub, bytes):
        pub = binascii.unhexlify(pub)
    script = pubkey_to_p2wpkh_script(pub)
    return p2sh_scriptaddr(script, magicbyte=magicbyte)

def pubkey_to_p2wpkh_script(pub):
    """ Construct a pay-to-witness-pubkey-hash
    scriptPubKey given a single pubkey. Note that
    this is the witness program (version 0). Script
    is returned in binary.
    """
    if not isinstance(pub, bytes):
        pub = binascii.unhexlify(pub)
    return pubkey_to_script(pub, P2WPKH_PRE,
                            require_compressed=True)

def pubkey_to_p2wpkh_address(pub):
    """ Construct a pay-to-witness-pubkey-hash
    address (bech32) given a single pubkey.
    """    
    script = pubkey_to_p2wpkh_script(pub)
    return script_to_address(script)

def pubkeys_to_p2wsh_script(pubs):
    """ Given a list of N pubkeys, constructs an N of N
    multisig scriptPubKey of type pay-to-witness-script-hash.
    No other scripts than N-N multisig supported as of now.
    """
    N = len(pubs)
    script = mk_multisig_script(pubs, N)
    return P2WSH_PRE + bin_sha256(binascii.unhexlify(script))

def pubkeys_to_p2wsh_address(pubs):
    """ Given a list of N pubkeys, constructs an N of N
    multisig address of type pay-to-witness-script-hash.
    No other scripts than N-N multisig supported as of now.
    """
    script = pubkeys_to_p2wsh_script(pubs)
    return script_to_address(script)

def deserialize_script(scriptinp):
    """ Note that this is not used internally, in
    the jmbitcoin package, to deserialize() transactions;
    its function is only to allow parsing of scripts by
    external callers. Thus, it returns in the format used
    outside the package: a deserialized script is a list of
    entries which can be any of:
    None
    integer
    hex string
    """
    def hex_string(scriptbytes, hexout):
        if hexout:
            return binascii.hexlify(scriptbytes).decode('ascii')
        else:
            return scriptbytes

    if isinstance(scriptinp, basestring):
        script = BytesIO(binascii.unhexlify(scriptinp))
        hexout = True
    else:
        script = BytesIO(scriptinp)
        hexout = False
    script.seek(0, os.SEEK_END)
    length = script.tell()
    script.seek(0, os.SEEK_SET)
    out = []
    while script.tell() < length:
        code = from_byte_to_int(ser_read(script, 1))
        if code == 0:
            out.append(None)
        elif code <= 75:
            out.append(hex_string(ser_read(script, code), hexout))
        elif code <= 78:
            if code == 78:
                sz = struct.unpack(b'<I', ser_read(script, 4))[0]
            elif code == 77:
                sz = struct.unpack(b'<H', ser_read(script, 2))[0]
            elif code == 76:
                sz = struct.unpack(b'<B', ser_read(script, 1))[0]
            else:
                sz = code
            out.append(hex_string(ser_read(script, sz), hexout))
        elif code <= 96:
            out.append(code - 80)
        else:
            out.append(code)
    return out


def serialize_script_unit(unit):
    if isinstance(unit, int):
        if unit < 16:
            return from_int_to_byte(unit + 80)
        else:
            return from_int_to_byte(unit)
    elif unit is None:
        return b'\x00'
    else:
        if isinstance(unit, basestring) and not isinstance(unit, bytes):
            unit = binascii.unhexlify(unit)
        if len(unit) <= 75:
            return from_int_to_byte(len(unit)) + unit
        elif len(unit) < 256:
            return from_int_to_byte(76) + struct.pack(b'<B', len(unit)) + unit
        elif len(unit) < 65536:
            return from_int_to_byte(77) + struct.pack(b'<H', len(unit)) + unit
        else:
            return from_int_to_byte(78) + struct.pack(b'<I', len(unit)) + unit


def serialize_script(script):
    result = b''
    hexout = True
    for b in script:
        if isinstance(b, basestring) and isinstance(b, bytes):
            hexout = False
        result += serialize_script_unit(b)
    if hexout:
        return binascii.hexlify(result).decode('ascii')
    else:
        return result


def mk_multisig_script(pubs, k):
    """ Given a list of pubkeys and an integer k,
    construct a multisig script for k of N, where N is
    the length of the list `pubs`; script is returned
    as hex string.
    """
    return serialize_script([k] + pubs + [len(pubs)]) + 'ae'


# Signing and verifying

def verify_tx_input(tx, i, script, sig, pub, scriptCode=None, amount=None):
    """ Given a hex-serialized transaction tx, an integer index i,
    a script (see more on this below), signature and pubkey, and optionally
    a segwit scriptCode and  amount in satoshis (that flags segwit usage),
    we return True if and only if the signature and pubkey is valid for
    this tx input.
    Note on 'script' and 'scriptCode':
    For p2pkh, 'script' should be the output script (scriptPubKey), and
    the scriptCode should be left as the default None.
    For p2sh non-segwit multisig, the script should be the
    output of mk_multisig_script (and scriptCode and amount None).
    For either nested (p2sh) or not p2wpkh and p2wsh, the scriptCode is the
    preimage of the scriptPubKey hash (the witness program, which here
    has been passed in in the 'script' parameter).

    Note that for the p2sh-p2wsh and p2wsh cases, a redeem script that is not
    multisig should still be correctly handled here; the codebase restricts
    the creation of such signatures to multisig only, but *verification* should
    function correctly with any custom script.

    TODO: Also note that the OP_CODESEPARATOR special case outlined in BIP143
    is not yet covered.
    """
    assert isinstance(i, int)
    assert i >= 0
    if not isinstance(tx, bytes):
        tx = binascii.unhexlify(tx)
    if not isinstance(script, bytes):
        script = binascii.unhexlify(script)
    if scriptCode is not None and not isinstance(scriptCode, bytes):
        scriptCode = binascii.unhexlify(scriptCode)
    if isinstance(sig, bytes):
        sig = binascii.hexlify(sig).decode('ascii')
    if isinstance(pub, bytes):
        pub = binascii.hexlify(pub).decode('ascii')

    hashcode = binascii.unhexlify(sig[-2:])

    if amount:
        modtx = segwit_signature_form(deserialize(tx), i,
                    scriptCode, amount, hashcode, decoder_func=lambda x: x)
    else:
        modtx = signature_form(tx, i, script, hashcode)
    return ecdsa_tx_verify(modtx, sig, pub, hashcode)


def sign(tx, i, priv, hashcode=SIGHASH_ALL, usenonce=None, amount=None,
         native=False):
    """
    Given a serialized transaction tx, an input index i, and a privkey
    in bytes or hex, returns a serialized transaction, in hex always,
    into which the signature and/or witness has been inserted. The field
    `amount` flags whether segwit signing is to be done, and the field
    `native` flags that native segwit p2wpkh signing is to be done. Note
    that signing multisig is to be done with the alternative functions
    multisign or p2wsh_multisign (and non N of N multisig scripthash
    signing is not currently supported).
    """
    if isinstance(tx, basestring) and not isinstance(tx, bytes):
        tx = binascii.unhexlify(tx)
    if len(priv) <= 33:
        priv = safe_hexlify(priv)
    if amount:
        serobj = p2wpkh_sign(tx, i, priv, amount, hashcode=hashcode,
                               usenonce=usenonce, native=native)
    else:
        pub = privkey_to_pubkey(priv, True)
        address = pubkey_to_address(pub)
        signing_tx = signature_form(tx, i, mk_pubkey_script(address), hashcode)
        sig = ecdsa_tx_sign(signing_tx, priv, hashcode, usenonce=usenonce)
        txobj = deserialize(tx)
        txobj["ins"][i]["script"] = serialize_script([sig, pub])
        serobj = serialize(txobj)
    if isinstance(serobj, basestring) and isinstance(serobj, bytes):
        return binascii.hexlify(serobj).decode('ascii')
    else:
        return serobj

def p2wpkh_sign(tx, i, priv, amount, hashcode=SIGHASH_ALL, native=False,
                usenonce=None):
    """Given a serialized transaction, index, private key in hex,
    amount in satoshis and optionally hashcode, return the serialized
    transaction containing a signature and witness for this input; it's
    assumed that the input is of type pay-to-witness-pubkey-hash.
    If native is False, it's treated as p2sh nested.
    """
    pub = privkey_to_pubkey(priv)
    # Convert the input tx and script to hex so that the deserialize()
    # call creates hex-encoded fields
    script = binascii.hexlify(pubkey_to_p2wpkh_script(pub)).decode('ascii')
    scriptCode = binascii.hexlify(pubkey_to_p2pkh_script(pub)).decode('ascii')
    if isinstance(tx, bytes):
        tx = binascii.hexlify(tx).decode('ascii')
    signing_tx = segwit_signature_form(deserialize(tx), i, scriptCode, amount,
                                       hashcode=hashcode)
    sig = ecdsa_tx_sign(signing_tx, priv, hashcode, usenonce=usenonce)
    txobj = deserialize(tx)
    if not native:
        txobj["ins"][i]["script"] = "16" + script
    else:
        txobj["ins"][i]["script"] = ""
    txobj["ins"][i]["txinwitness"] = [sig, pub]
    return serialize(txobj)

def signall(tx, priv):
    # if priv is a dictionary, assume format is
    # { 'txinhash:txinidx' : privkey }
    if isinstance(priv, dict):
        for e, i in enumerate(deserialize(tx)["ins"]):
            k = priv["%s:%d" % (i["outpoint"]["hash"], i["outpoint"]["index"])]
            tx = sign(tx, e, k)
    else:
        for i in range(len(deserialize(tx)["ins"])):
            tx = sign(tx, i, priv)
    return tx


def multisign(tx, i, script, pk, amount=None, hashcode=SIGHASH_ALL):
    """ Tx is assumed to be serialized. The script passed here is
    the redeemscript, for example the output of mk_multisig_script.
    pk is the private key, and must be passed in hex.
    If amount is not None, the output of p2wsh_multisign is returned.
    What is returned is a single signature.
    """
    if isinstance(tx, str):
        tx = binascii.unhexlify(tx)
    if isinstance(script, str):
        script = binascii.unhexlify(script)
    if amount:
        return p2wsh_multisign(tx, i, script, pk, amount, hashcode)
    modtx = signature_form(tx, i, script, hashcode)
    return ecdsa_tx_sign(modtx, pk, hashcode)

def p2wsh_multisign(tx, i, script, pk, amount, hashcode=SIGHASH_ALL):
    """ See note to multisign for the value to pass in as `script`.
    Tx is assumed to be serialized.
    """
    modtx = segwit_signature_form(deserialize(tx), i, script, amount,
                                  hashcode, decoder_func=lambda x: x)
    return ecdsa_tx_sign(modtx, pk, hashcode)

def apply_p2wsh_multisignatures(tx, i, script, sigs):
    """Sigs must be passed in as a list, and must be a
    complete list for this multisig, in the same order
    as the list of pubkeys when creating the scriptPubKey.
    """
    if isinstance(script, str):
        script = binascii.unhexlify(script)
    sigs = [binascii.unhexlify(x) if x[:2] == '30' else x for x in sigs]
    if isinstance(tx, str):
        return safe_hexlify(apply_p2wsh_multisignatures(
            binascii.unhexlify(tx), i, script, sigs))
    txobj = deserialize(tx)
    txobj["ins"][i]["script"] = ""
    txobj["ins"][i]["txinwitness"] = [None] + sigs + [script]
    return serialize(txobj)

def apply_multisignatures(*args):
    # tx,i,script,sigs OR tx,i,script,sig1,sig2...,sig[n]
    tx, i, script = args[0], int(args[1]), args[2]
    sigs = args[3] if isinstance(args[3], list) else list(args[3:])

    if isinstance(script, str):
        script = binascii.unhexlify(script)
    sigs = [binascii.unhexlify(x) if x[:2] == '30' else x for x in sigs]
    if isinstance(tx, str):
        return safe_hexlify(apply_multisignatures(
            binascii.unhexlify(tx), i, script, sigs))

    txobj = deserialize(tx)
    txobj["ins"][i]["script"] = serialize_script([None] + sigs + [script])
    return serialize(txobj)

def mktx(ins, outs, version=1, locktime=0):
    """ Given a list of input dicts with key "output"
    which are txid:n strings in hex, and a list of outputs
    which are dicts with keys "address", "value", outputs
    a hex serialized tranasction encoding this data.
    Tx version and locktime are optionally set, for non-default
    locktimes, inputs are given nSequence as per below comment.
    """
    txobj = {"locktime": locktime, "version": version, "ins": [], "outs": []}
    # This does NOT trigger rbf and mimics Core's standard behaviour as of
    # Jan 2019.
    # Tx creators wishing to use rbf will need to set it explicitly outside
    # of this function.
    if locktime != 0:
        sequence = 0xffffffff - 1
    else:
        sequence = 0xffffffff
    for i in ins:
        if isinstance(i, dict) and "outpoint" in i:
            txobj["ins"].append(i)
        else:
            if isinstance(i, dict) and "output" in i:
                i = i["output"]
            txobj["ins"].append({
                "outpoint": {"hash": i[:64],
                             "index": int(i[65:])},
                "script": "",
                "sequence": sequence
            })
    for o in outs:
        if isinstance(o, str):
            addr = o[:o.find(':')]
            val = int(o[o.find(':') + 1:])
            o = {}
            if re.match('^[0-9a-fA-F]*$', addr):
                o["script"] = addr
            else:
                o["address"] = addr
            o["value"] = val

        outobj = {}
        if "address" in o:
            outobj["script"] = address_to_script(o["address"])
        elif "script" in o:
            outobj["script"] = o["script"]
        else:
            raise Exception("Could not find 'address' or 'script' in output.")
        outobj["value"] = o["value"]
        txobj["outs"].append(outobj)
    return serialize(txobj)

def bip69_sort(tx):
    """ See https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki
    Given a deserialized transaction, return a reordered deserialized
    transaction according to BIP69. The original tx is unchanged.
    Note: it is the responsibility of the caller to ensure that the outputs
    have "script" entries and not (only) "address" entries (which mktx does
    by default, so this will usually not be an issue).
    """
    new_tx = copy.deepcopy(tx)
    new_tx["ins"].sort(key = lambda i: (i["outpoint"]["hash"], i["outpoint"]["index"]))
    new_tx["outs"].sort(key = lambda o: (o["value"], o["script"]))
    return new_tx