#!/usr/bin/python
import binascii, re, copy, sys
from jmbitcoin.secp256k1_main import *
from functools import reduce
import os

# =============================================
# Transaction serialization and deserialization
# =============================================

def serialize(tx):
    """Assumes a deserialized transaction in which all
    dictionary values are decoded hex strings or numbers.
    Rationale: mixing raw bytes/hex/strings in dict objects causes
    complexity; since the dict tx object has to be inspected
    in this function, avoid complicated logic elsewhere by making
    all conversions to raw byte strings happen here.
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

    Returned serialized transaction is a byte string.
    """
    #Because we are manipulating the dict in-place, need
    #to work on a copy
    txobj = copy.deepcopy(tx)
    o = bytes()
    o += encode(txobj["version"], 256, 4)[::-1]
    segwit = False
    if any("txinwitness" in list(x) for x in txobj["ins"]):
        segwit = True
    if segwit:
        #append marker and flag
        o += b'\x00'
        o += b'\x01'
    o += num_to_var_int(len(txobj["ins"]))
    for inp in txobj["ins"]:
        o += binascii.unhexlify(inp["outpoint"]["hash"])[::-1]
        o += encode(inp["outpoint"]["index"], 256, 4)[::-1]
        inp["script"] = binascii.unhexlify(inp["script"])
        o += num_to_var_int(len(inp["script"])) + (inp["script"] if inp[
            "script"] else bytes())
        o += encode(inp["sequence"], 256, 4)[::-1]
    o += num_to_var_int(len(txobj["outs"]))
    for out in txobj["outs"]:
        o += encode(out["value"], 256, 8)[::-1]
        out["script"] = binascii.unhexlify(out["script"])
        o += num_to_var_int(len(out["script"])) + out["script"]
    if segwit:
        #number of witnesses is not explicitly encoded;
        #it's implied by txin length
        for inp in txobj["ins"]:
            if "txinwitness" not in list(inp):
                o += b'\x00'
                continue
            items = inp["txinwitness"]
            o += num_to_var_int(len(items))
            for item in items:
                item = binascii.unhexlify(item)
                o += num_to_var_int(len(item)) + item
    o += encode(txobj["locktime"], 256, 4)[::-1]

    return o

def deserialize(tx):
    """Input tx is assumed always to be a byte string,
    so deserialize(serialize(x)) == x.

    Returns None for an invalid transaction (TODO: check all cases)
    Returns a dict of the form described in the comment for
    `serialize` function, if valid.
    """
    pos = [0]
    #Helper functions for decoding sections;
    #TODO: these are disgustingly ignorant of overrun errors!
    def read_as_int(bytez):
        pos[0] += bytez
        return decode(tx[pos[0] - bytez:pos[0]][::-1], 256)

    def read_var_int():
        pos[0] += 1

        val = from_byte_to_int(tx[pos[0] - 1])
        if val < 253:
            return val
        return read_as_int(pow(2, val - 252))

    def read_bytes(bytez):
        pos[0] += bytez
        return tx[pos[0] - bytez:pos[0]]

    def read_var_string():
        size = read_var_int()
        return read_bytes(size)

    def read_flag_byte(val):
        flag = read_bytes(1)
        if from_byte_to_int(flag)==val:
            return True
        else:
            pos[0] -= 1
            return False

    obj = {"ins": [], "outs": []}
    obj["version"] = read_as_int(4)
    segwit = False
    if read_flag_byte(0): segwit = True
    if segwit:
        if not read_flag_byte(1):
            #BIP141 is currently "MUST" ==1
            #A raise is a DOS vector in some contexts
            return None

    ins = read_var_int()
    for i in range(ins):
        obj["ins"].append({
            "outpoint": {
                "hash": binascii.hexlify(read_bytes(32)[::-1]),
                "index": read_as_int(4)
            },
            #TODO this will probably crap out on null for segwit
            "script": binascii.hexlify(read_var_string()),
            "sequence": read_as_int(4)
        })
    outs = read_var_int()
    for i in range(outs):
        obj["outs"].append({
            "value": read_as_int(8),
            "script": binascii.hexlify(read_var_string())
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
            num_items = read_var_int()
            items = []
            for ni in range(num_items):
                items.append(binascii.hexlify(read_var_string()))
            obj["ins"][i]["txinwitness"] = items

    obj["locktime"] = read_as_int(4)
    return obj

# ============================================
# Hashing transactions for signing
# ============================================

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80

def segwit_signature_form(txobj, i, script, amount, hashcode=SIGHASH_ALL):
    """Given a deserialized transaction txobj, an input index i,
    which spends from a witness,
    a script for redemption and an amount in satoshis, prepare
    the version of the transaction to be hashed and signed.
    """
    script = binascii.unhexlify(script)
    nVersion = encode(txobj["version"], 256, 4)[::-1]
    #create hashPrevouts
    if hashcode & SIGHASH_ANYONECANPAY:
        hashPrevouts = "\x00"*32
    else:
        pi = ""
        for inp in txobj["ins"]:
            pi += binascii.unhexlify(inp["outpoint"]["hash"])[::-1]
            pi += encode(inp["outpoint"]["index"], 256, 4)[::-1]
        hashPrevouts = bin_dbl_sha256(pi)
    #create hashSequence
    if not hashcode & SIGHASH_ANYONECANPAY and not (
        hashcode & 0x1f == SIGHASH_NONE) and not (hashcode & 0x1f == SIGHASH_NONE):
        pi = ""
        for inp in txobj["ins"]:
            pi += encode(inp["sequence"], 256, 4)[::-1]
        hashSequence = bin_dbl_sha256(pi)
    else:
        hashSequence = "\x00"*32
    #add this input's outpoint
    thisOut = binascii.unhexlify(txobj["ins"][i]["outpoint"]["hash"])[::-1]
    thisOut += encode(txobj["ins"][i]["outpoint"]["index"], 256, 4)[::-1]
    scriptCode = num_to_var_int(len(script)) + script
    amt = encode(amount, 256, 8)[::-1]
    thisSeq = encode(txobj["ins"][i]["sequence"], 256, 4)[::-1]
    #create hashOutputs
    if not (hashcode & 0x1f == SIGHASH_SINGLE) and not (hashcode & 0x1f == SIGHASH_NONE):
        pi = ""
        for out in txobj["outs"]:
            pi += encode(out["value"], 256, 8)[::-1]
            pi += (num_to_var_int(len(binascii.unhexlify(out["script"]))) + \
                   binascii.unhexlify(out["script"]))
        hashOutputs = bin_dbl_sha256(pi)
    elif hashcode & 0x1f == SIGHASH_SINGLE:
        pi = ""
        if i < len(txobj['outs']):
            pi += encode(txobj["outs"][i]["value"], 256, 8)[::-1]
            pi += (num_to_var_int(len(binascii.unhexlify(txobj["outs"][i][
                "script"]))) + binascii.unhexlify(txobj["outs"][i]["script"]))
        hashOutputs = bin_dbl_sha256(pi)
    else:
        hashOutputs = "\x00"*32
    nLockTime = encode(txobj["locktime"], 256, 4)[::-1]
    return nVersion + hashPrevouts + hashSequence + thisOut + scriptCode + amt + \
           thisSeq + hashOutputs + nLockTime

def signature_form(tx, i, script, hashcode=SIGHASH_ALL):
    """Given a deserialized transaction txobj, an input index i,
    and a script for redemption, prepare
    the version of the transaction to be hashed and signed.
    The returned tx object is serialized (since it's specifically for signing).
    """
    i, hashcode = int(i), int(hashcode)
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
    return serialize(newtx)

def segwit_txid(tx, hashcode=None):
    """An easy way to construct the old-style hash (which is the real txid,
    the one without witness or marker/flag, is to remove all txinwitness
    entries from the deserialized form of the full tx, then reserialize,
    because serialize uses that as a flag to decide which serialization
    style to apply.
    """
    dtx = deserialize(tx)
    for vin in dtx["ins"]:
        if "txinwitness" in vin:
            del vin["txinwitness"]
            reserialized_tx = serialize(dtx)
    return txhash(reserialized_tx, hashcode)

def txhash(tx, hashcode=None, check_sw=True):
    """Creates the appropriate sha256 hash as required
    either for signing or calculating txids.
    Input should be the serialized transaction in bytes,
    that is, as output from serialize().
    If check_sw is True it checks the serialized format for
    segwit flag bytes, and produces the correct form for txid (not wtxid).
    Return value is decoded hex string.
    """
    if check_sw and from_byte_to_int(tx[4]) == 0:
        if not from_byte_to_int(tx[5]) == 1:
            #This is invalid, but a raise is a DOS vector in some contexts.
            return None
        return segwit_txid(tx, hashcode)
    if hashcode:
        return dbl_sha256(from_string_to_bytes(tx) + encode(
            int(hashcode), 256, 4)[::-1])
    else:
        return safe_hexlify(bin_dbl_sha256(tx)[::-1])


def bin_txhash(tx, hashcode=None):
    return binascii.unhexlify(txhash(tx, hashcode))


def ecdsa_tx_sign(tx, priv, hashcode=SIGHASH_ALL, usenonce=None):
    """Input is a *serialized* transaction byte string,
    and a hex private key string;
    returned is a hex string signature.
    """
    sig = ecdsa_raw_sign(
        txhash(tx, hashcode, check_sw=False),
        priv,
        True,
        rawmsg=True,
        usenonce=usenonce)
    return sig + encode(hashcode, 16, 2).encode("utf-8")


def ecdsa_tx_verify(tx, sig, pub, hashcode=SIGHASH_ALL):
    """Input is a *serialized* transaction byte string,
    and hex strings for sig and pub.
    Returned is True/False.
    """
    return ecdsa_raw_verify(
        txhash(tx, hashcode, check_sw=False),
        pub,
        sig[:-2],
        True,
        rawmsg=True)

# Scripts


def mk_pubkey_script(addr):
    # Keep the auxiliary functions around for altcoins' sake
    return '76a914' + b58check_to_hex(addr) + '88ac'


def mk_scripthash_script(addr):
    return 'a914' + b58check_to_hex(addr) + '87'

# Address representation to output script


def address_to_script(addr):
    if addr[0] == '3' or addr[0] == '2':
        return mk_scripthash_script(addr)
    else:
        return mk_pubkey_script(addr)

# Output script to address representation

def is_p2pkh_script(script):
    if script[:3] == b'\x76\xa9\x14' and script[-2:] == b'\x88\xac' and len(
            script) == 25:
        return True
    return False

def script_to_address(script, vbyte=0):
    if re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    if is_p2pkh_script(script):
        return bin_to_b58check(script[3:-2], vbyte)  # pubkey hash addresses
    else:
        # BIP0016 scripthash addresses: requires explicit vbyte set
        if vbyte == 0: raise Exception("Invalid version byte for P2SH")
        return bin_to_b58check(script[2:-1], vbyte)

def pubkey_to_p2sh_p2wpkh_script(pub):
    """Pubkey must be passed as hex string
    """
    return "0014" + hash160(binascii.unhexlify(pub))

def pubkey_to_p2sh_p2wpkh_address(pub, magicbyte=5):
    script = pubkey_to_p2sh_p2wpkh_script(pub)
    return p2sh_scriptaddr(script, magicbyte=magicbyte)

def p2sh_scriptaddr(script, magicbyte=5):
    return hex_to_b58check(hash160(binascii.unhexlify(script)), magicbyte)


scriptaddr = p2sh_scriptaddr


def deserialize_script(script):
    """Note that this is not used internally, in
    the jmbitcoin package, to deserialize() transactions;
    its function is only to allow parsing of scripts by
    external callers. Thus, it returns in the format used
    outside the package: a deserialized script is a list of
    entries which can be any of:
    None
    integer
    hex string
    """
    out, pos = [], 0
    while pos < len(script):
        code = from_byte_to_int(script[pos])
        if code == 0:
            out.append(None)
            pos += 1
        elif code <= 75:
            out.append(binascii.hexlify(script[pos + 1:pos + 1 + code]).decode("utf-8"))
            pos += 1 + code
        elif code <= 78:
            szsz = pow(2, code - 76)
            sz = decode(script[pos + szsz:pos:-1], 256)
            out.append(binascii.hexlify(script[pos + 1 + szsz:pos + 1 + szsz + sz]).decode("utf-8"))
            pos += 1 + szsz + sz
        elif code <= 96:
            out.append(code - 80)
            pos += 1
        else:
            out.append(code)
            pos += 1
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
        if len(unit) <= 75:
            return from_int_to_byte(len(unit)) + unit
        elif len(unit) < 256:
            return from_int_to_byte(76) + from_int_to_byte(len(unit)) + unit
        elif len(unit) < 65536:
            return from_int_to_byte(77) + encode(len(unit), 256, 2)[::-1] + unit
        else:
            return from_int_to_byte(78) + encode(len(unit), 256, 4)[::-1] + unit

def serialize_script(script):
    """Script must be passed hex-encoded; serialization returned is also hex-encoded.
    """
    def unhexlify_if_needed(x):
        if x is None or isinstance(x, int):
            return x
        return binascii.unhexlify(x)
    return safe_hexlify(b''.join(map(serialize_script_unit,
                                         [unhexlify_if_needed(x) for x in script])))

def mk_multisig_script(*args):  # [pubs],k or pub1,pub2...pub[n],k
    if isinstance(args[0], list):
        pubs, k = args[0], int(args[1])
    else:
        pubs = list([x for x in args if len(str(x)) >= 32])
        k = int(args[len(pubs)])
    return serialize_script([k] + pubs + [len(pubs)]) + 'ae'

# Signing and verifying


def verify_tx_input(tx, i, script, sig, pub, witness=None, amount=None):
    """Input types:
    tx - dict (deserialized)
    i - int
    script - hex string
    sig - hex string
    pub - hex string
    witness - hex string
    amount - int (optional but required with witness)

    Returns: True/False
    """
    hashcode = decode(sig[-2:], 16)
    if witness and amount:
        #TODO assumes p2sh wrapped segwit input; OK for JM wallets
        scriptCode = "76a914"+hash160(binascii.unhexlify(pub))+"88ac"
        modtx = segwit_signature_form(tx, int(i), scriptCode, amount, hashcode)
    else:
        modtx = signature_form(tx, int(i), script, hashcode)
    return ecdsa_tx_verify(modtx, sig, pub, hashcode)


def sign(tx, i, priv, hashcode=SIGHASH_ALL, usenonce=None, amount=None):
    """Given a deserialized transaction tx, a private key as a hex string
    (not WIF), returns a deserialized transaction containing the applied signature.
    """
    txcopy = copy.deepcopy(tx)
    i = int(i)
    if amount:
        return p2sh_p2wpkh_sign(tx, i, priv, amount, hashcode=hashcode,
                                usenonce=usenonce)
    pub = privkey_to_pubkey(priv, True)
    address = pubkey_to_address(pub)
    signing_tx = signature_form(tx, i, mk_pubkey_script(address), hashcode)
    sig = ecdsa_tx_sign(signing_tx, priv, hashcode, usenonce=usenonce)
    txcopy["ins"][i]["script"] = serialize_script([sig, pub])
    return txcopy

def p2sh_p2wpkh_sign(tx, i, priv, amount, hashcode=SIGHASH_ALL, usenonce=None):
    """Given a serialized transaction, index, private key in hex,
    amount in satoshis and optionally hashcode, return the serialized
    transaction containing a signature and witness for this input; it's
    assumed that the input is of type pay-to-witness-pubkey-hash nested in p2sh.
    """
    pub = privkey_to_pubkey(priv)
    script = pubkey_to_p2sh_p2wpkh_script(pub)
    scriptCode = "76a914"+hash160(binascii.unhexlify(pub))+"88ac"
    signing_tx = segwit_signature_form(deserialize(tx), i, scriptCode, amount,
                                       hashcode=hashcode)
    sig = ecdsa_tx_sign(signing_tx, priv, hashcode, usenonce=usenonce)
    txobj = deserialize(tx)
    txobj["ins"][i]["script"] = "16"+script
    txobj["ins"][i]["txinwitness"] = [sig, pub]
    return serialize(txobj)

def signall(tx, priv):
    # if priv is a dictionary, assume format is
    # { 'txinhash:txinidx' : privkey }
    if isinstance(priv, dict):
        for e, i in enumerate(tx["ins"]):
            k = priv["%s:%d" % (i["outpoint"]["hash"], i["outpoint"]["index"])]
            tx = sign(tx, e, k)
    else:
        for i in range(len(tx["ins"])):
            tx = sign(tx, i, priv)
            print("after sign number: ", i, ", tx is: ", tx)
    return tx


def multisign(tx, i, script, pk, hashcode=SIGHASH_ALL):
    """tx must be a deserialized transaction dict.
    script must be a hex string.
    Return value is a signature as hex string.
    """
    modtx = signature_form(tx, i, script, hashcode)
    return ecdsa_tx_sign(modtx, pk, hashcode)


def apply_multisignatures(tx, i, script, sigs):
    """Args are:
    tx - deserialized transaction
    i - index of signing
    script - redeem script, hex string
    sigs - list of hex strings as sigs at each appropriate index.
    Returns a deserialized transaction object (reasoning same as for 'sign').
    """
    i = int(i)
    txobj = copy.deepcopy(tx)
    txobj["ins"][i]["script"] = serialize_script([None] + sigs + [script])
    return txobj

def mktx(ins, outs):
    """Assumed that all inputs to mktx are decoded strings, not byte strings.
    Returns a deserialized, not serialized, tranaction object, since
    calls to `sign` take deserialized objects.
    """
    txobj = {"locktime": 0, "version": 1, "ins": [], "outs": []}
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
                "sequence": 4294967295
            })
    for o in outs:
        outobj = {}
        if "address" in o:
            outobj["script"] = address_to_script(o["address"])
        elif "script" in o:
            outobj["script"] = o["script"]
        else:
            raise Exception("Could not find 'address' or 'script' in output.")
        outobj["value"] = o["value"]
        txobj["outs"].append(outobj)
    print('at end of mktx, txobj is: ', txobj)
    return txobj
