#!/usr/bin/python
import binascii, re, json, copy, sys
from jmbitcoin.secp256k1_main import *
from _functools import reduce
import os

is_python2 = sys.version_info.major == 2

### Hex to bin converter and vice versa for objects
def json_is_base(obj, base):
    if not is_python2 and isinstance(obj, bytes): #pragma: no cover
        return False

    alpha = get_code_string(base)
    if isinstance(obj, string_types):
        for i in range(len(obj)):
            if alpha.find(obj[i]) == -1:
                return False
        return True
    elif isinstance(obj, int_types) or obj is None:
        return True
    elif isinstance(obj, list):
        for i in range(len(obj)):
            if not json_is_base(obj[i], base):
                return False
        return True
    else:
        for x in obj:
            if not json_is_base(obj[x], base):
                return False
        return True


def json_changebase(obj, changer):
    if isinstance(obj, string_or_bytes_types):
        return changer(obj)
    elif isinstance(obj, int_types) or obj is None:
        return obj
    elif isinstance(obj, list):
        return [json_changebase(x, changer) for x in obj]
    return dict((x, json_changebase(obj[x], changer)) for x in obj)

# Transaction serialization and deserialization

def deserialize(tx):
    if isinstance(tx, str) and re.match('^[0-9a-fA-F]*$', tx):
        #tx = bytes(bytearray.fromhex(tx))
        return json_changebase(
            deserialize(binascii.unhexlify(tx)), lambda x: safe_hexlify(x))
    # http://stackoverflow.com/questions/4851463/python-closure-write-to-variable-in-parent-scope
    # Python's scoping rules are demented, requiring me to make pos an object
    # so that it is call-by-reference
    pos = [0]

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
                "hash": read_bytes(32)[::-1],
                "index": read_as_int(4)
            },
            #TODO this will probably crap out on null for segwit
            "script": read_var_string(),
            "sequence": read_as_int(4)
        })
    outs = read_var_int()
    for i in range(outs):
        obj["outs"].append({
            "value": read_as_int(8),
            "script": read_var_string()
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
                items.append(read_var_string())
            obj["ins"][i]["txinwitness"] = items

    obj["locktime"] = read_as_int(4)
    return obj

def serialize(txobj):
    o = []
    if json_is_base(txobj, 16):
        json_changedbase = json_changebase(txobj,
                                           lambda x: binascii.unhexlify(x))
        hexlified = safe_hexlify(serialize(json_changedbase))
        return hexlified
    o.append(encode(txobj["version"], 256, 4)[::-1])
    segwit = False
    if any("txinwitness" in x.keys() for x in txobj["ins"]):
        segwit = True
    if segwit:
        #append marker and flag
        o.append('\x00')
        o.append('\x01')
    o.append(num_to_var_int(len(txobj["ins"])))
    for inp in txobj["ins"]:
        o.append(inp["outpoint"]["hash"][::-1])
        o.append(encode(inp["outpoint"]["index"], 256, 4)[::-1])
        o.append(num_to_var_int(len(inp["script"])) + (inp["script"] if inp[
            "script"] or is_python2 else bytes()))
        o.append(encode(inp["sequence"], 256, 4)[::-1])
    o.append(num_to_var_int(len(txobj["outs"])))
    for out in txobj["outs"]:
        o.append(encode(out["value"], 256, 8)[::-1])
        o.append(num_to_var_int(len(out["script"])) + out["script"])
    if segwit:
        #number of witnesses is not explicitly encoded;
        #it's implied by txin length
        for inp in txobj["ins"]:
            if "txinwitness" not in inp.keys():
                o.append('\x00')
                continue
            items = inp["txinwitness"]
            o.append(num_to_var_int(len(items)))
            for item in items:
                o.append(num_to_var_int(len(item)) + item)
    o.append(encode(txobj["locktime"], 256, 4)[::-1])

    return ''.join(o) if is_python2 else reduce(lambda x, y: x + y, o, bytes())

# Hashing transactions for signing

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
    #if isinstance(txobj, string_or_bytes_types):
    #    return serialize(segwit_signature_form(deserialize(txobj), i, script,
    #                                           amount, hashcode))
    script = binascii.unhexlify(script)
    nVersion = encode(txobj["version"], 256, 4)[::-1]
    #create hashPrevouts preimage
    pi = ""
    for inp in txobj["ins"]:
        pi += binascii.unhexlify(inp["outpoint"]["hash"])[::-1]
        pi += encode(inp["outpoint"]["index"], 256, 4)[::-1]
    hashPrevouts = bin_dbl_sha256(pi)
    #create hashSequence preimage
    pi = ""
    for inp in txobj["ins"]:
        pi += encode(inp["sequence"], 256, 4)[::-1]
    hashSequence = bin_dbl_sha256(pi)
    #add this input's outpoint
    thisOut = binascii.unhexlify(txobj["ins"][i]["outpoint"]["hash"])[::-1]
    thisOut += encode(txobj["ins"][i]["outpoint"]["index"], 256, 4)[::-1]
    scriptCode = num_to_var_int(len(script)) + script
    amt = encode(amount, 256, 8)[::-1]
    thisSeq = encode(txobj["ins"][i]["sequence"], 256, 4)[::-1]
    #create hashOutputs preimage
    pi = ""
    for out in txobj["outs"]:
        pi += encode(out["value"], 256, 8)[::-1]
        pi += (num_to_var_int(len(binascii.unhexlify(out["script"]))) + \
               binascii.unhexlify(out["script"]))
    hashOutputs = bin_dbl_sha256(pi)
    nLockTime = encode(txobj["locktime"], 256, 4)[::-1]
    return nVersion + hashPrevouts + hashSequence + thisOut + scriptCode + amt + \
           thisSeq + hashOutputs + nLockTime

def signature_form(tx, i, script, hashcode=SIGHASH_ALL):
    i, hashcode = int(i), int(hashcode)
    if isinstance(tx, string_or_bytes_types):
        return serialize(signature_form(deserialize(tx), i, script, hashcode))
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
    """Creates the appropriate sha256 hash as required
    either for signing or calculating txids.
    If check_sw is True it checks the serialized format for
    segwit flag bytes, and produces the correct form for txid (not wtxid).
    """
    if isinstance(tx, str) and re.match('^[0-9a-fA-F]*$', tx):
        tx = changebase(tx, 16, 256)
    if check_sw and from_byte_to_int(tx[4]) == 0:
        if not from_byte_to_int(tx[5]) == 1:
            #This invalid, but a raise is a DOS vector in some contexts.
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


def script_to_address(script, vbyte=0):
    if re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    if script[:3] == b'\x76\xa9\x14' and script[-2:] == b'\x88\xac' and len(
            script) == 25:
        return bin_to_b58check(script[3:-2], vbyte)  # pubkey hash addresses
    else:
        # BIP0016 scripthash addresses: requires explicit vbyte set
        if vbyte == 0: raise Exception("Invalid version byte for P2SH")
        return bin_to_b58check(script[2:-1], vbyte)

def pubkey_to_p2sh_p2wpkh_script(pub):
    if re.match('^[0-9a-fA-F]*$', pub):
        pub = binascii.unhexlify(pub)
    return "0014" + hash160(pub)

def pubkey_to_p2sh_p2wpkh_address(pub, magicbyte=5):
    if re.match('^[0-9a-fA-F]*$', pub):
        pub = binascii.unhexlify(pub)
    script = pubkey_to_p2sh_p2wpkh_script(pub)
    return p2sh_scriptaddr(script, magicbyte=magicbyte)

def p2sh_scriptaddr(script, magicbyte=5):
    if re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    return hex_to_b58check(hash160(script), magicbyte)


scriptaddr = p2sh_scriptaddr


def deserialize_script(script):
    if isinstance(script, str) and re.match('^[0-9a-fA-F]*$', script):
        return json_changebase(
            deserialize_script(binascii.unhexlify(script)),
            lambda x: safe_hexlify(x))
    out, pos = [], 0
    while pos < len(script):
        code = from_byte_to_int(script[pos])
        if code == 0:
            out.append(None)
            pos += 1
        elif code <= 75:
            out.append(script[pos + 1:pos + 1 + code])
            pos += 1 + code
        elif code <= 78:
            szsz = pow(2, code - 76)
            sz = decode(script[pos + szsz:pos:-1], 256)
            out.append(script[pos + 1 + szsz:pos + 1 + szsz + sz])
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


if is_python2:

    def serialize_script(script):
        #bugfix: if *every* item in the script is of type int,
        #for example a script of OP_TRUE, or None,
        #then the previous version would always report json_is_base as True,
        #resulting in an infinite loop (look who's demented now).
        #There is no easy solution without being less flexible;
        #here we default to returning a hex serialization in cases where
        #there are no strings to use as flags.
        if all([(isinstance(x, int) or x is None) for x in script]):
            #no indication given whether output should be hex or binary, so..?
            return binascii.hexlify(''.join(map(serialize_script_unit, script)))
        if json_is_base(script, 16):
            return binascii.hexlify(serialize_script(json_changebase(
                script, lambda x: binascii.unhexlify(x))))
        return ''.join(map(serialize_script_unit, script))

else: #pragma: no cover

    def serialize_script(script):
        #TODO Python 3 bugfix as above needed
        if json_is_base(script, 16):
            return safe_hexlify(serialize_script(json_changebase(
                script, lambda x: binascii.unhexlify(x))))

        result = bytes()
        for b in map(serialize_script_unit, script):
            result += b if isinstance(b, bytes) else bytes(b, 'utf-8')
        return result


def mk_multisig_script(*args):  # [pubs],k or pub1,pub2...pub[n],k
    if isinstance(args[0], list):
        pubs, k = args[0], int(args[1])
    else:
        pubs = list(filter(lambda x: len(str(x)) >= 32, args))
        k = int(args[len(pubs)])
    return serialize_script([k] + pubs + [len(pubs)]) + 'ae'

# Signing and verifying


def verify_tx_input(tx, i, script, sig, pub, witness=None, amount=None):
    if re.match('^[0-9a-fA-F]*$', tx):
        tx = binascii.unhexlify(tx)
    if re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    if not re.match('^[0-9a-fA-F]*$', sig):
        sig = safe_hexlify(sig)
    if not re.match('^[0-9a-fA-F]*$', pub):
        pub = safe_hexlify(pub)
    if witness:
        if not re.match('^[0-9a-fA-F]*$', witness):
            witness = safe_hexlify(witness)
    hashcode = decode(sig[-2:], 16)
    if witness and amount:
        #TODO assumes p2sh wrapped segwit input; OK for JM wallets
        scriptCode = "76a914"+hash160(binascii.unhexlify(pub))+"88ac"
        modtx = segwit_signature_form(deserialize(binascii.hexlify(tx)), int(i),
                                      scriptCode, amount, hashcode)
    else:
        modtx = signature_form(tx, int(i), script, hashcode)
    return ecdsa_tx_verify(modtx, sig, pub, hashcode)


def sign(tx, i, priv, hashcode=SIGHASH_ALL, usenonce=None, amount=None):
    i = int(i)
    if (not is_python2 and isinstance(re, bytes)) or not re.match(
            '^[0-9a-fA-F]*$', tx):
        return binascii.unhexlify(sign(safe_hexlify(tx), i, priv))
    if len(priv) <= 33:
        priv = safe_hexlify(priv)
    if amount:
        return p2sh_p2wpkh_sign(tx, i, priv, amount, hashcode=hashcode,
                                usenonce=usenonce)
    pub = privkey_to_pubkey(priv, True)
    address = pubkey_to_address(pub)
    signing_tx = signature_form(tx, i, mk_pubkey_script(address), hashcode)
    sig = ecdsa_tx_sign(signing_tx, priv, hashcode, usenonce=usenonce)
    txobj = deserialize(tx)
    txobj["ins"][i]["script"] = serialize_script([sig, pub])
    return serialize(txobj)

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
        for e, i in enumerate(deserialize(tx)["ins"]):
            k = priv["%s:%d" % (i["outpoint"]["hash"], i["outpoint"]["index"])]
            tx = sign(tx, e, k)
    else:
        for i in range(len(deserialize(tx)["ins"])):
            tx = sign(tx, i, priv)
    return tx


def multisign(tx, i, script, pk, hashcode=SIGHASH_ALL):
    if re.match('^[0-9a-fA-F]*$', tx):
        tx = binascii.unhexlify(tx)
    if re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    modtx = signature_form(tx, i, script, hashcode)
    return ecdsa_tx_sign(modtx, pk, hashcode)


def apply_multisignatures(*args):
    # tx,i,script,sigs OR tx,i,script,sig1,sig2...,sig[n]
    tx, i, script = args[0], int(args[1]), args[2]
    sigs = args[3] if isinstance(args[3], list) else list(args[3:])

    if isinstance(script, str) and re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    sigs = [binascii.unhexlify(x) if x[:2] == '30' else x for x in sigs]
    if isinstance(tx, str) and re.match('^[0-9a-fA-F]*$', tx):
        return safe_hexlify(apply_multisignatures(
            binascii.unhexlify(tx), i, script, sigs))

    txobj = deserialize(tx)
    txobj["ins"][i]["script"] = serialize_script([None] + sigs + [script])
    return serialize(txobj)


def is_inp(arg):
    return len(arg) > 64 or "output" in arg or "outpoint" in arg


def mktx(*args):
    # [in0, in1...],[out0, out1...] or in0, in1 ... out0 out1 ...
    ins, outs = [], []
    for arg in args:
        if isinstance(arg, list):
            for a in arg:
                (ins if is_inp(a) else outs).append(a)
        else:
            (ins if is_inp(arg) else outs).append(arg)

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
        if isinstance(o, string_or_bytes_types):
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

