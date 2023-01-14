# note, only used for non-cryptographic randomness:
import random
import json
from typing import List, Union, Tuple
# needed for single sha256 evaluation, which is used
# in bitcoin (p2wsh) but not exposed in python-bitcointx:
import hashlib

from jmbitcoin.secp256k1_main import *
from jmbase import bintohex, utxo_to_utxostr
from bitcointx.core import (CMutableTransaction, CTxInWitness,
                            CMutableOutPoint, CMutableTxIn, CTransaction,
                            CMutableTxOut, CTxIn, CTxOut, ValidationError)
from bitcointx.core.script import *
from bitcointx.wallet import (P2WPKHCoinAddress, CCoinAddress, P2PKHCoinAddress,
                              CCoinAddressError)
from bitcointx.core.scripteval import (VerifyScript, SCRIPT_VERIFY_WITNESS,
                                       SCRIPT_VERIFY_P2SH,
                                       SCRIPT_VERIFY_STRICTENC,
                                       SIGVERSION_WITNESS_V0)

def human_readable_transaction(tx, jsonified=True):
    """ Given a CTransaction object, output a human
    readable json-formatted string (suitable for terminal
    output or large GUI textbox display) containing
    all details of that transaction.
    If `jsonified` is False, the dict is returned, instead
    of the json string.
    """
    assert isinstance(tx, CTransaction)
    outdict = {}
    outdict["hex"] = bintohex(tx.serialize())
    outdict["inputs"]=[]
    outdict["outputs"]=[]
    outdict["txid"]= bintohex(tx.GetTxid()[::-1])
    outdict["nLockTime"] = tx.nLockTime
    outdict["nVersion"] = tx.nVersion
    for i, inp in enumerate(tx.vin):
        if not tx.wit.vtxinwit:
            # witness section is not initialized/empty
            witarg = None
        else:
            witarg = tx.wit.vtxinwit[i]
        outdict["inputs"].append(human_readable_input(inp, witarg))
    for i, out in enumerate(tx.vout):
        outdict["outputs"].append(human_readable_output(out))
    if not jsonified:
        return outdict
    return json.dumps(outdict, indent=4)

def human_readable_input(txinput, txinput_witness):
    """ Pass objects of type CTxIn and CTxInWitness (or None)
    and a dict of human-readable entries for this input
    is returned.
    """
    assert isinstance(txinput, CTxIn)
    outdict = {}
    success, u = utxo_to_utxostr((txinput.prevout.hash[::-1],
                                  txinput.prevout.n))
    assert success
    outdict["outpoint"] = u
    outdict["scriptSig"] = bintohex(txinput.scriptSig)
    outdict["nSequence"] = txinput.nSequence

    if txinput_witness:
        outdict["witness"] = bintohex(
            txinput_witness.scriptWitness.serialize())
    return outdict

def human_readable_output(txoutput):
    """ Returns a dict of human-readable entries
    for this output.
    """
    assert isinstance(txoutput, CTxOut)
    outdict = {}
    outdict["value_sats"] = txoutput.nValue
    outdict["scriptPubKey"] = bintohex(txoutput.scriptPubKey)
    try:
        addr = CCoinAddress.from_scriptPubKey(txoutput.scriptPubKey)
        outdict["address"] = str(addr)
    except CCoinAddressError:
        pass # non standard script
    return outdict

def there_is_one_segwit_input(input_types: List[str]) -> bool:
    # note that we need separate input types for
    # any distinct types of scripthash inputs supported,
    # since each may have a different size of witness; in
    # that case, the internal list in this list comprehension
    # will need updating.
    return any(y in ["p2sh-p2wpkh", "p2wpkh", "p2wsh"] for y in input_types)

def estimate_tx_size(ins: List[str], outs: List[str]) -> Union[int, Tuple[int]]:
    '''Estimate transaction size.
    Both arguments `ins` and `outs` must be lists of script types,
    and they must be present in the keys of the dicts `inmults`,
    `outmults` defined here.
    Note that variation in ECDSA signature sizes means
    we will sometimes see small inaccuracies in this estimate, but
    that this is ameliorated by the existence of the witness discount,
    in actually estimating fees.
    The value '72' is used for the most-likely size of these ECDSA
    signatures, due to 30[1 byte] + len(rest)[1 byte] + type:02 [1 byte] + len(r)[1] + r[32 or 33] + type:02[1] + len(s)[1] + s[32] + sighash_all [1]
    ... though as can be seen, 71 is also likely:
    r length 33 occurs when the value is 'negative' (>N/2) and a byte x80 is prepended,
    but shorter values for r are possible if rare.
    Returns:
    Either a single integer, if the transaction will be non-segwit,
    or a tuple (int, int) for witness and non-witness bytes respectively).
    '''

    # All non-witness input sizes include: txid, index, sequence,
    # which is 32, 4 and 4; the remaining is scriptSig which is 1
    # at minimum, for native segwit (the byte x00). Hence 41 is the minimum.
    # The witness field for p2wpkh consists of sig, pub so 72 + 33 + 1 byte
    # for the number of witness elements and 2 bytes for the size of each element,
    # hence 108.
    # For p2pkh, 148 comes from 32+4+1+1+~72+1+33+4
    # For p2sh-p2wpkh there is an additional 23 bytes of witness for the redeemscript.
    #
    # Note that p2wsh here is specific to the script
    # we use for fidelity bonds; 43 is the bytes required for that
    # script's redeemscript field in the witness, but for arbitrary scripts,
    # the witness portion could be any other size.
    # Hence, we may need to modify this later.
    inmults = {"p2wsh": {"w": 1 + 72 + 43, "nw": 41},
               "p2wpkh": {"w": 108, "nw": 41},
               "p2sh-p2wpkh": {"w": 108, "nw": 64},
               "p2pkh": {"w": 0, "nw": 148}}

    # Notes: in outputs, there is only 1 'scripthash'
    # type for either segwit/nonsegwit.
    # p2wsh has structure 8 bytes output, then:
    # x22,x00,x20,(32 byte hash), so 32 + 3 + 8
    # note also there is no need to distinguish witness
    # here, outputs are always entirely nonwitness.
    outmults = {"p2wsh": 43,
               "p2wpkh": 31,
               "p2sh-p2wpkh": 32,
               "p2pkh": 34}

    # nVersion, nLockTime, nins, nouts:
    nwsize =  4 + 4 + 2
    wsize = 0
    tx_is_segwit = there_is_one_segwit_input(ins)
    if tx_is_segwit:
        # flag and marker bytes are included in witness
        wsize += 2

    for i in ins:
        if i not in inmults:
            raise NotImplementedError(
            f"Script type not supported for transaction size estimation: {i}")
        inmult = inmults[i]
        nwsize += inmult["nw"]
        wsize += inmult["w"]
    for o in outs:
        if o not in outmults:
            raise NotImplementedError(
            f"Script type not supported for transaction size estimation: {o}")
        nwsize += outmults[o]

    if not tx_is_segwit:
        return nwsize
    return (wsize, nwsize)

def pubkey_to_p2pkh_script(pub, require_compressed=False):
    """
    Given a pubkey in bytes, return a CScript
    representing the corresponding pay-to-pubkey-hash
    scriptPubKey.
    """
    return P2PKHCoinAddress.from_pubkey(pub).to_scriptPubKey()

def pubkey_to_p2wpkh_script(pub):
    """
    Given a pubkey in bytes (compressed), return a CScript
    representing the corresponding pay-to-witness-pubkey-hash
    scriptPubKey.
    """
    return P2WPKHCoinAddress.from_pubkey(pub).to_scriptPubKey()

def pubkey_to_p2sh_p2wpkh_script(pub):
    """
    Given a pubkey in bytes, return a CScript representing
    the corresponding nested pay to witness keyhash
    scriptPubKey.
    """
    if not is_valid_pubkey(pub, True):
        raise Exception("Invalid pubkey")
    return pubkey_to_p2wpkh_script(pub).to_p2sh_scriptPubKey()

def redeem_script_to_p2wsh_script(redeem_script):
    """ Given redeem script of type CScript (or bytes)
    returns the corresponding segwit v0 scriptPubKey as
    for the case pay-to-witness-scripthash.
    """
    return standard_witness_v0_scriptpubkey(
        hashlib.sha256(redeem_script).digest())

def mk_freeze_script(pub, locktime):
    """
    Given a pubkey and locktime, create a script which can only be spent
    after the locktime has passed using OP_CHECKLOCKTIMEVERIFY
    """
    if not isinstance(locktime, int):
        raise TypeError("locktime must be int")
    if not isinstance(pub, bytes):
        raise TypeError("pubkey must be in bytes")
    if not is_valid_pubkey(pub, require_compressed=True):
        raise ValueError("not a valid public key")
    return CScript([locktime, OP_CHECKLOCKTIMEVERIFY, OP_DROP, pub,
                    OP_CHECKSIG])

def mk_burn_script(data):
    """ For a given bytestring (data),
    returns a scriptPubKey which is an OP_RETURN
    of that data.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be in bytes")
    return CScript([OP_RETURN, data])

def sign(tx, i, priv, hashcode=SIGHASH_ALL, amount=None, native=False):
    """
    Given a transaction tx of type CMutableTransaction, an input index i,
    and a raw privkey in bytes, updates the CMutableTransaction to contain
    the newly appended signature.
    Only four scriptPubKey types supported: p2pkh, p2wpkh, p2sh-p2wpkh, p2wsh.
    Note that signing multisig must be done outside this function, using
    the wrapped library.
    If native is not the default (False), and if native != "p2wpkh",
    then native must be a CScript object containing the redeemscript needed to sign.
    Returns: (signature, "signing succeeded")
    or: (None, errormsg) in case of failure
    """
    # script verification flags
    flags = set([SCRIPT_VERIFY_STRICTENC])

    def return_err(e):
        return None, "Error in signing: " + repr(e)

    assert isinstance(tx, CMutableTransaction)

    pub = privkey_to_pubkey(priv)

    if not amount:
        # p2pkh only supported here:
        input_scriptPubKey = pubkey_to_p2pkh_script(pub)
        sighash = SignatureHash(input_scriptPubKey, tx, i, hashcode)
        try:
            sig = ecdsa_raw_sign(sighash, priv, rawmsg=True) + bytes([hashcode])
        except Exception as e:
            return return_err(e)
        tx.vin[i].scriptSig = CScript([sig, pub])
        # Verify the signature worked.
        try:
            VerifyScript(tx.vin[i].scriptSig,
                        input_scriptPubKey, tx, i, flags=flags)
        except Exception as e:
            return return_err(e)
        return sig, "signing succeeded"

    else:
        # segwit case; we currently support p2wpkh native or under p2sh.

        # https://github.com/Simplexum/python-bitcointx/blob/648ad8f45ff853bf9923c6498bfa0648b3d7bcbd/bitcointx/core/scripteval.py#L1250-L1252
        flags.add(SCRIPT_VERIFY_P2SH)
        flags.add(SCRIPT_VERIFY_WITNESS)

        if native and native != "p2wpkh":
            scriptCode = native
            input_scriptPubKey = redeem_script_to_p2wsh_script(native)
        else:
            # this covers both p2wpkh and p2sh-p2wpkh case:
            input_scriptPubKey = pubkey_to_p2wpkh_script(pub)
            # only created for convenience access to scriptCode:
            input_address = P2WPKHCoinAddress.from_scriptPubKey(
                input_scriptPubKey)
            # function name is misleading here; redeemScript only applies to p2sh.
            scriptCode = input_address.to_redeemScript()

        sighash = SignatureHash(scriptCode, tx, i, hashcode, amount=amount,
                                sigversion=SIGVERSION_WITNESS_V0)
        try:
            sig = ecdsa_raw_sign(sighash, priv, rawmsg=True) + bytes([hashcode])
        except Exception as e:
            return return_err(e)
        if not native:
            tx.vin[i].scriptSig = CScript([input_scriptPubKey])
            input_scriptPubKey = pubkey_to_p2sh_p2wpkh_script(pub)

        if native and native != "p2wpkh":
            witness = [sig, scriptCode]
        else:
            witness = [sig, pub]
        ctxwitness = CTxInWitness(CScriptWitness(witness))
        tx.wit.vtxinwit[i] = ctxwitness
        # Verify the signature worked.
        try:
            VerifyScript(tx.vin[i].scriptSig, input_scriptPubKey, tx, i,
                     flags=flags, amount=amount, witness=tx.wit.vtxinwit[i].scriptWitness)
        except ValidationError as e:
            return return_err(e)

        return sig, "signing succeeded"

def mktx(ins, outs, version=1, locktime=0):
    """ Given a list of input tuples (txid(bytes), n(int)),
    and a list of outputs which are dicts with
    keys "address" (value should be *str* not CCoinAddress) (
    or alternately "script" (for nonstandard outputs, value
    should be CScript)),
    "value" (value should be integer satoshis), outputs a
    CMutableTransaction object.
    Tx version and locktime are optionally set, for non-default
    locktimes, inputs are given nSequence as per below comment.
    """
    vin = []
    vout = []
    # This does NOT trigger rbf and mimics Core's standard behaviour as of
    # Jan 2019.
    # Tx creators wishing to use rbf will need to set it explicitly outside
    # of this function.
    if locktime != 0:
        sequence = 0xffffffff - 1
    else:
        sequence = 0xffffffff
    for i in ins:
        outpoint = CMutableOutPoint((i[0][::-1]), i[1])
        inp = CMutableTxIn(prevout=outpoint, nSequence=sequence)
        vin.append(inp)
    for o in outs:
        if "script" in o:
            sPK = o["script"]
        else:
            # note the to_scriptPubKey method is only available for standard
            # address types
            sPK = CCoinAddress(o["address"]).to_scriptPubKey()
        out = CMutableTxOut(o["value"], sPK)
        vout.append(out)
    return CMutableTransaction(vin, vout, nLockTime=locktime, nVersion=version)

def make_shuffled_tx(ins, outs, version=1, locktime=0):
    """ Simple wrapper to ensure transaction
    inputs and outputs are randomly ordered.
    NB: This mutates ordering of `ins` and `outs`.
    """
    random.shuffle(ins)
    random.shuffle(outs)
    return mktx(ins, outs, version=version, locktime=locktime)

def verify_tx_input(tx, i, scriptSig, scriptPubKey, amount=None, witness=None):
    flags = set([SCRIPT_VERIFY_STRICTENC])
    if witness:
        # https://github.com/Simplexum/python-bitcointx/blob/648ad8f45ff853bf9923c6498bfa0648b3d7bcbd/bitcointx/core/scripteval.py#L1250-L1252
        flags.add(SCRIPT_VERIFY_P2SH)
        flags.add(SCRIPT_VERIFY_WITNESS)
    try:
        VerifyScript(scriptSig, scriptPubKey, tx, i,
                 flags=flags, amount=amount, witness=witness)
    except ValidationError as e:
        return False
    return True

def extract_witness(tx, i):
    """Given `tx` of type CTransaction, extract,
    as a list of objects of type CScript, which constitute the
    witness at the index i, followed by "success".
    If the witness is not present for this index, (None, "errmsg")
    is returned.
    Callers must distinguish the case 'tx is unsigned' from the
    case 'input is not type segwit' externally.
    """
    assert isinstance(tx, CTransaction)
    assert i >= 0
    if not tx.has_witness():
        return None, "Tx witness not present"
    if len(tx.vin) < i:
        return None, "invalid input index"
    witness = tx.wit.vtxinwit[i]
    return (witness, "success")

def extract_pubkey_from_witness(tx, i):
    """ Extract the pubkey used to sign at index i,
    in CTransaction tx, assuming it is of type p2wpkh
    (including wrapped segwit version).
    Returns (pubkey, "success") or (None, "errmsg").
    """
    witness, msg = extract_witness(tx, i)
    sWitness = [a for a in iter(witness.scriptWitness)]
    if not sWitness:
        return None, msg
    else:
        if len(sWitness) != 2:
            return None, "invalid witness for p2wpkh."
        if not is_valid_pubkey(sWitness[1], True):
            return None, "invalid pubkey in witness"
        return sWitness[1], "success"

def get_equal_outs(tx):
    """ If 2 or more transaction outputs have the same
    bitcoin value, return then as a list of CTxOuts.
    If there is not exactly one equal output size, return False.
    """
    retval = []
    l = [x.nValue for x in tx.vout]
    eos = [i for i in l if l.count(i)>=2]
    if len(eos) > 0:
        eos = set(eos)
        if len(eos) > 1:
            return False
    for i, vout in enumerate(tx.vout):
        if vout.nValue == list(eos)[0]:
            retval.append((i, vout))
    assert len(retval) > 1
    return retval

def is_jm_tx(tx, min_cj_amount=75000, min_participants=3):
    """ Identify Joinmarket-patterned transactions.
    TODO: this should be in another module.
    Given a CBitcoinTransaction tx, check:
    nins >= number of coinjoin outs (equal sized)
    non-equal outs = coinjoin outs or coinjoin outs -1
    at least 3 coinjoin outs (2 technically possible but excluded)
    also possible to try to get clever about fees, but won't bother.
    note: BlockSci's algo additionally addresses subset sum, so will
    give better quality data, but this is kept simple for now.
    We filter out joins with less than 3 participants as they are
    not really in Joinmarket "correct usage" and there will be a lot
    of false positives.
    We filter out "joins" less than 75000 sats as they are unlikely to
    be Joinmarket and there tend to be many low-value false positives.
    Returns:
    (False, None) for non-matches
    (coinjoin amount, number of participants) for matches.
    """
    def assumed_cj_out_num(nout):
        """Return the value ceil(nout/2)
        """
        x = nout//2
        if nout %2: return x+1
        return x

    def most_common_value(x):
        return max(set(x), key=x.count)

    assumed_coinjoin_outs = assumed_cj_out_num(len(tx.vout))
    if assumed_coinjoin_outs < min_participants:
        return (False, None)
    if len(tx.vin) < assumed_coinjoin_outs:
        return (False, None)
    outvals = [x.nValue for x in tx.vout]
    # it's not possible for the coinjoin out to not be
    # the most common value:
    mcov = most_common_value(outvals)
    if mcov < min_cj_amount:
        return (False, None)
    cjoutvals = [x for x in outvals if x == mcov]
    if len(cjoutvals) != assumed_coinjoin_outs:
        return (False, None)
    # number of participants is the number of assumed
    # coinjoin outputs:
    return (mcov, assumed_coinjoin_outs)
