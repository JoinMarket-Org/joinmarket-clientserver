# note, only used for non-cryptographic randomness:
import random
import json
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

# for each transaction type, different output script pubkeys may result in
# a difference in the number of bytes accounted for while estimating the
# transaction size, this variable stores the difference and is factored in
# when calculating the correct transaction size. For example, for a p2pkh
# transaction, if one of the outputs is a p2wsh pubkey, then the transaction
# would need 9 extra bytes to account for the difference in script pubkey
# sizes
OUTPUT_EXTRA_BYTES = {
    'p2pkh': {
        'p2wpkh': -3,
        'p2sh-p2wpkh': -2,
        'p2wsh': 9
    },
    'p2wpkh': {
        'p2pkh': 3,
        'p2sh-p2wpkh': 1,
        'p2wsh': 12
    },
    'p2sh-p2wpkh': {
        'p2pkh': 2,
        'p2wpkh': -1,
        'p2wsh': 11
    }
}

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

def estimate_tx_size(ins, outs, txtype='p2pkh', outtype=None):
    '''Estimate transaction size.
    The txtype field as detailed below is used to distinguish
    the type, but there is at least one source of meaningful roughness:
    we assume the output types are the same as the input (to be fair,
    outputs only contribute a little to the overall total). This combined
    with a few bytes variation in signature sizes means we will expect,
    say, 10% inaccuracy here.

    Assuming p2pkh:
    out: 8+1+3+20+2=34, in: 32+4+1+1+~72+1+33+4=148,
    ver: 4, locktime:4, +2 (len in,out)
    total = 34*len_out + 148*len_in + 10 (sig sizes vary slightly)

    Assuming p2sh M of N multisig:
    "ins" must contain M, N so ins= (numins, M, N) (crude assuming all same)
    73*M + 34*N + 45 per input, so total ins ~ len_ins * (45+73M+34N)
    so total ~ 32*len_out + (45+73M+34N)*len_in + 10

    Assuming p2sh-p2wpkh:
    witness are roughly 1+1+~72+1+33 for each input
    (txid, vin, 4+20 for witness program encoded as scriptsig, 4 for sequence)
    non-witness input fields are roughly 32+4+4+20+4=64, so total becomes
    n_in * 64 + 4(ver) + 2(marker, flag) + 2(n_in, n_out) + 4(locktime) + n_out*32

    Assuming p2wpkh native:
    witness as previous case
    non-witness loses the 24 witnessprogram, replaced with 1 zero,
    in the scriptSig, so becomes:
    4 + 1 + 1 + (n_in) + (vin) + (n_out) + (vout) + (witness) + (locktime)
    non-witness: 4(ver) +2 (marker, flag) + n_in*41 + 4(locktime) +2 (len in, out) + n_out*31
    witness: 1 + 1 + 72 + 1 + 33
    '''
    if txtype == 'p2pkh':
        return 4 + 4 + 2 + ins*148 + 34*outs + (
            OUTPUT_EXTRA_BYTES[txtype][outtype]
            if outtype and outtype in OUTPUT_EXTRA_BYTES[txtype] else 0)
    elif txtype == 'p2sh-p2wpkh':
        #return the estimate for the witness and non-witness
        #portions of the transaction, assuming that all the inputs
        #are of segwit type p2sh-p2wpkh
        # Note as of Jan19: this misses 2 bytes (trivial) for len in, out
        # and also overestimates output size by 2 bytes.
        witness_estimate = ins*108
        non_witness_estimate = 4 + 4 + 4 + outs*32 + ins*64 + (
            OUTPUT_EXTRA_BYTES[txtype][outtype]
            if outtype and outtype in OUTPUT_EXTRA_BYTES[txtype] else 0)
        return (witness_estimate, non_witness_estimate)
    elif txtype == 'p2wpkh':
        witness_estimate = ins*108
        non_witness_estimate = 4 + 4 + 4 + outs*31 + ins*41 + (
            OUTPUT_EXTRA_BYTES[txtype][outtype]
            if outtype and outtype in OUTPUT_EXTRA_BYTES[txtype] else 0)
        return (witness_estimate, non_witness_estimate)
    elif txtype == 'p2shMofN':
        ins, M, N = ins
        return 4 + 4 + 2 + (45 + 73*M + 34*N)*ins + outs*32 + (
            OUTPUT_EXTRA_BYTES['p2sh-p2wpkh'][outtype]
            if outtype and outtype in OUTPUT_EXTRA_BYTES['p2sh-p2wpkh'] else 0)
    else:
        raise NotImplementedError("Transaction size estimation not" +
                                  "yet implemented for type: " + txtype)

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
    usehex = False
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
    return CScript([btc.OP_RETURN, data])

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
