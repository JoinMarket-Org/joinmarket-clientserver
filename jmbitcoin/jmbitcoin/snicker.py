from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401

# Implementation of proposal as per
# https://gist.github.com/AdamISZ/2c13fb5819bd469ca318156e2cf25d79
# (BIP SNICKER)

from jmbitcoin.secp256k1_ecdh import *
from jmbitcoin.secp256k1_ecies import *
from jmbitcoin.secp256k1_main import *
from jmbitcoin.secp256k1_transaction import *
from jmbitcoin.jm_psbt import *
from .pythonpsbt import PSBT_IN_PARTIAL_SIG

SNICKER_MAGIC_BYTES = b'SNICKER'

# Flags may be added in future versions
SNICKER_FLAG_NONE = 0

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

def verify_output(tx, pub, tweak, spk_type='p2sh-p2wpkh'):
    """ A convenience function to check that one output address in a transaction
    is a SNICKER-type tweak of an existing key. Returns the index of the output
    for which this is True (and there must be only 1), and the derived spk,
    or -1 and None if it is not found exactly once.
    TODO Add support for other scriptPubKey types.
    """
    expected_destination_pub = snicker_pubkey_tweak(pub, tweak)
    expected_destination_spk = pubkey_to_p2sh_p2wpkh_script(expected_destination_pub)
    found = 0
    for i, o in enumerate(tx['outs']):
        if o['script'] == expected_destination_spk:
            found += 1
            found_index = i
    if found != 1:
        return -1, None
    return found_index, expected_destination_spk

def create_proposal(our_input, their_input, our_input_utxo, their_input_utxo,
                    net_transfer, network_fee, our_priv, their_pub,
                    our_spk, change_spk, encrypted=True, version_byte=1):
    """ Creates a SNICKER proposal from the given transaction data.
    This only applies to existing specification, i.e. SNICKER v 00 or 01.
    This is only to be used for Joinmarket as currently restricted to p2sh-p2wpkh.
    `our_input`, `their_input` - in format of deserialized inputs in jmbitcoin
    `our_input_utxo`, `their..` - in format (amount, scriptPubkey)
    net_transfer - amount, after bitcoin transaction fee, transferred from
    Proposer (our) to Receiver (their). May be negative.
    network_fee - total bitcoin network transaction fee to be paid (so estimates
    must occur before this function).
    `our_priv`, `their_pub` - these are the keys to be used in ECDH to derive
    the tweak as per the BIP. Note `their_pub` may or may not be associated with
    the input of the receiver, so is specified here separately. Note also that
    according to the BIP the privkey we use *must* be the one corresponding to
    the input we provided, else (properly coded) Receivers will reject our
    proposal.
    `our_spk` - a scriptPubKey for the Proposer coinjoin output
    `change_spk` - a change scriptPubkey for the proposer as per BIP
    `encrypted` - whether or not to return the ECIES encrypted version of the
    proposal.
    `version_byte` - which of currently specified Snicker versions is being
    used, (0 for reused address, 1 for inferred key).
    """
    # before constructing the bitcoin transaction we must calculate the output
    # amounts
    # TODO investigate arithmetic for negative transfer
    if our_input_utxo[0] - their_input_utxo[0] - network_fee <= 0:
        raise Exception(
            "Cannot create SNICKER proposal, Proposer input too small")
    total_input_amount = our_input_utxo[0] + their_input_utxo[0]
    total_output_amount = total_input_amount - network_fee
    receiver_output_amount = their_input_utxo[0] + net_transfer
    proposer_output_amount = total_output_amount - receiver_output_amount

    # we must also use ecdh to calculate the output scriptpubkey for the
    # receiver
    # TODO: add check here that `our_priv` corresponds to scriptPubKey in
    # `our_input_utxo` to prevent callers from making useless proposals.
    tweak_bytes = ecdh(our_priv[:-1], their_pub)
    tweaked_pub = snicker_pubkey_tweak(their_pub, tweak_bytes)
    # TODO: remove restriction to one scriptpubkey type
    tweaked_spk = pubkey_to_p2sh_p2wpkh_script(tweaked_pub)

    # now we must construct the three outputs with correct output amounts.
    outputs = [{"script": tweaked_spk, "value": receiver_output_amount}]
    outputs.append({"script": our_spk, "value": receiver_output_amount})
    outputs.append({"script": change_spk,
                    "value": total_output_amount - 2 * receiver_output_amount})
    assert all([x["value"] > 0 for x in outputs])

    # version and locktime as currently specified in the BIP
    # for 0/1 version SNICKER.
    tx = mktx([our_input, their_input], outputs, version=2, locktime=0)

    # Apply lexicographic ordering BIP 69:
    desertx = btc.deserialize(tx)
    bip69tx = bip69_sort(desertx)

    # input utxo data must be attached to the right input, according to
    # BIP69 ordering. Since v0/1 only use 2 inputs, this is fairly simple:
    if bip69tx["ins"] == desertx["ins"]:
        utxoargs = (our_input_utxo, their_input_utxo)
        signing_index = 0
    else:
        utxoargs = (their_input_utxo, our_input_utxo)
        signing_index = 1
    updater, nserialized = create_psbt(bip69tx, utxoargs)

    # having created the PSBT, sign our input
    updater.add_input_redeem_script(signing_index, pubkey_to_p2wpkh_script(
        privkey_to_pubkey(our_priv, False)))
    updater.add_sighash_type(signing_index, 1)

    signer = Signer(updater.psbt.serialize())
    signed_serialized = sign(nserialized, signing_index, our_priv,
                             amount=our_input_utxo[0])
    signed_deserialized = deserialize(signed_serialized)
    sig, pub = [binascii.unhexlify(x) for x in signed_deserialized['ins']
                [signing_index]['txinwitness']]
    partially_signed_psbt = sign_psbt(signer.psbt.serialize(),
                                      signing_index, sig, pub)

    snicker_serialized_message = SNICKER_MAGIC_BYTES + bytes([version_byte]) + \
        b'\x00' + tweak_bytes + partially_signed_psbt

    if not encrypted:
        return snicker_serialized_message

    # encryption has been requested; we apply ECIES in the form given by the BIP.
    return ecies_encrypt(snicker_serialized_message, their_pub)

def parse_proposal_to_signed_tx(privkey, proposal, acceptance_callback):
    """ Given a candidate privkey (binary and compressed format),
    and a candidate encrypted SNICKER proposal, attempt to decrypt
    and validate it in all aspects. If validation fails the first
    return value is None and the second is the reason as a string.

    If all validation checks pass, the next step is checking
    acceptance according to financial rules: the acceptance
    callback must be a function that accepts four arguments:
    (our_ins, their_ins, our_outs, their_outs), where each of those
    arguments are dicts of the format used in jmbitcoin transaction
    deserialization) and must return only True/False where True
    means that the transaction should be signed.

    If True is returned from the callback, the following are returned
    from this function:
    (raw transaction for signing [deserialized, with other signature
    attached], tweak value as bytes, unsigned_index,
    derived output spk belonging to receiver, version, flags), "Valid"
    Note: flags is currently always None as version is only 0 or 1.
    """

    our_pub = privkey_to_pubkey(privkey, usehex=False)

    if len(proposal) < 5:
        return None, "Invalid proposal, too short."

    if base64.b64decode(proposal)[:4] == ECIES_MAGIC_BYTES:
        # attempt decryption and reject if fails:
        try:
            snicker_message = ecies_decrypt(privkey, proposal)
        except Exception as e:
            return None, "Failed to decrypt." + repr(e)
    else:
        snicker_message = proposal

    # magic + version,flag + tweak + psbt:
    # TODO replace '20' with the minimum feasible PSBT.
    if len(snicker_message) < 7 + 2 + 32 + 20:
        return None, "Invalid proposal, too short."

    if snicker_message[:7] != SNICKER_MAGIC_BYTES:
        return None, "Invalid SNICKER magic bytes."

    version_byte = snicker_message[7]
    flag_byte = snicker_message[8]
    if version_byte not in [0,1]:
        return None, "Unrecognized SNICKER version: " + version_byte
    if flag_byte != 0:
        return None, "Invalid flag byte for version 0,1: " + flag_byte

    tweak_bytes = snicker_message[9:41]
    candidate_psbt = snicker_message[41:]
    # attempt to validate the PSBT's format:
    try:
        updater = Updater(candidate_psbt)
    except:
        return None, "Invalid PSBT format."

    # validate that it contains one signature,
    # else the proposal is invalid:
    # TODO this code should be encapsulated in the PSBT
    # implementation, but the current one is rudimentary.
    ins = updater.psbt.maps['inputs']
    if len(ins) != 2:
        return None, "Invalid number of transaction inputs, must be 2."
    sig_found = 0
    for j, i in enumerate(ins):
        for k, v in i.items():
            if k[0] == ord(PSBT_IN_PARTIAL_SIG):
                # TODO actually validate here?
                if k[1] not in [2, 3]:
                    return None, "Invalid public key."
                if v[0] != 48 or len(v) < 8:
                    return None, "Invalid ECDSA signature"
                sig_found += 1
                their_index = j
                break
    if sig_found != 1:
        return None, "There must be exactly one signed input."

    # TODO Ver 0/1 has only 2 inputs, change for other versions.
    unsigned_index = 0 if their_index == 1 else 1

    raw_transaction = deserialize(updater.get_unsigned_tx())

    # check that BIP 69 was applied
    check_raw_tx = bip69_sort(raw_transaction)
    if not check_raw_tx == raw_transaction:
        return None, "The proposed transaction is not BIP69 sorted."

    # Validate that we own one SNICKER style output:
    spk = verify_output(raw_transaction, our_pub, tweak_bytes)

    if spk[0] == -1:
        return None, "Correct tweaked destination not found exactly once in outputs."
    our_output_index = spk[0]
    our_output_amount = raw_transaction['outs'][our_output_index]['value']

    # At least one other output must have an amount equal to that at
    # `our_output_index`, according to the spec.
    found = 0
    for i, o in enumerate(raw_transaction['outs']):
        if i == our_output_index:
            continue
        if o['value'] == our_output_amount:
            found += 1
    if found != 1:
        return None, "Invalid coinjoin, there are not two equal outputs."

    # All validation checks passed. We now check whether the
    #transaction is acceptable according to the caller:
    if not acceptance_callback([raw_transaction['ins'][unsigned_index]],
                               [raw_transaction['ins'][their_index]],
                               [raw_transaction['outs'][our_output_index]],
                               [x for i, x in enumerate(raw_transaction['outs']) if i != our_output_index]):
        return None, "Caller rejected transaction for signing."

    # Acceptance passed, prepare the deserialized tx for signing by us:
    # TODO This is p2sh-p2wpkh specific
    # TODO consider how to generalize this *without* requiring jmclient
    # to do PSBT processing itself.
    m = updater.psbt.maps['inputs'][their_index]
    for k,v in m.items():
        if k[0] == ord(PSBT_IN_PARTIAL_SIG):
            pub = k[1:]
            sig = v #check that
    raw_transaction['ins'][their_index]['script'] = b'\x16' + pubkey_to_p2wpkh_script(pub)
    raw_transaction['ins'][their_index]['txinwitness'] = [sig, pub]

    # Return the data in detail to
    # the caller (see docstring):
    return (raw_transaction, tweak_bytes, unsigned_index,
            spk[1], version_byte, flag_byte)
