from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401

from binascii import unhexlify

from .pythonpsbt import (Creator,
                        Updater,
                        Signer,
                        Input_Finalizer,
                        Transaction_Extractor
                        )

def convert_ins_format_for_creator(ins):
    """ Takes transaction inputs as formatted in jmbitcoin
    and converts them into required format for PSBT creation.
    """

    return [(unhexlify(x['outpoint']['hash']),
             x['outpoint']['index']) for x in ins]

def convert_outs_format_for_creator(outs):
    """ Takes transaction outputs as formatted in jmbitcoin
    and converts them into required format for PSBT creation.
    """
    return [(x["value"], unhexlify(x["script"])) for x in outs]

def create_psbt(tx, ins_segwit_utxos):
    """ Takes a deserialized bitcoin transaction(as formatted
    in this jmbitcoin library), and creates the PSBT object initialized
    with no signatures or data, and returns both the PSBT Updater object
    and the network serialized bitcoin transaction, for convenience.
    ins_segwit_utxos should be a list of (amount, scriptPubkey)
    for each input, in order.
    Currently supports segwit inputs only.
    """
    ins = convert_ins_format_for_creator(tx['ins'])
    outs = convert_outs_format_for_creator(tx['outs'])
    creator = Creator(ins, outs, tx_version=tx['version'],
                      locktime=tx['locktime'])
    updater = Updater(creator.serialized())
    for i in range(len(ins)):
        # note: we do not use the add_witness_utxo method
        # of the Updater object, because it requires the full
        # transaction containing the utxo, which rather misses
        # the point: we can add just the single transaction output
        # without knowing the full transaction.
        updater.add_witness_utxo_from_txout(i, *ins_segwit_utxos[i])
    return updater, get_tx_from_psbt(updater)

def update_our_inputs(updater, ins, prevtxs, prevtxindices, indices, psbt_serialized):
    """ Given a list of inputs `ins` as formatted deserialized
    in jmbitcoin, at indices `indices` (list of ints), each of which came from a
    tx as serialized in prevtxs, from output index in prevtxindices,
    update the corresponding inputs in serialized psbt `psbt_serialized`,
    to prepare for signing.
    For simplicity we assume only one input type p2sh-p2wpkh as per JM default.
    """
    for i, j in enumerate(indices):
        updater.add_witness_utxo(j, prevtxs[i], prevtxindices[i])
        updater.add_input_redeem_script(j, ins[i]['script'])
    return updater.psbt.serialize()

def get_tx_from_psbt(psbt_tx):
    """ Takes as argument an object of type psbt,
    and retruns the network serialized transaction.
    """
    return psbt_tx.get_unsigned_tx()

def sign_psbt(psbt_tx, input_index, sig, pub):
    """ Takes a serialized PSBT, an index, signature
    and pubkey and returns a new serialized PSBT
    including the added signature.
    """
    updater = Updater(psbt_tx)
    updater.add_sighash_type(input_index, sig[-1])
    signer = Signer(updater.psbt.serialize())
    signer.add_partial_signature(sig, pub, input_index=input_index)
    return signer.psbt.serialize()

def extract_final_tx_from_psbt(psbt_tx):
    """ Takes a serialized PSBT and attempts to
    finalize it, then extract a network serialized and
    validly signed Bitcoin transaction. If the
    finalization fails, None is returned.
    """
    # note the constructor performs finalization automatically.
    finalizer = Input_Finalizer(psbt_tx)
    extractor = Transaction_Extractor(finalizer.serialized())
    return extractor.psbt, extractor.serialized()
