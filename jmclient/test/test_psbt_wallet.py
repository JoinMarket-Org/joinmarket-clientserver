#! /usr/bin/env python
'''Test of psbt creation, update, signing and finalizing
   using the functionality of the PSBT Wallet Mixin.
   Note that Joinmarket's PSBT code is a wrapper around
   bitcointx.core.psbt, and the basic test vectors for
   BIP174 are tested there, not here.
   '''

import time
import binascii
import struct
import copy
from commontest import make_wallets, dummy_accept_callback, dummy_info_callback

import jmbitcoin as bitcoin
import pytest
from jmbase import get_log, bintohex, hextobin
from jmclient import (load_test_config, jm_single, direct_send,
                      SegwitLegacyWallet, SegwitWallet, LegacyWallet)

log = get_log()

def test_create_and_sign_psbt_with_legacy(setup_psbt_wallet):
    """ The purpose of this test is to check that we can create and
    then partially sign a PSBT where we own one input and the other input
    is of legacy p2pkh type.
    """
    wallet_service = make_wallets(1, [[1,0,0,0,0]], 1)[0]['wallet']
    wallet_service.sync_wallet(fast=True)
    utxos = wallet_service.select_utxos(0, bitcoin.coins_to_satoshi(0.5))
    assert len(utxos) == 1
    # create a legacy address and make a payment into it
    legacy_addr = bitcoin.CCoinAddress.from_scriptPubKey(
        bitcoin.pubkey_to_p2pkh_script(
            bitcoin.privkey_to_pubkey(b"\x01"*33)))
    tx = direct_send(wallet_service, bitcoin.coins_to_satoshi(0.3), 0,
                       str(legacy_addr), accept_callback=dummy_accept_callback,
                       info_callback=dummy_info_callback,
                       return_transaction=True)
    assert tx
    # this time we will have one utxo worth <~ 0.7
    my_utxos = wallet_service.select_utxos(0, bitcoin.coins_to_satoshi(0.5))
    assert len(my_utxos) == 1
    # find the outpoint for the legacy address we're spending
    n = -1
    for i, t in enumerate(tx.vout):
        if bitcoin.CCoinAddress.from_scriptPubKey(t.scriptPubKey) == legacy_addr:
            n = i
    assert n > -1
    utxos = copy.deepcopy(my_utxos)
    utxos[(tx.GetTxid()[::-1], n)] ={"script": legacy_addr.to_scriptPubKey(),
              "value": bitcoin.coins_to_satoshi(0.3)}
    outs = [{"value": bitcoin.coins_to_satoshi(0.998),
                 "address": wallet_service.get_addr(0,0,0)}]
    tx2 = bitcoin.mktx(list(utxos.keys()), outs)
    spent_outs = wallet_service.witness_utxos_to_psbt_utxos(my_utxos)
    spent_outs.append(tx)
    new_psbt = wallet_service.create_psbt_from_tx(tx2, spent_outs)
    signed_psbt_and_signresult, err = wallet_service.sign_psbt(
        new_psbt.serialize(), with_sign_result=True)
    assert err is None
    signresult, signed_psbt = signed_psbt_and_signresult
    assert signresult.num_inputs_signed == 1
    assert signresult.num_inputs_final == 1
    assert not signresult.is_final

@pytest.mark.parametrize('unowned_utxo, wallet_cls', [
    (True, SegwitLegacyWallet),
    (False, SegwitLegacyWallet),
    (True, SegwitWallet),
    (False, SegwitWallet),
    (True, LegacyWallet),
    (False, LegacyWallet),
])
def test_create_psbt_and_sign(setup_psbt_wallet, unowned_utxo, wallet_cls):
    """ Plan of test:
    1. Create a wallet and source 3 destination addresses.
    2. Make, and confirm, transactions that fund the 3 addrs.
    3. Create a new tx spending 2 of those 3 utxos and spending
       another utxo we don't own (extra is optional per `unowned_utxo`).
    4. Create a psbt using the above transaction and corresponding
       `spent_outs` field to fill in the redeem script.
    5. Compare resulting PSBT with expected structure.
    6. Use the wallet's sign_psbt method to sign the whole psbt, which
       means signing each input we own.
    7. Check that each input is finalized as per expected. Check that the whole
       PSBT is or is not finalized as per whether there is an unowned utxo.
    8. In case where whole psbt is finalized, attempt to broadcast the tx.
    """
    # steps 1 and 2:
    wallet_service = make_wallets(1, [[3,0,0,0,0]], 1,
                                  wallet_cls=wallet_cls)[0]['wallet']
    wallet_service.sync_wallet(fast=True)
    utxos = wallet_service.select_utxos(0, bitcoin.coins_to_satoshi(1.5))
    # for legacy wallets, psbt creation requires querying for the spending
    # transaction:
    if wallet_cls == LegacyWallet:
        fulltxs = []
        for utxo, v in utxos.items():
            fulltxs.append(jm_single().bc_interface.get_deser_from_gettransaction(
                jm_single().bc_interface.get_transaction(utxo[0])))

    assert len(utxos) == 2
    u_utxos = {}
    if unowned_utxo:
        # note: tx creation uses the key only; psbt creation uses the value,
        # which can be fake here; we do not intend to attempt to fully
        # finalize a psbt with an unowned input. See
        # https://github.com/Simplexum/python-bitcointx/issues/30
        # the redeem script creation (which is artificial) will be
        # avoided in future.
        priv = b"\xaa"*32 + b"\x01"
        pub = bitcoin.privkey_to_pubkey(priv)
        script = bitcoin.pubkey_to_p2sh_p2wpkh_script(pub)
        redeem_script = bitcoin.pubkey_to_p2wpkh_script(pub)
        u_utxos[(b"\xaa"*32, 12)] = {"value": 1000, "script": script}
    utxos.update(u_utxos)
    # outputs aren't interesting for this test (we selected 1.5 but will get 2):
    outs = [{"value": bitcoin.coins_to_satoshi(1.999),
             "address": wallet_service.get_addr(0,0,0)}]
    tx = bitcoin.mktx(list(utxos.keys()), outs)

    if wallet_cls != LegacyWallet:
        spent_outs = wallet_service.witness_utxos_to_psbt_utxos(utxos)
    else:
        spent_outs = fulltxs
        # the extra input is segwit:
        if unowned_utxo:
            spent_outs.extend(
                wallet_service.witness_utxos_to_psbt_utxos(u_utxos))
    newpsbt = wallet_service.create_psbt_from_tx(tx, spent_outs)
    # see note above
    if unowned_utxo:
        newpsbt.inputs[-1].redeem_script = redeem_script
    print(bintohex(newpsbt.serialize()))
    # we cannot compare with a fixed expected result due to wallet randomization, but we can
    # check psbt structure:
    expected_inputs_length = 3 if unowned_utxo else 2
    assert len(newpsbt.inputs) == expected_inputs_length
    assert len(newpsbt.outputs) == 1
    # note: redeem_script field is a CScript which is a bytes instance,
    # so checking length is best way to check for existence (comparison
    # with None does not work):
    if wallet_cls == SegwitLegacyWallet:
        assert len(newpsbt.inputs[0].redeem_script) != 0
        assert len(newpsbt.inputs[1].redeem_script) != 0
    if unowned_utxo:
        assert newpsbt.inputs[2].redeem_script == redeem_script

    signed_psbt_and_signresult, err = wallet_service.sign_psbt(
        newpsbt.serialize(), with_sign_result=True)
    assert err is None
    signresult, signed_psbt = signed_psbt_and_signresult
    expected_signed_inputs = len(utxos) if not unowned_utxo else len(utxos)-1
    assert signresult.num_inputs_signed == expected_signed_inputs
    assert signresult.num_inputs_final == expected_signed_inputs

    if not unowned_utxo:
        assert signresult.is_final
        # only in case all signed do we try to broadcast:
        extracted_tx = signed_psbt.extract_transaction().serialize()
        assert jm_single().bc_interface.pushtx(extracted_tx)
    else:
        # transaction extraction must fail for not-fully-signed psbts:
        with pytest.raises(ValueError) as e:
            extracted_tx = signed_psbt.extract_transaction()

@pytest.mark.parametrize('payment_amt, wallet_cls_sender, wallet_cls_receiver', [
    (0.05, SegwitLegacyWallet, SegwitLegacyWallet),
    (0.95, SegwitLegacyWallet, SegwitWallet),
    (0.05, SegwitWallet, SegwitLegacyWallet),
    (0.95, SegwitWallet, SegwitWallet),
])
def test_payjoin_workflow(setup_psbt_wallet, payment_amt, wallet_cls_sender,
                          wallet_cls_receiver):
    """ Workflow step 1:
    Create a payment from a wallet, and create a finalized PSBT.
    This step is fairly trivial as the functionality is built-in to
    PSBTWalletMixin.
    Note that only Segwit* wallets are supported for PayJoin.

        Workflow step 2:
    Receiver creates a new partially signed PSBT with the same amount
    and at least one more utxo.

        Workflow step 3:
    Given a partially signed PSBT created by a receiver, here the sender
    completes (co-signs) the PSBT they are given. Note this code is a PSBT
    functionality check, and does NOT include the detailed checks that
    the sender should perform before agreeing to sign (see:
    https://github.com/btcpayserver/btcpayserver-doc/blob/eaac676866a4d871eda5fd7752b91b88fdf849ff/Payjoin-spec.md#receiver-side
    ).
    """

    wallet_r = make_wallets(1, [[3,0,0,0,0]], 1,
                    wallet_cls=wallet_cls_receiver)[0]["wallet"]
    wallet_s = make_wallets(1, [[3,0,0,0,0]], 1,
                        wallet_cls=wallet_cls_sender)[0]["wallet"]
    for w in [wallet_r, wallet_s]:
        w.sync_wallet(fast=True)

    # destination address for payment:
    destaddr = str(bitcoin.CCoinAddress.from_scriptPubKey(
        bitcoin.pubkey_to_p2wpkh_script(bitcoin.privkey_to_pubkey(b"\x01"*33))))

    payment_amt = bitcoin.coins_to_satoshi(payment_amt)

    # *** STEP 1 ***
    # **************

    # create a normal tx from the sender wallet:
    payment_psbt = direct_send(wallet_s, payment_amt, 0, destaddr,
                    accept_callback=dummy_accept_callback,
                    info_callback=dummy_info_callback,
                    with_final_psbt=True)

    # ensure that the payemnt amount is what was intended:
    out_amts = [x.nValue for x in payment_psbt.unsigned_tx.vout]
    # NOTE this would have to change for more than 2 outputs:
    assert any([out_amts[i] == payment_amt for i in [0, 1]])

    # ensure that we can actually broadcast the created tx:
    # (note that 'extract_transaction' represents an implicit
    # PSBT finality check).
    extracted_tx = payment_psbt.extract_transaction().serialize()
    # don't want to push the tx right now, because of test structure
    # (in production code this isn't really needed, we will not
    # produce invalid payment transactions).
    res = jm_single().bc_interface.rpc('testmempoolaccept',
                                       [[bintohex(extracted_tx)]])
    assert res[0]["allowed"], "Payment transaction was rejected from mempool."

    # *** STEP 2 ***
    # **************

    # This step will not be in Joinmarket code for the first cut,
    # it will be done by the merchant, but included here for the data flow.
    # receiver grabs a random utxo here (as per previous sentence, this is
    # the merchant's responsibility, not ours, but see earlier code in
    # jmclient.maker.P2EPMaker for possibe heuristics).
    # for more generality we test with two receiver-utxos, not one.
    all_receiver_utxos = wallet_r.get_all_utxos()
    # TODO is there a less verbose way to get any 2 utxos from the dict?
    receiver_utxos_keys = list(all_receiver_utxos.keys())[:2]
    receiver_utxos = {k: v for k, v in all_receiver_utxos.items(
        ) if k in receiver_utxos_keys}

    # receiver will do other checks as discussed above, including payment
    # amount; as discussed above, this is out of the scope of this PSBT test.

    # construct unsigned tx for payjoin-psbt:
    payjoin_tx_inputs = [(x.prevout.hash[::-1],
                x.prevout.n) for x in payment_psbt.unsigned_tx.vin]
    payjoin_tx_inputs.extend(receiver_utxos.keys())
    # find payment output and change output
    pay_out = None
    change_out = None
    for o in payment_psbt.unsigned_tx.vout:
        jm_out_fmt = {"value": o.nValue,
        "address": str(bitcoin.CCoinAddress.from_scriptPubKey(
        o.scriptPubKey))}
        if o.nValue == payment_amt:
            assert pay_out is None
            pay_out = jm_out_fmt
        else:
            assert change_out is None
            change_out = jm_out_fmt

    # we now know there were two outputs and know which is payment.
    # bump payment output with our input:
    outs = [pay_out, change_out]
    our_inputs_val = sum([v["value"] for _, v in receiver_utxos.items()])
    pay_out["value"] += our_inputs_val
    print("we bumped the payment output value by: ", our_inputs_val)
    print("It is now: ", pay_out["value"])
    unsigned_payjoin_tx = bitcoin.make_shuffled_tx(payjoin_tx_inputs, outs,
                                version=payment_psbt.unsigned_tx.nVersion,
                                locktime=payment_psbt.unsigned_tx.nLockTime)
    print("we created this unsigned tx: ")
    print(unsigned_payjoin_tx)
    # to create the PSBT we need the spent_outs for each input,
    # in the right order:
    spent_outs = []
    for i, inp in enumerate(unsigned_payjoin_tx.vin):
        input_found = False
        for j, inp2 in enumerate(payment_psbt.unsigned_tx.vin):
            if inp.prevout == inp2.prevout:
                spent_outs.append(payment_psbt.inputs[j].utxo)
                input_found = True
                break
        if input_found:
            continue
        # if we got here this input is ours, we must find
        # it from our original utxo choice list:
        for ru in receiver_utxos.keys():
            if (inp.prevout.hash[::-1], inp.prevout.n) == ru:
                spent_outs.append(
                    wallet_r.witness_utxos_to_psbt_utxos(
                        {ru: receiver_utxos[ru]})[0])
                input_found = True
                break
        # there should be no other inputs:
        assert input_found

    r_payjoin_psbt = wallet_r.create_psbt_from_tx(unsigned_payjoin_tx,
                                                  spent_outs=spent_outs)
    signresultandpsbt, err = wallet_r.sign_psbt(r_payjoin_psbt.serialize(),
                                                with_sign_result=True)
    assert not err, err
    signresult, receiver_signed_psbt = signresultandpsbt
    assert signresult.num_inputs_final == len(receiver_utxos)
    assert not signresult.is_final

    # *** STEP 3 ***
    # **************

    # take the half-signed PSBT, validate and co-sign:

    signresultandpsbt, err = wallet_s.sign_psbt(
        receiver_signed_psbt.serialize(), with_sign_result=True)
    assert not err, err
    signresult, sender_signed_psbt =  signresultandpsbt
    assert signresult.is_final
    # broadcast the tx
    extracted_tx = sender_signed_psbt.extract_transaction().serialize()
    assert jm_single().bc_interface.pushtx(extracted_tx)

@pytest.fixture(scope="module")
def setup_psbt_wallet():
    load_test_config()
