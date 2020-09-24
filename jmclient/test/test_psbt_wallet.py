#! /usr/bin/env python
'''Test of psbt creation, update, signing and finalizing
   using the functionality of the PSBT Wallet Mixin.
   Note that Joinmarket's PSBT code is a wrapper around
   bitcointx.core.psbt, and the basic test vectors for
   BIP174 are tested there, not here.
   '''

import copy
from commontest import make_wallets, dummy_accept_callback, dummy_info_callback

import jmbitcoin as bitcoin
import pytest
from jmbase import get_log, bintohex, hextobin
from jmclient import (load_test_config, jm_single, direct_send,
                      SegwitLegacyWallet, SegwitWallet, LegacyWallet)
from jmclient.wallet import PSBTWalletMixin
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
    print("human readable: ")
    print(wallet_service.human_readable_psbt(newpsbt))
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
    #(0.95, SegwitLegacyWallet, SegwitWallet),
    #(0.05, SegwitWallet, SegwitLegacyWallet),
    #(0.95, SegwitWallet, SegwitWallet),
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

    print("Initial payment PSBT created:\n{}".format(
        wallet_s.human_readable_psbt(payment_psbt)))
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

    # Simple receiver utxo choice heuristic.
    # For more generality we test with two receiver-utxos, not one.
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
    print(bitcoin.human_readable_transaction(unsigned_payjoin_tx))
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
    print("Receiver created payjoin PSBT:\n{}".format(
        wallet_r.human_readable_psbt(r_payjoin_psbt)))

    signresultandpsbt, err = wallet_r.sign_psbt(r_payjoin_psbt.serialize(),
                                                with_sign_result=True)
    assert not err, err
    signresult, receiver_signed_psbt = signresultandpsbt
    assert signresult.num_inputs_final == len(receiver_utxos)
    assert not signresult.is_final

    print("Receiver signing successful. Payjoin PSBT is now:\n{}".format(
        wallet_r.human_readable_psbt(receiver_signed_psbt)))

    # *** STEP 3 ***
    # **************

    # take the half-signed PSBT, validate and co-sign:

    signresultandpsbt, err = wallet_s.sign_psbt(
        receiver_signed_psbt.serialize(), with_sign_result=True)
    assert not err, err
    signresult, sender_signed_psbt =  signresultandpsbt
    print("Sender's final signed PSBT is:\n{}".format(
        wallet_s.human_readable_psbt(sender_signed_psbt)))
    assert signresult.is_final

    # broadcast the tx
    extracted_tx = sender_signed_psbt.extract_transaction().serialize()
    assert jm_single().bc_interface.pushtx(extracted_tx)

""" test vector data for human readable parsing only,
they are taken from bitcointx/tests/test_psbt.py and in turn
taken from BIP174 test vectors.
TODO add more, but note we are not testing functionality here.
"""
hr_test_vectors = {
# PSBT with one P2PKH input. Outputs are empty
"one-p2pkh": '70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab300000000000000',
# PSBT with one P2PKH input and one P2SH-P2WPKH input.
# First input is signed and finalized. Outputs are empty
"first-input-signed": '70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac000000000001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000',
# PSBT with one P2PKH input which has a non-final scriptSig
# and has a sighash type specified. Outputs are empty
"nonfinal-scriptsig": '70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000001030401000000000000',
# PSBT with one P2PKH input and one P2SH-P2WPKH input both with
# non-final scriptSigs. P2SH-P2WPKH input's redeemScript is available.
# Outputs filled.
"mixed-inputs-nonfinal": '70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000000100df0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e13000001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb8230800220202ead596687ca806043edc3de116cdf29d5e9257c196cd055cf698c8d02bf24e9910b4a6ba670000008000000080020000800022020394f62be9df19952c5587768aeb7698061ad2c4a25c894f47d8c162b4d7213d0510b4a6ba6700000080010000800200008000',
# PSBT with one P2SH-P2WSH input of a 2-of-2 multisig, redeemScript,
# witnessScript, and keypaths are available. Contains one signature.
"2-2-multisig-p2wsh": '70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000',
# PSBT with unknown types in the inputs
"unknown-input-types": '70736274ff01003f0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000ffffffff010000000000000000036a010000000000000a0f0102030405060708090f0102030405060708090a0b0c0d0e0f0000',
# PSBT with `PSBT_GLOBAL_XPUB`
"global-xpub": '70736274ff01009d0100000002710ea76ab45c5cb6438e607e59cc037626981805ae9e0dfd9089012abb0be5350100000000ffffffff190994d6a8b3c8c82ccbcfb2fba4106aa06639b872a8d447465c0d42588d6d670000000000ffffffff0200e1f505000000001976a914b6bc2c0ee5655a843d79afedd0ccc3f7dd64340988ac605af405000000001600141188ef8e4ce0449eaac8fb141cbf5a1176e6a088000000004f010488b21e039e530cac800000003dbc8a5c9769f031b17e77fea1518603221a18fd18f2b9a54c6c8c1ac75cbc3502f230584b155d1c7f1cd45120a653c48d650b431b67c5b2c13f27d7142037c1691027569c503100008000000080000000800001011f00e1f5050000000016001433b982f91b28f160c920b4ab95e58ce50dda3a4a220203309680f33c7de38ea6a47cd4ecd66f1f5a49747c6ffb8808ed09039243e3ad5c47304402202d704ced830c56a909344bd742b6852dccd103e963bae92d38e75254d2bb424502202d86c437195df46c0ceda084f2a291c3da2d64070f76bf9b90b195e7ef28f77201220603309680f33c7de38ea6a47cd4ecd66f1f5a49747c6ffb8808ed09039243e3ad5c1827569c5031000080000000800000008000000000010000000001011f00e1f50500000000160014388fb944307eb77ef45197d0b0b245e079f011de220202c777161f73d0b7c72b9ee7bde650293d13f095bc7656ad1f525da5fd2e10b11047304402204cb1fb5f869c942e0e26100576125439179ae88dca8a9dc3ba08f7953988faa60220521f49ca791c27d70e273c9b14616985909361e25be274ea200d7e08827e514d01220602c777161f73d0b7c72b9ee7bde650293d13f095bc7656ad1f525da5fd2e10b1101827569c5031000080000000800000008000000000000000000000220202d20ca502ee289686d21815bd43a80637b0698e1fbcdbe4caed445f6c1a0a90ef1827569c50310000800000008000000080000000000400000000',
# PSBT with proprietary values
"proprietary-values": '70736274ff0100550200000001ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff018e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac0000000015fc0a676c6f62616c5f706678016d756c7469706c790563686965660001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb823080ffc06696e5f706678fde80377686174056672616d650afc00fe40420f0061736b077361746f7368690012fc076f75745f706678feffffff01636f726e05746967657217fc076f75745f706678ffffffffffffffffff707570707905647269766500'
}

def test_hr_psbt(setup_psbt_wallet):
    bitcoin.select_chain_params("bitcoin")
    for k, v in hr_test_vectors.items():
        print(PSBTWalletMixin.human_readable_psbt(
            bitcoin.PartiallySignedTransaction.from_binary(hextobin(v))))
    bitcoin.select_chain_params("bitcoin/regtest")

@pytest.fixture(scope="module")
def setup_psbt_wallet():
    load_test_config()
