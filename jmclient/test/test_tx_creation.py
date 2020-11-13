#! /usr/bin/env python
'''Test of unusual transaction types creation and push to
   network to check validity.
   Note as of Feb 2020: earlier versions included multisig
   p2(w)sh tests, these have been removed since Joinmarket
   does not use this feature.'''

import struct
from commontest import make_wallets, make_sign_and_push, ensure_bip65_activated

import jmbitcoin as bitcoin
import pytest
from jmbase import get_log
from jmclient import load_test_config, jm_single

log = get_log()
#just a random selection of pubkeys for receiving multisigs;
#if we ever need the privkeys, they are in a json file somewhere
vpubs = ["03e9a06e539d6bf5cf1ca5c41b59121fa3df07a338322405a312c67b6349a707e9",
         "0280125e42c1984923106e281615dfada44d38c4125c005963b322427110d709d6",
         "02726fa5b19e9406aaa46ee22fd9e81a09dd5eb7c87505b93a11efcf4b945e778c",
         "03600a739be32a14938680b3b3d61b51f217a60df118160d0decab22c9e1329862",
         "028a2f126e3999ff66d01dcb101ab526d3aa1bf5cbdc4bde14950a4cead95f6fcb",
         "02bea84d70e74f7603746b62d79bf035e16d982b56e6a1ee07dfd3b9130e8a2ad9"]

def test_all_same_priv(setup_tx_creation):
    #recipient
    priv = b"\xaa"*32 + b"\x01"
    pub = bitcoin.privkey_to_pubkey(priv)
    addr = str(bitcoin.CCoinAddress.from_scriptPubKey(
        bitcoin.CScript([bitcoin.OP_0, bitcoin.Hash160(pub)])))
    wallet_service = make_wallets(1, [[1,0,0,0,0]], 1)[0]['wallet']
    #make another utxo on the same address
    addrinwallet = wallet_service.get_addr(0,0,0)
    jm_single().bc_interface.grab_coins(addrinwallet, 1)
    wallet_service.sync_wallet(fast=True)
    insfull = wallet_service.select_utxos(0, 110000000)
    outs = [{"address": addr, "value": 1000000}]
    ins = list(insfull.keys())
    tx = bitcoin.mktx(ins, outs)
    scripts = {}
    for i, j in enumerate(ins):
        scripts[i] = (insfull[j]["script"], insfull[j]["value"])
    success, msg = wallet_service.sign_tx(tx, scripts)
    assert success, msg

def test_verify_tx_input(setup_tx_creation):
    priv = b"\xaa"*32 + b"\x01"
    pub = bitcoin.privkey_to_pubkey(priv)
    script = bitcoin.pubkey_to_p2sh_p2wpkh_script(pub)
    addr = str(bitcoin.CCoinAddress.from_scriptPubKey(script))
    wallet_service = make_wallets(1, [[2,0,0,0,0]], 1)[0]['wallet']
    wallet_service.sync_wallet(fast=True)
    insfull = wallet_service.select_utxos(0, 110000000)
    outs = [{"address": addr, "value": 1000000}]
    ins = list(insfull.keys())
    tx = bitcoin.mktx(ins, outs)
    scripts = {0: (insfull[ins[0]]["script"], bitcoin.coins_to_satoshi(1))}
    success, msg = wallet_service.sign_tx(tx, scripts)
    assert success, msg
    # testing Joinmarket's ability to verify transaction inputs
    # of others: pretend we don't have a wallet owning the transaction,
    # and instead verify an input using the (sig, pub, scriptCode) data
    # that is sent by counterparties:
    cScrWit = tx.wit.vtxinwit[0].scriptWitness
    sig = cScrWit.stack[0]
    pub = cScrWit.stack[1]
    scriptSig = tx.vin[0].scriptSig
    tx2 = bitcoin.mktx(ins, outs)
    res = bitcoin.verify_tx_input(tx2, 0, scriptSig,
                            bitcoin.pubkey_to_p2wpkh_script(pub),
                            amount = bitcoin.coins_to_satoshi(1),
                            witness = bitcoin.CScriptWitness([sig, pub]))
    assert res

def test_absurd_fees(setup_tx_creation):
    """Test triggering of ValueError exception
    if the transaction fees calculated from the blockchain
    interface exceed the limit set in the config.
    """
    jm_single().bc_interface.absurd_fees = True
    #pay into it
    wallet_service = make_wallets(1, [[2, 0, 0, 0, 1]], 3)[0]['wallet']
    wallet_service.sync_wallet(fast=True)
    amount = 350000000
    ins_full = wallet_service.select_utxos(0, amount)
    with pytest.raises(ValueError) as e_info:
        txid = make_sign_and_push(ins_full, wallet_service, amount, estimate_fee=True)

def test_create_sighash_txs(setup_tx_creation):
    #non-standard hash codes:
    for sighash in [bitcoin.SIGHASH_ANYONECANPAY + bitcoin.SIGHASH_SINGLE,
                    bitcoin.SIGHASH_NONE, bitcoin.SIGHASH_SINGLE]:
        wallet_service = make_wallets(1, [[2, 0, 0, 0, 1]], 3)[0]['wallet']
        wallet_service.sync_wallet(fast=True)
        amount = 350000000
        ins_full = wallet_service.select_utxos(0, amount)
        txid = make_sign_and_push(ins_full, wallet_service, amount, hashcode=sighash)
        assert txid

    #trigger insufficient funds
    with pytest.raises(Exception) as e_info:
        fake_utxos = wallet_service.select_utxos(4, 1000000000)

def test_spend_p2wpkh(setup_tx_creation):
    #make 3 p2wpkh outputs from 3 privs
    privs = [struct.pack(b'B', x) * 32 + b'\x01' for x in range(1, 4)]
    pubs = [bitcoin.privkey_to_pubkey(priv) for priv in privs]
    scriptPubKeys = [bitcoin.pubkey_to_p2wpkh_script(pub) for pub in pubs]
    addresses = [str(bitcoin.CCoinAddress.from_scriptPubKey(
        spk)) for spk in scriptPubKeys]
    #pay into it
    wallet_service = make_wallets(1, [[3, 0, 0, 0, 0]], 3)[0]['wallet']
    wallet_service.sync_wallet(fast=True)
    amount = 35000000
    p2wpkh_ins = []
    for i, addr in enumerate(addresses):
        ins_full = wallet_service.select_utxos(0, amount)
        txid = make_sign_and_push(ins_full, wallet_service, amount, output_addr=addr)
        assert txid
        p2wpkh_ins.append((txid, 0))
        txhex = jm_single().bc_interface.get_transaction(txid)
        #wait for mining
        jm_single().bc_interface.tick_forward_chain(1)
    #random output address
    output_addr = wallet_service.get_internal_addr(1)
    amount2 = amount*3 - 50000
    outs = [{'value': amount2, 'address': output_addr}]
    tx = bitcoin.mktx(p2wpkh_ins, outs)

    for i, priv in enumerate(privs):
        # sign each of 3 inputs; note that bitcoin.sign
        # automatically validates each signature it creates.
        sig, msg = bitcoin.sign(tx, i, priv, amount=amount, native="p2wpkh")
        if not sig:
            assert False, msg
    txid = jm_single().bc_interface.pushtx(tx.serialize())
    assert txid

def test_spend_freeze_script(setup_tx_creation):
    ensure_bip65_activated()

    wallet_service = make_wallets(1, [[3, 0, 0, 0, 0]], 3)[0]['wallet']
    wallet_service.sync_wallet(fast=True)

    mediantime = jm_single().bc_interface.get_best_block_median_time()

    timeoffset_success_tests = [(2, False), (-60*60*24*30, True), (60*60*24*30, False)]

    for timeoffset, required_success in timeoffset_success_tests:
        #generate keypair
        priv = b"\xaa"*32 + b"\x01"
        pub = bitcoin.privkey_to_pubkey(priv)
        addr_locktime = mediantime + timeoffset
        redeem_script = bitcoin.mk_freeze_script(pub, addr_locktime)
        script_pub_key = bitcoin.redeem_script_to_p2wsh_script(redeem_script)
        # cannot convert to address within wallet service, as not known
        # to wallet; use engine directly:
        addr = wallet_service._ENGINE.script_to_address(script_pub_key)

        #fund frozen funds address
        amount = 100000000
        funding_ins_full = wallet_service.select_utxos(0, amount)
        funding_txid = make_sign_and_push(funding_ins_full, wallet_service, amount, output_addr=addr)
        assert funding_txid

        #spend frozen funds
        frozen_in = (funding_txid, 0)
        output_addr = wallet_service.get_internal_addr(1)
        miner_fee = 5000
        outs = [{'value': amount - miner_fee, 'address': output_addr}]
        tx = bitcoin.mktx([frozen_in], outs, locktime=addr_locktime+1)
        i = 0
        sig, success = bitcoin.sign(tx, i, priv, amount=amount,
                                    native=redeem_script)
        assert success
        push_success = jm_single().bc_interface.pushtx(tx.serialize())
        assert push_success == required_success

@pytest.fixture(scope="module")
def setup_tx_creation():
    load_test_config()
