#! /usr/bin/env python
'''Test of unusual transaction types creation and push to
network to check validity.'''

import time
import binascii
import struct
from commontest import make_wallets, make_sign_and_push

import jmbitcoin as bitcoin
import pytest
from jmbase import get_log
from jmclient import load_test_config, jm_single,\
    get_p2pk_vbyte

log = get_log()
#just a random selection of pubkeys for receiving multisigs;
#if we ever need the privkeys, they are in a json file somewhere
vpubs = ["03e9a06e539d6bf5cf1ca5c41b59121fa3df07a338322405a312c67b6349a707e9",
         "0280125e42c1984923106e281615dfada44d38c4125c005963b322427110d709d6",
         "02726fa5b19e9406aaa46ee22fd9e81a09dd5eb7c87505b93a11efcf4b945e778c",
         "03600a739be32a14938680b3b3d61b51f217a60df118160d0decab22c9e1329862",
         "028a2f126e3999ff66d01dcb101ab526d3aa1bf5cbdc4bde14950a4cead95f6fcb",
         "02bea84d70e74f7603746b62d79bf035e16d982b56e6a1ee07dfd3b9130e8a2ad9"]


@pytest.mark.parametrize(
    "nw, wallet_structures, mean_amt, sdev_amt, amount, pubs, k", [
        (1, [[2, 1, 4, 0, 0]], 4, 1.4, 600000000, vpubs[1:4], 2),
        (1, [[3, 3, 0, 0, 3]], 4, 1.4, 100000000, vpubs[:4], 3),
    ])
def test_create_p2sh_output_tx(setup_tx_creation, nw, wallet_structures,
                               mean_amt, sdev_amt, amount, pubs, k):
    wallets = make_wallets(nw, wallet_structures, mean_amt, sdev_amt)
    for w in wallets.values():
        w['wallet'].sync_wallet(fast=True)
    for k, w in enumerate(wallets.values()):
        wallet_service = w['wallet']
        ins_full = wallet_service.select_utxos(0, amount)
        script = bitcoin.mk_multisig_script(pubs, k)
        output_addr = bitcoin.p2sh_scriptaddr(bitcoin.safe_from_hex(script),
                                              magicbyte=196)
        txid = make_sign_and_push(ins_full,
                                  wallet_service,
                                  amount,
                                  output_addr=output_addr)
        assert txid

def test_script_to_address(setup_tx_creation):
    sample_script = "a914307f099a3bfedec9a09682238db491bade1b467f87"
    assert bitcoin.script_to_address(
        sample_script, vbyte=5) == "367SYUMqo1Fi4tQsycnmCtB6Ces1Z7EZLH"
    assert bitcoin.script_to_address(
        sample_script, vbyte=196) == "2MwfecDHsQTm4Gg3RekQdpqAMR15BJrjfRF"

def test_mktx(setup_tx_creation):
    """Testing exceptional conditions; not guaranteed
    to create valid tx objects"""
    #outpoint structure must be {"outpoint":{"hash":hash, "index": num}}
    ins = [{'outpoint': {"hash":x*64, "index":0},
            "script": "", "sequence": 4294967295} for x in ["a", "b", "c"]]
    pub = vpubs[0]
    addr = bitcoin.pubkey_to_address(pub, magicbyte=get_p2pk_vbyte())
    script = bitcoin.address_to_script(addr)
    outs = [script + ":1000", addr+":2000",{"script":script, "value":3000}]
    tx = bitcoin.mktx(ins, outs)
    print(tx)
    #rewrite with invalid output
    outs.append({"foo": "bar"})
    with pytest.raises(Exception) as e_info:
        tx = bitcoin.mktx(ins, outs)

def test_bintxhash(setup_tx_creation):
    tx = "abcdef1234"
    x = bitcoin.bin_txhash(tx)
    assert binascii.hexlify(x).decode('ascii') == "121480fc2cccd5103434a9c88b037e08ef6c4f9f95dfb85b56f7043a344613fe"

def test_all_same_priv(setup_tx_creation):
    #recipient
    priv = "aa"*32 + "01"
    addr = bitcoin.privkey_to_address(priv, magicbyte=get_p2pk_vbyte())
    wallet_service = make_wallets(1, [[1,0,0,0,0]], 1)[0]['wallet']
    #make another utxo on the same address
    addrinwallet = wallet_service.get_addr(0,0,0)
    jm_single().bc_interface.grab_coins(addrinwallet, 1)
    wallet_service.sync_wallet(fast=True)
    insfull = wallet_service.select_utxos(0, 110000000)
    outs = [{"address": addr, "value": 1000000}]
    ins = list(insfull.keys())
    tx = bitcoin.mktx(ins, outs)
    tx = bitcoin.signall(tx, wallet_service.get_key_from_addr(addrinwallet))

@pytest.mark.parametrize(
    "signall",
    [
        (True,),
        (False,),
    ])
def test_verify_tx_input(setup_tx_creation, signall):
    priv = "aa"*32 + "01"
    addr = bitcoin.privkey_to_address(priv, magicbyte=get_p2pk_vbyte())
    wallet_service = make_wallets(1, [[2,0,0,0,0]], 1)[0]['wallet']
    wallet_service.sync_wallet(fast=True)
    insfull = wallet_service.select_utxos(0, 110000000)
    print(insfull)
    outs = [{"address": addr, "value": 1000000}]
    ins = list(insfull.keys())
    tx = bitcoin.mktx(ins, outs)
    desertx = bitcoin.deserialize(tx)
    print(desertx)
    if signall:
        privdict = {}
        for index, ins in enumerate(desertx['ins']):
            utxo = ins['outpoint']['hash'] + ':' + str(ins['outpoint']['index'])
            ad = insfull[utxo]['address']
            priv = wallet_service.get_key_from_addr(ad)
            privdict[utxo] = priv
        tx = bitcoin.signall(tx, privdict)
    else:
        for index, ins in enumerate(desertx['ins']):
            utxo = ins['outpoint']['hash'] + ':' + str(ins['outpoint']['index'])
            ad = insfull[utxo]['address']
            priv = wallet_service.get_key_from_addr(ad)
            tx = bitcoin.sign(tx, index, priv)
    desertx2 = bitcoin.deserialize(tx)
    print(desertx2)
    sig, pub = bitcoin.deserialize_script(desertx2['ins'][0]['script'])
    print(sig, pub)
    pubscript = bitcoin.address_to_script(bitcoin.pubkey_to_address(
        pub, magicbyte=get_p2pk_vbyte()))
    sig = binascii.unhexlify(sig)
    pub = binascii.unhexlify(pub)
    sig_good = bitcoin.verify_tx_input(tx, 0, pubscript,
                                       sig, pub)
    assert sig_good
   
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
        print("using hashcode: " + str(sighash))
        txid = make_sign_and_push(ins_full, wallet_service, amount, hashcode=sighash)
        assert txid

    #trigger insufficient funds
    with pytest.raises(Exception) as e_info:
        fake_utxos = wallet_service.select_utxos(4, 1000000000)


def test_spend_p2sh_utxos(setup_tx_creation):
    #make a multisig address from 3 privs
    privs = [struct.pack('B', x) * 32 + b'\x01' for x in range(1, 4)]
    pubs = [bitcoin.privkey_to_pubkey(binascii.hexlify(priv).decode('ascii')) for priv in privs]
    script = bitcoin.mk_multisig_script(pubs, 2)
    msig_addr = bitcoin.p2sh_scriptaddr(script, magicbyte=196)
    #pay into it
    wallet_service = make_wallets(1, [[2, 0, 0, 0, 1]], 3)[0]['wallet']
    wallet_service.sync_wallet(fast=True)
    amount = 350000000
    ins_full = wallet_service.select_utxos(0, amount)
    txid = make_sign_and_push(ins_full, wallet_service, amount, output_addr=msig_addr)
    assert txid
    #wait for mining
    time.sleep(1)
    #spend out; the input can be constructed from the txid of previous
    msig_in = txid + ":0"
    ins = [msig_in]
    #random output address and change addr
    output_addr = wallet_service.get_internal_addr(1)
    amount2 = amount - 50000
    outs = [{'value': amount2, 'address': output_addr}]
    tx = bitcoin.mktx(ins, outs)
    sigs = []
    for priv in privs[:2]:
        sigs.append(bitcoin.multisign(tx, 0, script, binascii.hexlify(priv).decode('ascii')))
    tx = bitcoin.apply_multisignatures(tx, 0, script, sigs)
    txid = jm_single().bc_interface.pushtx(tx)
    assert txid

def test_spend_p2wpkh(setup_tx_creation):
    #make 3 p2wpkh outputs from 3 privs
    privs = [struct.pack('B', x) * 32 + b'\x01' for x in range(1, 4)]
    pubs = [bitcoin.privkey_to_pubkey(
        binascii.hexlify(priv).decode('ascii')) for priv in privs]
    scriptPubKeys = [bitcoin.pubkey_to_p2wpkh_script(pub) for pub in pubs]
    addresses = [bitcoin.pubkey_to_p2wpkh_address(pub) for pub in pubs]
    #pay into it
    wallet_service = make_wallets(1, [[3, 0, 0, 0, 0]], 3)[0]['wallet']
    wallet_service.sync_wallet(fast=True)
    amount = 35000000
    p2wpkh_ins = []
    for addr in addresses:
        ins_full = wallet_service.select_utxos(0, amount)
        txid = make_sign_and_push(ins_full, wallet_service, amount, output_addr=addr)
        assert txid
        p2wpkh_ins.append(txid + ":0")
        #wait for mining
        time.sleep(1)
    #random output address
    output_addr = wallet_service.get_internal_addr(1)
    amount2 = amount*3 - 50000
    outs = [{'value': amount2, 'address': output_addr}]
    tx = bitcoin.mktx(p2wpkh_ins, outs)
    sigs = []
    for i, priv in enumerate(privs):
        # sign each of 3 inputs
        tx = bitcoin.p2wpkh_sign(tx, i, binascii.hexlify(priv),
                                 amount, native=True)
        # check that verify_tx_input correctly validates;
        # to do this, we need to extract the signature and get the scriptCode
        # of this pubkey
        scriptCode = bitcoin.pubkey_to_p2pkh_script(pubs[i])
        witness = bitcoin.deserialize(tx)['ins'][i]['txinwitness']
        assert len(witness) == 2
        assert witness[1] == pubs[i]
        sig = witness[0]
        assert bitcoin.verify_tx_input(tx, i, scriptPubKeys[i], sig,
                        pubs[i], scriptCode=scriptCode, amount=amount)
    txid = jm_single().bc_interface.pushtx(tx)
    assert txid


def test_spend_p2wsh(setup_tx_creation):
    #make 2 x 2 of 2multisig outputs; will need 4 privs
    privs = [struct.pack('B', x) * 32 + b'\x01' for x in range(1, 5)]
    privs = [binascii.hexlify(priv).decode('ascii') for priv in privs]
    pubs = [bitcoin.privkey_to_pubkey(priv) for priv in privs]
    redeemScripts = [bitcoin.mk_multisig_script(pubs[i:i+2], 2) for i in [0, 2]]
    scriptPubKeys = [bitcoin.pubkeys_to_p2wsh_script(pubs[i:i+2]) for i in [0, 2]]
    addresses = [bitcoin.pubkeys_to_p2wsh_address(pubs[i:i+2]) for i in [0, 2]]
    #pay into it
    wallet_service = make_wallets(1, [[3, 0, 0, 0, 0]], 3)[0]['wallet']
    wallet_service.sync_wallet(fast=True)
    amount = 35000000
    p2wsh_ins = []
    for addr in addresses:
        ins_full = wallet_service.select_utxos(0, amount)
        txid = make_sign_and_push(ins_full, wallet_service, amount, output_addr=addr)
        assert txid
        p2wsh_ins.append(txid + ":0")
        #wait for mining
        time.sleep(1)
    #random output address and change addr
    output_addr = wallet_service.get_internal_addr(1)
    amount2 = amount*2 - 50000
    outs = [{'value': amount2, 'address': output_addr}]
    tx = bitcoin.mktx(p2wsh_ins, outs)
    sigs = []
    for i in range(2):
        sigs = []
        for priv in privs[i*2:i*2+2]:
            # sign input j with each of 2 keys
            sig = bitcoin.multisign(tx, i, redeemScripts[i], priv, amount=amount)
            sigs.append(sig)
            # check that verify_tx_input correctly validates;
            assert bitcoin.verify_tx_input(tx, i, scriptPubKeys[i], sig,
                                           bitcoin.privkey_to_pubkey(priv),
                                           scriptCode=redeemScripts[i], amount=amount)
        tx = bitcoin.apply_p2wsh_multisignatures(tx, i, redeemScripts[i], sigs)
    txid = jm_single().bc_interface.pushtx(tx)
    assert txid


@pytest.fixture(scope="module")
def setup_tx_creation():
    load_test_config()
