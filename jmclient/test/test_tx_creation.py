#! /usr/bin/env python
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401
'''Test of unusual transaction types creation and push to
network to check validity.'''

import time
import binascii
import struct
from commontest import make_wallets, make_sign_and_push

import jmbitcoin as bitcoin
import pytest
from jmbase import get_log
from jmclient import load_program_config, jm_single, sync_wallet,\
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
        sync_wallet(w['wallet'], fast=True)
    for k, w in enumerate(wallets.values()):
        wallet = w['wallet']
        ins_full = wallet.select_utxos(0, amount)
        script = bitcoin.mk_multisig_script(pubs, k)
        #try the alternative argument passing
        pubs.append(k)
        script2 = bitcoin.mk_multisig_script(*pubs)
        assert script2 == script
        output_addr = bitcoin.scriptaddr(script, magicbyte=196)
        txid = make_sign_and_push(ins_full,
                                  wallet,
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
    wallet = make_wallets(1, [[1,0,0,0,0]], 1)[0]['wallet']
    #make another utxo on the same address
    addrinwallet = wallet.get_addr(0,0,0)
    jm_single().bc_interface.grab_coins(addrinwallet, 1)
    sync_wallet(wallet, fast=True)
    insfull = wallet.select_utxos(0, 110000000)
    outs = [{"address": addr, "value": 1000000}]
    ins = list(insfull.keys())
    tx = bitcoin.mktx(ins, outs)
    tx = bitcoin.signall(tx, wallet.get_key_from_addr(addrinwallet))

@pytest.mark.parametrize(
    "signall, mktxlist",
    [
        (True, False),
        (False, True),
    ])
def test_verify_tx_input(setup_tx_creation, signall, mktxlist):
    priv = "aa"*32 + "01"
    addr = bitcoin.privkey_to_address(priv, magicbyte=get_p2pk_vbyte())
    wallet = make_wallets(1, [[2,0,0,0,0]], 1)[0]['wallet']
    sync_wallet(wallet, fast=True)
    insfull = wallet.select_utxos(0, 110000000)
    print(insfull)    
    if not mktxlist:
        outs = [{"address": addr, "value": 1000000}]
        ins = list(insfull.keys())
        tx = bitcoin.mktx(ins, outs)
    else:
        out1 = addr+":1000000"
        ins0, ins1 = list(insfull.keys())
        print("INS0 is: " + str(ins0))
        print("INS1 is: " + str(ins1))
        tx = bitcoin.mktx(ins0, ins1, out1)
    desertx = bitcoin.deserialize(tx)
    print(desertx)
    if signall:
        privdict = {}
        for index, ins in enumerate(desertx['ins']):
            utxo = ins['outpoint']['hash'] + ':' + str(ins['outpoint']['index'])
            ad = insfull[utxo]['address']
            priv = wallet.get_key_from_addr(ad)
            privdict[utxo] = priv
        tx = bitcoin.signall(tx, privdict)
    else:
        for index, ins in enumerate(desertx['ins']):
            utxo = ins['outpoint']['hash'] + ':' + str(ins['outpoint']['index'])
            ad = insfull[utxo]['address']
            priv = wallet.get_key_from_addr(ad)
            if index % 2:
                tx = binascii.unhexlify(tx)
            tx = bitcoin.sign(tx, index, priv)
            if index % 2:
                tx = binascii.hexlify(tx).decode('ascii')
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
    wallet = make_wallets(1, [[2, 0, 0, 0, 1]], 3)[0]['wallet']
    sync_wallet(wallet, fast=True)
    amount = 350000000
    ins_full = wallet.select_utxos(0, amount)
    with pytest.raises(ValueError) as e_info:
        txid = make_sign_and_push(ins_full, wallet, amount, estimate_fee=True)

def test_create_sighash_txs(setup_tx_creation):
    #non-standard hash codes:
    for sighash in [bitcoin.SIGHASH_ANYONECANPAY + bitcoin.SIGHASH_SINGLE,
                    bitcoin.SIGHASH_NONE, bitcoin.SIGHASH_SINGLE]:
        wallet = make_wallets(1, [[2, 0, 0, 0, 1]], 3)[0]['wallet']
        sync_wallet(wallet, fast=True)
        amount = 350000000
        ins_full = wallet.select_utxos(0, amount)
        print("using hashcode: " + str(sighash))
        txid = make_sign_and_push(ins_full, wallet, amount, hashcode=sighash)
        assert txid

    #trigger insufficient funds
    with pytest.raises(Exception) as e_info:
        fake_utxos = wallet.select_utxos(4, 1000000000)


def test_spend_p2sh_utxos(setup_tx_creation):
    #make a multisig address from 3 privs
    privs = [struct.pack(b'B', x) * 32 + b'\x01' for x in range(1, 4)]
    pubs = [bitcoin.privkey_to_pubkey(binascii.hexlify(priv).decode('ascii')) for priv in privs]
    script = bitcoin.mk_multisig_script(pubs, 2)
    msig_addr = bitcoin.scriptaddr(script, magicbyte=196)
    #pay into it
    wallet = make_wallets(1, [[2, 0, 0, 0, 1]], 3)[0]['wallet']
    sync_wallet(wallet, fast=True)
    amount = 350000000
    ins_full = wallet.select_utxos(0, amount)
    txid = make_sign_and_push(ins_full, wallet, amount, output_addr=msig_addr)
    assert txid
    #wait for mining
    time.sleep(1)
    #spend out; the input can be constructed from the txid of previous
    msig_in = txid + ":0"
    ins = [msig_in]
    #random output address and change addr
    output_addr = wallet.get_new_addr(1, 1)
    amount2 = amount - 50000
    outs = [{'value': amount2, 'address': output_addr}]
    tx = bitcoin.mktx(ins, outs)
    sigs = []
    for priv in privs[:2]:
        sigs.append(bitcoin.multisign(tx, 0, script, binascii.hexlify(priv).decode('ascii')))
    tx = bitcoin.apply_multisignatures(tx, 0, script, sigs)
    txid = jm_single().bc_interface.pushtx(tx)
    assert txid


@pytest.fixture(scope="module")
def setup_tx_creation():
    load_program_config()
