#! /usr/bin/env python
from __future__ import absolute_import
'''Wallet functionality tests.'''

import sys
import os
import time
import binascii
import pexpect
import random
import subprocess
import datetime
import unittest
from ConfigParser import SafeConfigParser, NoSectionError
from decimal import Decimal
from commontest import (local_command, interact, make_wallets, make_sign_and_push,
                        DummyBlockchainInterface, TestWallet)
import json

import jmbitcoin as bitcoin
import pytest
from jmclient import (load_program_config, jm_single, sync_wallet, AbstractWallet,
                      get_p2pk_vbyte, get_log, Wallet, select, select_gradual,
                      select_greedy, select_greediest, estimate_tx_fee, encryptData,
                      get_network)
from jmbase.support import chunks
from taker_test_data import t_obtained_tx

log = get_log()

def do_tx(wallet, amount):
    ins_full = wallet.select_utxos(0, amount)
    cj_addr = wallet.get_internal_addr(1)
    change_addr = wallet.get_internal_addr(0)
    wallet.update_cache_index()
    txid = make_sign_and_push(ins_full, wallet, amount,
                              output_addr=cj_addr,
                              change_addr=change_addr,
                              estimate_fee=True)
    assert txid
    time.sleep(2) #blocks
    jm_single().bc_interface.sync_unspent(wallet)

def test_absurd_fee(setup_wallets):
    jm_single().config.set("POLICY", "absurd_fee_per_kb", "1000")
    with pytest.raises(ValueError) as e_info:
        estimate_tx_fee(10,2)
    load_program_config()

def test_abstract_wallet(setup_wallets):
    class DoNothingWallet(AbstractWallet):
        pass
    for algo in ["default", "gradual", "greedy", "greediest", "none"]:
        jm_single().config.set("POLICY", "merge_algorithm", algo)
        if algo == "none":
            with pytest.raises(Exception) as e_info:
                dnw = DoNothingWallet()
            #also test if the config is blank
            jm_single().config = SafeConfigParser()
            dnw = DoNothingWallet()
            assert dnw.utxo_selector == select
        else:
            dnw = DoNothingWallet()
        assert not dnw.get_key_from_addr("a")
        assert not dnw.get_utxos_by_mixdepth()
        assert not dnw.get_external_addr(1)
        assert not dnw.get_internal_addr(0)
        dnw.update_cache_index()
        dnw.remove_old_utxos("a")
        dnw.add_new_utxos("b", "c")
        load_program_config()

def create_default_testnet_wallet():
    walletdir = "wallets"
    testwalletname = "testwallet.json"
    pathtowallet = os.path.join(walletdir, testwalletname)
    if os.path.exists(pathtowallet):
        os.remove(pathtowallet)
    seed = "hello"
    return (walletdir, pathtowallet, testwalletname, Wallet(seed,
                    5,
                    6,
                    extend_mixdepth=False,
                    storepassword=False))

@pytest.mark.parametrize(
    "includecache, wrongnet, storepwd, extendmd, pwdnumtries",
    [
        (False, False, False, False, 1000),
        (True, False, False, True, 1),
        (False, True, False, False, 1),
        (False, False, True, False, 1)
    ])
def test_wallet_create(setup_wallets, includecache, wrongnet, storepwd, extendmd,
                       pwdnumtries):
    walletdir, pathtowallet, testwalletname, wallet = create_default_testnet_wallet()
    assert wallet.get_key(4,1,17) == "1289ca322f96673acef83f396a9735840e3ab69f0459cf9bfa8d9985a876534401"
    assert wallet.get_addr(2,0,5) == "myWPu9QJWHGE79XAmuKkwKgNk8vsr5evpk"
    jm_single().bc_interface.wallet_synced = True
    assert wallet.get_new_addr(1, 0) == "mi88ZgDGPmarzcsU6S437h9CY9BLmgH5M6"
    assert wallet.get_external_addr(3) == "mvChQuChnXVhqvH67wfMxrodPQ7xccdVJU"
    addr3internal = wallet.get_internal_addr(3)
    assert addr3internal == "mv26o79Bauf2miJMoxoSu1vXmfXnk85YPQ"
    assert wallet.get_key_from_addr(addr3internal) == "2a283c9a2168a25509e2fb944939637228c50c8b4fecd9024650316c4584246501"
    dummyaddr = "mvw1NazKDRbeNufFANqpYNAANafsMC2zVU"
    assert not wallet.get_key_from_addr(dummyaddr)
    #Make a new Wallet(), and prepare a testnet wallet file for this wallet
    
    password = "dummypassword"
    password_key = bitcoin.bin_dbl_sha256(password)
    seed = bitcoin.sha256("\xaa"*64)[:32]
    encrypted_seed = encryptData(password_key, seed.decode('hex'))
    timestamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    net = get_network() if not wrongnet else 'mainnnet'
    walletfilejson = {'creator': 'joinmarket project',
                                 'creation_time': timestamp,
                                 'encrypted_seed': encrypted_seed.encode('hex'),
                                 'network': net}
    if includecache:
        mmd = wallet.max_mix_depth if not extendmd else wallet.max_mix_depth + 5
        print("using mmd: " + str(mmd))
        walletfilejson.update({'index_cache': [[0,0]]*mmd})
    walletfile = json.dumps(walletfilejson)
    if not os.path.exists(walletdir):
        os.makedirs(walletdir)
    with open(pathtowallet, "wb") as f:
        f.write(walletfile)
    if wrongnet:
        with pytest.raises(ValueError) as e_info:
            TestWallet(testwalletname, 5, 6, extend_mixdepth=extendmd,
                   storepassword=storepwd, pwd=password)
        return
    from string import ascii_letters
    for i in range(pwdnumtries): #multiple tries to ensure pkcs7 error is triggered   
        with pytest.raises(ValueError) as e_info:
            wrongpwd = "".join([random.choice(ascii_letters) for _ in range(20)])
            TestWallet(testwalletname, 5, 6, extend_mixdepth=extendmd,
                   storepassword=storepwd, pwd=wrongpwd)

    with pytest.raises(ValueError) as e_info:
        TestWallet(testwalletname, 5, 6, extend_mixdepth=extendmd,
                   storepassword=storepwd, pwd=None)
    newwallet = TestWallet(testwalletname, 5, 6, extend_mixdepth=extendmd,
                           storepassword=storepwd, pwd=password)            
    assert newwallet.seed == seed
    #now we have a functional wallet + file, update the cache; first try
    #with failed paths
    oldpath = newwallet.path
    newwallet.path = None
    newwallet.update_cache_index()
    newwallet.path = "fake-path-definitely-doesnt-exist"
    newwallet.update_cache_index()
    #with real path
    newwallet.path = oldpath
    newwallet.index = [[1,1]]*5
    newwallet.update_cache_index()
    
    #ensure we cannot find a mainnet wallet from seed
    seed = "goodbye"
    jm_single().config.set("BLOCKCHAIN", "network", "mainnet")
    with pytest.raises(IOError) as e_info:
        Wallet(seed, 5, 6, False, False)
    load_program_config()

def test_imported_privkey(setup_wallets):
    jm_single().config.set("BLOCKCHAIN", "network", "mainnet")
    password = "dummypassword"
    password_key = bitcoin.bin_dbl_sha256(password)    
    privkey = "L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi"
    #to verify use from_wif_privkey and privkey_to_address
    iaddr = "1LDsjB43N2NAQ1Vbc2xyHca4iBBciN8iwC"
    privkey_bin = bitcoin.from_wif_privkey(privkey,
                                    vbyte=get_p2pk_vbyte()).decode('hex')[:-1]
    encrypted_privkey = encryptData(password_key, privkey_bin)
    encrypted_privkey_bad = encryptData(password_key, privkey_bin[:6])
    walletdir = "wallets"
    testwalletname = "testreal"
    pathtowallet = os.path.join(walletdir, testwalletname)
    seed = bitcoin.sha256("\xaa"*64)[:32]
    encrypted_seed = encryptData(password_key, seed.decode('hex'))
    timestamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    for ep in [encrypted_privkey, encrypted_privkey_bad]:
        walletfilejson = {'creator': 'joinmarket project',
                                     'creation_time': timestamp,
                                     'encrypted_seed': encrypted_seed.encode('hex'),
                                     'network': get_network(),
                                     'index_cache': [[0,0]]*5,
                                     'imported_keys': [
                                         {'encrypted_privkey': ep.encode('hex'),
                                          'mixdepth': 0}]}
        walletfile = json.dumps(walletfilejson)
        if not os.path.exists(walletdir):
            os.makedirs(walletdir)
        with open(pathtowallet, "wb") as f:
            f.write(walletfile)
        if ep == encrypted_privkey_bad:
            with pytest.raises(Exception) as e_info:
                TestWallet(testwalletname, 5, 6, False, False, pwd=password)
            continue
        newwallet = TestWallet(testwalletname, 5, 6, False, False, pwd=password)
        assert newwallet.seed == seed
        #test accessing the key from the addr
        assert newwallet.get_key_from_addr(iaddr) == bitcoin.from_wif_privkey(privkey)
    load_program_config()

def test_add_remove_utxos(setup_wallets):
    #Make a fake wallet and inject and then remove fake utxos
    walletdir, pathtowallet, testwalletname, wallet = create_default_testnet_wallet()
    assert wallet.get_addr(2,0,5) == "myWPu9QJWHGE79XAmuKkwKgNk8vsr5evpk"
    wallet.addr_cache["myWPu9QJWHGE79XAmuKkwKgNk8vsr5evpk"] = (2, 0, 5)
    #'76a914c55738deaa9861b6022e53a129968cbf354898b488ac'
    #these calls automatically update the addr_cache:
    assert wallet.get_new_addr(1, 0) == "mi88ZgDGPmarzcsU6S437h9CY9BLmgH5M6"
    #76a9141c9761f5fef73bef6aca378c930c59e7e795088488ac
    assert wallet.get_external_addr(3) == "mvChQuChnXVhqvH67wfMxrodPQ7xccdVJU"
    #76a914a115fa0394ce881437a96d443e236b39e07db1f988ac 
    #using the above pubkey scripts:
    faketxforwallet = {'outs':
        [{'script': '76a914c55738deaa9861b6022e53a129968cbf354898b488ac',
           'value': 110000000},
          {'script': '76a9141c9761f5fef73bef6aca378c930c59e7e795088488ac',
           'value': 89910900},
          {'script': '76a914a115fa0394ce881437a96d443e236b39e07db1f988ac',
           'value': 90021000},
          {'script': '76a9145ece2dac945c8ff5b2b6635360ca0478ade305d488ac', #not ours
           'value': 110000000}],
 'version': 1}
    wallet.add_new_utxos(faketxforwallet, "aa"*32)
    faketxforspending = {'ins':
        [{'outpoint': {'hash': 'aa'*32,
                       'index': 0}},
         {'outpoint': {'hash': 'aa'*32,
                        'index': 1}},
         {'outpoint': {'hash': 'aa'*32,
                        'index': 2}},         
         {'outpoint': {'hash': '3f3ea820d706e08ad8dc1d2c392c98facb1b067ae4c671043ae9461057bd2a3c',
                       'index': 1},
          'script': '',
          'sequence': 4294967295}]}
    wallet.select_utxos(1, 100000)
    with pytest.raises(Exception) as e_info:
        wallet.select_utxos(0, 100000)
    #ensure get_utxos_by_mixdepth can handle utxos outside of maxmixdepth
    wallet.max_mix_depth = 2
    mul = wallet.get_utxos_by_mixdepth()
    assert mul[3] != {}
    wallet.remove_old_utxos(faketxforspending)
    
@pytest.fixture(scope="module")
def setup_wallets():
    load_program_config()
