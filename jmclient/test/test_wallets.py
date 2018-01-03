#! /usr/bin/env python
from __future__ import print_function, absolute_import
'''Wallet functionality tests.'''

import sys
import os
import time
import binascii
import random
import subprocess
import datetime
import unittest
from mnemonic import Mnemonic
try:
    from ConfigParser import SafeConfigParser, NoOptionError
except:
    from configparser import SafeConfigParser, NoOptionError
from decimal import Decimal
from commontest import (interact, make_wallets,
                        make_sign_and_push, DummyBlockchainInterface)
import json

import jmbitcoin as bitcoin
import pytest
from jmclient import (load_program_config, jm_single, sync_wallet,
                      AbstractWallet, get_p2pk_vbyte, get_log, Wallet, select,
                      select_gradual, select_greedy, select_greediest,
                      estimate_tx_fee, encryptData, get_network, WalletError,
                      BitcoinCoreWallet, BitcoinCoreInterface, SegwitWallet,
                      wallet_generate_recover_bip39, decryptData, encryptData)
from jmbase.support import chunks
from taker_test_data import t_obtained_tx, t_raw_signed_tx
testdir = os.path.dirname(os.path.realpath(__file__))
log = get_log()


def do_tx(wallet, amount):
    ins_full = wallet.select_utxos(0, amount)
    cj_addr = wallet.get_internal_addr(1)
    change_addr = wallet.get_internal_addr(0)
    wallet.update_cache_index()
    txid = make_sign_and_push(ins_full,
                              wallet,
                              amount,
                              output_addr=cj_addr,
                              change_addr=change_addr,
                              estimate_fee=True)
    assert txid
    time.sleep(2)  #blocks
    jm_single().bc_interface.sync_unspent(wallet)
    return txid


def test_query_utxo_set(setup_wallets):
    load_program_config()
    jm_single().bc_interface.tick_forward_chain_interval = 1
    wallet = create_wallet_for_sync("wallet4utxo.json", "4utxo",
                                    [2, 3, 0, 0, 0],
                                    ["wallet4utxo.json", "4utxo", [2, 3]])
    sync_wallet(wallet, fast=True)
    txid = do_tx(wallet, 90000000)
    txid2 = do_tx(wallet, 20000000)
    print("Got txs: ", txid, txid2)
    res1 = jm_single().bc_interface.query_utxo_set(txid + ":0", includeunconf=True)
    res2 = jm_single().bc_interface.query_utxo_set(
        [txid + ":0", txid2 + ":1"],
        includeconf=True, includeunconf=True)
    assert len(res1) == 1
    assert len(res2) == 2
    assert all([x in res1[0] for x in ['script', 'address', 'value']])
    assert not 'confirms' in res1[0]
    assert 'confirms' in res2[0]
    assert 'confirms' in res2[1]
    res3 = jm_single().bc_interface.query_utxo_set("ee" * 32 + ":25")
    assert res3 == [None]


def create_wallet_for_sync(wallet_file, password, wallet_structure, a):
    #Prepare a testnet wallet file for this wallet
    password_key = bitcoin.bin_dbl_sha256(password)
    #We need a distinct seed for each run so as not to step over each other;
    #make it through a deterministic hash
    seedh = bitcoin.sha256("".join([str(x) for x in a]))[:32]
    encrypted_seed = encryptData(password_key, bitcoin.safe_from_hex(seedh))
    timestamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    walletfilejson = {'creator': 'joinmarket project',
                      'creation_time': timestamp,
                      'encrypted_seed': bitcoin.safe_hexlify(encrypted_seed),
                      'network': get_network()}
    walletfile = json.dumps(walletfilejson)
    if not os.path.exists('wallets'):
        os.makedirs('wallets')
    with open(os.path.join('wallets', wallet_file), "w") as f:
        f.write(walletfile)
    #The call to Wallet() in make_wallets should now find the file
    #and read from it:
    return make_wallets(1,
                        [wallet_structure],
                        fixed_seeds=[wallet_file],
                        test_wallet=True,
                        passwords=[password])[0]['wallet']


@pytest.mark.parametrize(
    "num_txs, fake_count, wallet_structure, amount, wallet_file, password",
    [
        (3, 13, [11, 3, 4, 5, 6], 150000000, 'test_import_wallet.json',
         'import-pwd'),
        #Uncomment all these for thorough tests. Passing currently.
        #Lots of used addresses
        #(7, 1, [51, 3, 4, 5, 6], 150000000, 'test_import_wallet.json',
        # 'import-pwd'),
        #(3, 1, [3, 1, 4, 5, 6], 50000000, 'test_import_wallet.json',
        # 'import-pwd'),
        #No spams/fakes
        #(2, 0, [5, 20, 1, 1, 1], 50000000, 'test_import_wallet.json',
        # 'import-pwd'),
        #Lots of transactions and fakes
        #(25, 30, [30, 20, 1, 1, 1], 50000000, 'test_import_wallet.json',
        # 'import-pwd'),
    ])
def test_wallet_sync_with_fast(setup_wallets, num_txs, fake_count,
                               wallet_structure, amount, wallet_file, password):
    jm_single().bc_interface.tick_forward_chain_interval = 1
    wallet = create_wallet_for_sync(wallet_file, password, wallet_structure,
                                    [num_txs, fake_count, wallet_structure,
                                     amount, wallet_file, password])
    sync_count = 0
    jm_single().bc_interface.wallet_synced = False
    while not jm_single().bc_interface.wallet_synced:
        sync_wallet(wallet)
        sync_count += 1
        #avoid infinite loop
        assert sync_count < 10
        log.debug("Tried " + str(sync_count) + " times")

    assert jm_single().bc_interface.wallet_synced
    assert not jm_single().bc_interface.fast_sync_called
    #do some transactions with the wallet, then close, then resync
    for i in range(num_txs):
        do_tx(wallet, amount)
        log.debug("After doing a tx, index is now: " + str(wallet.index))
        #simulate a spammer requesting a bunch of transactions. This
        #mimics what happens in CoinJoinOrder.__init__()
        for j in range(fake_count):
            #Note that as in a real script run,
            #the initial call to sync_wallet will
            #have set wallet_synced to True, so these will
            #trigger actual imports.
            cj_addr = wallet.get_internal_addr(0)
            change_addr = wallet.get_internal_addr(0)
            wallet.update_cache_index()
            log.debug("After doing a spam, index is now: " + str(wallet.index))

    assert wallet.index[0][1] == num_txs + fake_count * 2 * num_txs

    #Attempt re-sync, simulating a script restart.

    jm_single().bc_interface.wallet_synced = False
    sync_count = 0
    #Probably should be fixed in main code:
    #wallet.index_cache is only assigned in Wallet.__init__(),
    #meaning a second sync in the same script, after some transactions,
    #will not know about the latest index_cache value (see is_index_ahead_of_cache),
    #whereas a real re-sync will involve reading the cache from disk.
    #Hence, simulation of the fact that the cache index will
    #be read from the file on restart:
    wallet.index_cache = wallet.index

    while not jm_single().bc_interface.wallet_synced:
        #Wallet.__init__() resets index to zero.
        wallet.index = []
        for i in range(5):
            wallet.index.append([0, 0])
        #Wallet.__init__() also updates the cache index
        #from file, but we can reuse from the above pre-loop setting,
        #since nothing else in sync will overwrite the cache.

        #for regtest add_watchonly_addresses does not exit(), so can
        #just repeat as many times as possible. This might
        #be usable for non-test code (i.e. no need to restart the
        #script over and over again)?
        sync_count += 1
        log.debug("TRYING SYNC NUMBER: " + str(sync_count))
        sync_wallet(wallet, fast=True)
        assert jm_single().bc_interface.fast_sync_called
        #avoid infinite loop on failure.
        assert sync_count < 10
    #Wallet should recognize index_cache on fast sync, so should not need to
    #run sync process more than once.
    assert sync_count == 1
    #validate the wallet index values after sync
    for i, ws in enumerate(wallet_structure):
        assert wallet.index[i][0] == ws  #spends into external only
    #Same number as above; note it includes the spammer's extras.
    assert wallet.index[0][1] == num_txs + fake_count * 2 * num_txs
    assert wallet.index[1][1] == num_txs  #one change per transaction
    for i in range(2, 5):
        assert wallet.index[i][1] == 0  #unused

    #Now try to do more transactions as sanity check.
    do_tx(wallet, 50000000)


@pytest.mark.parametrize(
    "wallet_structure, wallet_file, password, ic",
    [
        #As usual, more test cases are preferable but time
        #of build test is too long, so only one activated.
        #([11,3,4,5,6], 'test_import_wallet.json', 'import-pwd',
        # [(12,3),(100,99),(7, 40), (200, 201), (10,0)]
        # ),
        ([1, 3, 0, 2, 9], 'test_import_wallet.json', 'import-pwd',
         [(1, 7), (100, 99), (0, 0), (200, 201), (21, 41)]),
    ])
def test_wallet_sync_from_scratch(setup_wallets, wallet_structure, wallet_file,
                                  password, ic):
    """Simulate a scenario in which we use a new bitcoind, thusly:
    generate a new wallet and simply pretend that it has an existing
    index_cache. This will force import of all addresses up to
    the index_cache values.
    """
    wallet = create_wallet_for_sync(wallet_file, password, wallet_structure,
                                    [wallet_structure, wallet_file, password,
                                     ic])
    sync_count = 0
    jm_single().bc_interface.wallet_synced = False
    wallet.index_cache = ic
    while not jm_single().bc_interface.wallet_synced:
        wallet.index = []
        for i in range(5):
            wallet.index.append([0, 0])
        #will call with fast=False but index_cache exists; should use slow-sync
        sync_wallet(wallet)
        sync_count += 1
        #avoid infinite loop
        assert sync_count < 10
        log.debug("Tried " + str(sync_count) + " times")
    #after #586 we expect to ALWAYS succeed within 2 rounds
    assert sync_count <= 2
    #for each external branch, the new index may be higher than
    #the original index_cache if there was a higher used address
    expected_wallet_index = []
    for i, val in enumerate(wallet_structure):
        if val > wallet.index_cache[i][0]:
            expected_wallet_index.append([val, wallet.index_cache[i][1]])
        else:
            expected_wallet_index.append([wallet.index_cache[i][0],
                                          wallet.index_cache[i][1]])
    assert wallet.index == expected_wallet_index
    log.debug("This is wallet unspent: ")
    log.debug(json.dumps(wallet.unspent, indent=4))


"""Purely blockchaininterface related error condition tests"""


def test_index_ahead_cache(setup_wallets):
    """Artificial test; look into finding a sync mode that triggers this
    """

    class NonWallet(object):
        pass

    wallet = NonWallet()
    wallet.index_cache = [[0, 0], [0, 2]]
    from jmclient.blockchaininterface import is_index_ahead_of_cache
    assert is_index_ahead_of_cache(wallet, 3, 1)


def test_core_wallet_no_sync(setup_wallets):
    """Ensure BitcoinCoreWallet sync attempt does nothing
    """
    wallet = BitcoinCoreWallet("")
    #this will not trigger sync due to absence of non-zero index_cache, usually.
    wallet.index_cache = [[1, 1]]
    jm_single().bc_interface.wallet_synced = False
    jm_single().bc_interface.sync_wallet(wallet, fast=True)
    assert not jm_single().bc_interface.wallet_synced
    jm_single().bc_interface.sync_wallet(wallet)
    assert not jm_single().bc_interface.wallet_synced


def test_wrong_network_bci(setup_wallets):
    rpc = jm_single().bc_interface.jsonRpc
    with pytest.raises(Exception) as e_info:
        x = BitcoinCoreInterface(rpc, 'mainnet')


def test_pushtx_errors(setup_wallets):
    """Ensure pushtx fails return False
    """
    badtxhex = "aaaa"
    assert not jm_single().bc_interface.pushtx(bitcoin.safe_from_hex(badtxhex))
    #Break the authenticated jsonrpc and try again
    jm_single().bc_interface.jsonRpc.port = 18333
    assert not jm_single().bc_interface.pushtx(bitcoin.safe_from_hex(t_raw_signed_tx))
    #rebuild a valid jsonrpc inside the bci
    load_program_config()


"""Tests mainly for wallet.py"""


def test_absurd_fee(setup_wallets):
    jm_single().config.set("POLICY", "absurd_fee_per_kb", "1000")
    with pytest.raises(ValueError) as e_info:
        estimate_tx_fee(10, 2)
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

def check_bip39_case(vectors, language="english"):
    mnemo = Mnemonic(language)
    for v in vectors:
        code = mnemo.to_mnemonic(binascii.unhexlify(v[0]))
        seed = binascii.hexlify(Mnemonic.to_seed(code, passphrase=v[4]))
        if sys.version >= '3':
            seed = seed.decode('utf8')
        print('checking this phrase: ' + v[1])
        assert mnemo.check(v[1])
        assert v[1] == code
        assert v[2] == seed

"""
Sanity check of basic bip39 functionality for 12 words seed, copied from
https://github.com/trezor/python-mnemonic/blob/master/test_mnemonic.py
"""
def test_bip39_vectors(setup_wallets):
    with open(os.path.join(testdir, 'bip39vectors.json'), 'r') as f:
        vectors_full = json.load(f)
    vectors = vectors_full['english']
    #default from-file cases use passphrase 'TREZOR'; TODO add other
    #extensions, but note there is coverage of that in the below test
    for v in vectors:
        v.append("TREZOR")
    #12 word seeds only
    vectors = filter(lambda x: len(x[1].split())==12, vectors)
    check_bip39_case(vectors)

@pytest.mark.parametrize(
    "pwd, me, valid", [
        ("asingleword", "1234aaaaaaaaaaaaaaaaa", True),
        ("a whole set of words", "a whole set of words", True),
        ("wordwithtrailingspaces   ", "A few words with trailing  ", True),
        ("monkey", "verylongpasswordindeedxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", True),
        ("blablah", "invalidcontainsnonascii\xee", False)
    ])
def test_create_bip39_with_me(setup_wallets, pwd, me, valid):
    def dummyDisplayWords(a, b):
        pass
    def getMnemonic():
        return ("legal winner thank year wave sausage worth useful legal winner thank yellow",
                me)
    def getPassword():
        return pwd
    def getWalletFileName():
        return "bip39-test-wallet-name-from-callback.json"
    def promptMnemonicExtension():
        return me
    if os.path.exists(os.path.join("wallets", getWalletFileName())):
        os.remove(os.path.join("wallets", getWalletFileName()))
    success = wallet_generate_recover_bip39("generate",
                                            "wallets",
                                            "wallet.json",
                                            callbacks=(dummyDisplayWords,
                                                       getMnemonic,
                                                       getPassword,
                                                       getWalletFileName,
                                                       promptMnemonicExtension))
    if not valid:
        #wgrb39 returns false for failed wallet creation case
        assert not success
        return
    assert success
    #open the wallet file, and decrypt the encrypted mnemonic extension and check
    #it's the one we intended.
    with open(os.path.join("wallets", getWalletFileName()), 'r') as f:
        walletdata = json.load(f)
    password_key = bitcoin.bin_dbl_sha256(getPassword())
    cleartext = decryptData(password_key,
                            bitcoin.safe_from_hex(walletdata['encrypted_mnemonic_extension']))
    assert len(cleartext) >= 79
    #throws if not len == 3
    padding, me2, checksum = cleartext.split(b"\xff")
    strippedme = me.strip().encode("ascii")
    assert strippedme == me2
    assert checksum == bitcoin.bin_dbl_sha256(strippedme)[:8]
    #also test recovery from this combination of mnemonic + extension
    if os.path.exists(os.path.join("wallets", getWalletFileName())):
        os.remove(os.path.join("wallets", getWalletFileName()))
    success = wallet_generate_recover_bip39("recover", "wallets", "wallet.json",
                                            callbacks=(dummyDisplayWords,
                                                       getMnemonic,
                                                       getPassword,
                                                       getWalletFileName,
                                                       None))
    assert success
    with open(os.path.join("wallets", getWalletFileName()), 'r') as f:
        walletdata = json.load(f)
        password_key = bitcoin.bin_dbl_sha256(getPassword())
        cleartext = bitcoin.safe_hexlify(decryptData(password_key,
                    bitcoin.safe_from_hex(walletdata['encrypted_entropy'])))
        assert cleartext == "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"

def create_default_testnet_wallet():
    walletdir = "wallets"
    testwalletname = "testwallet.json"
    pathtowallet = os.path.join(walletdir, testwalletname)
    if os.path.exists(pathtowallet):
        os.remove(pathtowallet)
    seed = "deadbeef"
    return (walletdir, pathtowallet, testwalletname,
            SegwitWallet(seed,
                   None,
                   5,
                   6,
                   extend_mixdepth=False,
                   storepassword=False))

@pytest.mark.parametrize(
    "includecache, wrongnet, storepwd, extendmd, pwdnumtries", [
        (False, False, False, False, 100),
        (True, False, False, True, 1),
        (False, True, False, False, 1),
        (False, False, True, False, 1)
    ])
def test_wallet_create(setup_wallets, includecache, wrongnet, storepwd,
                       extendmd, pwdnumtries):
    walletdir, pathtowallet, testwalletname, wallet = create_default_testnet_wallet(
    )
    assert wallet.get_key(
        4, 1,
        17) == "96095d7542e4e832c476b9df7e49ca9e5be61ad3bb8c8a3bdd8e141e2f4caf9101"
    assert wallet.get_addr(2, 0, 5) == "2NBUxbEQrGPKrYCV6d4o7Y4AtJ34Uy6gZZg"
    jm_single().bc_interface.wallet_synced = True
    assert wallet.get_new_addr(1, 0) == "2Mz817RE6zqywgkG2h9cATUoiXwnFSxufk2"
    assert wallet.get_external_addr(3) == "2N3gn65WXEzbLnjk5FLDZPc1pL6ebvZAmoA"
    addr3internal = wallet.get_internal_addr(3)
    assert addr3internal == "2N5NMTYogAyrGhDtWBnVQUp1kgwwFzcf7UM"
    assert wallet.get_key_from_addr(
        addr3internal) == "089a7173314d29f99e02a37e36da517ce41537a317c83284db1f33dda0af0cc201"
    dummyaddr = "mvw1NazKDRbeNufFANqpYNAANafsMC2zVU"
    assert not wallet.get_key_from_addr(dummyaddr)
    #Make a new Wallet(), and prepare a testnet wallet file for this wallet

    password = "dummypassword"
    password_key = bitcoin.bin_dbl_sha256(password)
    seed = bitcoin.sha256("\xaa" * 64)[:32]
    encrypted_seed = encryptData(password_key, bitcoin.safe_from_hex(seed))
    timestamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    net = get_network() if not wrongnet else 'mainnnet'
    walletfilejson = {'creator': 'joinmarket project',
                      'creation_time': timestamp,
                      'encrypted_seed': bitcoin.safe_hexlify(encrypted_seed),
                      'network': net}
    if includecache:
        mmd = wallet.max_mix_depth if not extendmd else wallet.max_mix_depth + 5
        print("using mmd: " + str(mmd))
        walletfilejson.update({'index_cache': [[0, 0]] * mmd})
    walletfile = json.dumps(walletfilejson)
    if not os.path.exists(walletdir):
        os.makedirs(walletdir)
    with open(pathtowallet, "w") as f:
        f.write(walletfile)
    if wrongnet:
        with pytest.raises(ValueError) as e_info:
            SegwitWallet(testwalletname,
                   password,
                   5,
                   6,
                   extend_mixdepth=extendmd,
                   storepassword=storepwd)
        return
    from string import ascii_letters
    for i in range(
            pwdnumtries):  #multiple tries to ensure pkcs7 error is triggered
        with pytest.raises(WalletError) as e_info:
            wrongpwd = "".join([random.choice(ascii_letters) for _ in range(20)
                               ])
            SegwitWallet(testwalletname,
                   wrongpwd,
                   5,
                   6,
                   extend_mixdepth=extendmd,
                   storepassword=storepwd)

    with pytest.raises(WalletError) as e_info:
        SegwitWallet(testwalletname,
               None,
               5,
               6,
               extend_mixdepth=extendmd,
               storepassword=storepwd)
    newwallet = SegwitWallet(testwalletname,
                       password,
                       5,
                       6,
                       extend_mixdepth=extendmd,
                       storepassword=storepwd)
    assert newwallet.seed == wallet.wallet_data_to_seed(seed)
    #now we have a functional wallet + file, update the cache; first try
    #with failed paths
    oldpath = newwallet.path
    newwallet.path = None
    newwallet.update_cache_index()
    newwallet.path = "fake-path-definitely-doesnt-exist"
    newwallet.update_cache_index()
    #with real path
    newwallet.path = oldpath
    newwallet.index = [[1, 1]] * 5
    newwallet.update_cache_index()

    #ensure we cannot find a mainnet wallet from seed
    seed = "goodbye"
    jm_single().config.set("BLOCKCHAIN", "network", "mainnet")
    with pytest.raises(IOError) as e_info:
        Wallet(seed, 5, 6, False, False)
    load_program_config()


def test_imported_privkey(setup_wallets):
    for n in ["mainnet", "testnet"]:
        privkey = "7d998b45c219a1e38e99e7cbd312ef67f77a455a9b50c730c27f02c6f730dfb401"
        jm_single().config.set("BLOCKCHAIN", "network", n)
        password = "dummypassword"
        password_key = bitcoin.bin_dbl_sha256(password)
        wifprivkey = bitcoin.wif_compressed_privkey(privkey, get_p2pk_vbyte())
        #mainnet is "L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi"
        #to verify use from_wif_privkey and privkey_to_address
        if n == "mainnet":
            iaddr = "1LDsjB43N2NAQ1Vbc2xyHca4iBBciN8iwC"
        else:
            iaddr = "mzjq2E92B3oRB7yDKbwM7XnPaAnKfRERw2"
        privkey_bin = bitcoin.safe_from_hex(bitcoin.from_wif_privkey(
            wifprivkey,
            vbyte=get_p2pk_vbyte()))[:-1]
        encrypted_privkey = encryptData(password_key, privkey_bin)
        encrypted_privkey_bad = encryptData(password_key, privkey_bin[:6])
        walletdir = "wallets"
        testwalletname = "test" + n
        pathtowallet = os.path.join(walletdir, testwalletname)
        seed = bitcoin.sha256("\xaa" * 64)[:32]
        encrypted_seed = encryptData(password_key, bitcoin.safe_from_hex(seed))
        timestamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        for ep in [encrypted_privkey, encrypted_privkey_bad]:
            walletfilejson = {'creator': 'joinmarket project',
                              'creation_time': timestamp,
                              'encrypted_seed': bitcoin.safe_hexlify(encrypted_seed),
                              'network': n,
                              'index_cache': [[0, 0]] * 5,
                              'imported_keys': [
                                  {'encrypted_privkey': bitcoin.safe_hexlify(ep),
                                   'mixdepth': 0}
                              ]}
            walletfile = json.dumps(walletfilejson)
            if not os.path.exists(walletdir):
                os.makedirs(walletdir)
            with open(pathtowallet, "w") as f:
                f.write(walletfile)
            if ep == encrypted_privkey_bad:
                with pytest.raises(Exception) as e_info:
                    Wallet(testwalletname, password, 5, 6, False, False)
                continue
            newwallet = Wallet(testwalletname, password, 5, 6, False, False)
            assert newwallet.seed == seed
            #test accessing the key from the addr
            assert newwallet.get_key_from_addr(
                iaddr) == bitcoin.from_wif_privkey(wifprivkey,
                                                   vbyte=get_p2pk_vbyte())
            if n == "testnet":
                jm_single().bc_interface.sync_wallet(newwallet)
    load_program_config()

def test_add_remove_utxos(setup_wallets):
    #Make a fake wallet and inject and then remove fake utxos
    walletdir, pathtowallet, testwalletname, wallet = create_default_testnet_wallet()
    assert wallet.get_addr(2, 0, 5) == "2NBUxbEQrGPKrYCV6d4o7Y4AtJ34Uy6gZZg"
    wallet.addr_cache["2NBUxbEQrGPKrYCV6d4o7Y4AtJ34Uy6gZZg"] = (2, 0, 5)
    #'a914c80b3c03b96c0da5ef983942d9e541cb788aed8787'
    #these calls automatically update the addr_cache:
    assert wallet.get_new_addr(1, 0) == "2Mz817RE6zqywgkG2h9cATUoiXwnFSxufk2"
    #a9144b6b3836a1708fd38d4728e41b86e69d5bb15d5187
    assert wallet.get_external_addr(3) == "2N3gn65WXEzbLnjk5FLDZPc1pL6ebvZAmoA"
    #a914728673d95ceafa892ed82f9cc23c8bf1700b6c6187
    #using the above pubkey scripts:
    faketxforwallet = {'outs': [
        {'script': 'a914c80b3c03b96c0da5ef983942d9e541cb788aed8787',
         'value': 110000000},
        {'script': 'a9144b6b3836a1708fd38d4728e41b86e69d5bb15d5187',
         'value': 89910900},
        {'script': 'a914728673d95ceafa892ed82f9cc23c8bf1700b6c6187',
         'value': 90021000},
        {'script':
         '76a9145ece2dac945c8ff5b2b6635360ca0478ade305d488ac',  #not ours
         'value': 110000000}
    ],
                       'version': 1}
    wallet.add_new_utxos(faketxforwallet, "aa" * 32)
    faketxforspending = {'ins': [
        {'outpoint': {'hash': 'aa' * 32,
                      'index': 0}}, {'outpoint': {'hash': 'aa' * 32,
                                                  'index': 1}}, {'outpoint':
                                                                 {'hash':
                                                                  'aa' * 32,
                                                                  'index': 2}},
        {'outpoint':
         {'hash':
          '3f3ea820d706e08ad8dc1d2c392c98facb1b067ae4c671043ae9461057bd2a3c',
          'index': 1},
         'script': '',
         'sequence': 4294967295}
    ]}
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
    jm_single().bc_interface.tick_forward_chain_interval = 2
