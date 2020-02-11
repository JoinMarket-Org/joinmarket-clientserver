'''Wallet functionality tests.'''

import os
import json
from binascii import hexlify, unhexlify

import pytest
import jmbitcoin as btc
from commontest import binarize_tx
from jmbase import get_log
from jmclient import load_test_config, jm_single, \
    SegwitLegacyWallet,BIP32Wallet, BIP49Wallet, LegacyWallet,\
    VolatileStorage, get_network, cryptoengine, WalletError,\
    SegwitWallet, WalletService
from test_blockchaininterface import sync_test_wallet

testdir = os.path.dirname(os.path.realpath(__file__))
log = get_log()


def signed_tx_is_segwit(tx):
    for inp in tx['ins']:
        if 'txinwitness' not in inp:
            return False
    return True


def assert_segwit(tx):
    assert signed_tx_is_segwit(tx)


def assert_not_segwit(tx):
    assert not signed_tx_is_segwit(tx)


def get_populated_wallet(amount=10**8, num=3):
    storage = VolatileStorage()
    SegwitLegacyWallet.initialize(storage, get_network())
    wallet = SegwitLegacyWallet(storage)

    # fund three wallet addresses at mixdepth 0
    for i in range(num):
        fund_wallet_addr(wallet, wallet.get_internal_addr(0), amount / 10**8)

    return wallet


def fund_wallet_addr(wallet, addr, value_btc=1):
    txin_id = jm_single().bc_interface.grab_coins(addr, value_btc)
    txinfo = jm_single().bc_interface.get_transaction(txin_id)
    txin = btc.deserialize(unhexlify(txinfo['hex']))
    utxo_in = wallet.add_new_utxos_(txin, unhexlify(txin_id), 1)
    assert len(utxo_in) == 1
    return list(utxo_in.keys())[0]


def get_bip39_vectors():
    fh = open(os.path.join(testdir, 'bip39vectors.json'))
    data = json.load(fh)['english']
    fh.close()
    return data


@pytest.mark.parametrize('entropy,mnemonic,key,xpriv', get_bip39_vectors())
def test_bip39_seeds(monkeypatch, setup_wallet, entropy, mnemonic, key, xpriv):
    jm_single().config.set('BLOCKCHAIN', 'network', 'mainnet')
    created_entropy = SegwitLegacyWallet.entropy_from_mnemonic(mnemonic)
    assert entropy == hexlify(created_entropy).decode('ascii')
    storage = VolatileStorage()
    SegwitLegacyWallet.initialize(
        storage, get_network(), entropy=created_entropy,
        entropy_extension=b'TREZOR', max_mixdepth=4)
    wallet = SegwitLegacyWallet(storage)
    assert (mnemonic, b'TREZOR') == wallet.get_mnemonic_words()
    assert key == hexlify(wallet._create_master_key()).decode('ascii')

    # need to monkeypatch this, else we'll default to the BIP-49 path
    monkeypatch.setattr(SegwitLegacyWallet, '_get_bip32_base_path',
                        BIP32Wallet._get_bip32_base_path)
    assert xpriv == wallet.get_bip32_priv_export()


def test_bip49_seed(monkeypatch, setup_wallet):
    jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
    mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
    master_xpriv = 'tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd'
    account0_xpriv = 'tprv8gRrNu65W2Msef2BdBSUgFdRTGzC8EwVXnV7UGS3faeXtuMVtGfEdidVeGbThs4ELEoayCAzZQ4uUji9DUiAs7erdVskqju7hrBcDvDsdbY'
    addr0_script_hash = '336caa13e08b96080a32b5d818d59b4ab3b36742'

    entropy = SegwitLegacyWallet.entropy_from_mnemonic(mnemonic)
    storage = VolatileStorage()
    SegwitLegacyWallet.initialize(
        storage, get_network(), entropy=entropy, max_mixdepth=0)
    wallet = SegwitLegacyWallet(storage)
    assert (mnemonic, None) == wallet.get_mnemonic_words()
    assert account0_xpriv == wallet.get_bip32_priv_export(0)
    assert addr0_script_hash == hexlify(wallet.get_external_script(0)[2:-1]).decode('ascii')

    # FIXME: is this desired behaviour? BIP49 wallet will not return xpriv for
    # the root key but only for key after base path
    monkeypatch.setattr(SegwitLegacyWallet, '_get_bip32_base_path',
                        BIP32Wallet._get_bip32_base_path)
    assert master_xpriv == wallet.get_bip32_priv_export()


def test_bip32_test_vector_1(monkeypatch, setup_wallet):
    jm_single().config.set('BLOCKCHAIN', 'network', 'mainnet')

    entropy = unhexlify('000102030405060708090a0b0c0d0e0f')
    storage = VolatileStorage()
    LegacyWallet.initialize(
        storage, get_network(), entropy=entropy, max_mixdepth=0)

    # test vector 1 is using hardened derivation for the account/mixdepth level
    monkeypatch.setattr(LegacyWallet, '_get_mixdepth_from_path',
                        BIP49Wallet._get_mixdepth_from_path)
    monkeypatch.setattr(LegacyWallet, '_get_bip32_mixdepth_path_level',
                        BIP49Wallet._get_bip32_mixdepth_path_level)
    monkeypatch.setattr(LegacyWallet, '_get_bip32_base_path',
                        BIP32Wallet._get_bip32_base_path)
    monkeypatch.setattr(LegacyWallet, '_create_master_key',
                        BIP32Wallet._create_master_key)

    wallet = LegacyWallet(storage)

    assert wallet.get_bip32_priv_export() == 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
    assert wallet.get_bip32_pub_export() == 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
    assert wallet.get_bip32_priv_export(0) == 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'
    assert wallet.get_bip32_pub_export(0) == 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw'
    assert wallet.get_bip32_priv_export(0, 1) == 'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs'
    assert wallet.get_bip32_pub_export(0, 1) == 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ'
    # there are more test vectors but those don't match joinmarket's wallet
    # structure, hence they make litte sense to test here


def test_bip32_test_vector_2(monkeypatch, setup_wallet):
    jm_single().config.set('BLOCKCHAIN', 'network', 'mainnet')

    entropy = unhexlify('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542')
    storage = VolatileStorage()
    LegacyWallet.initialize(
        storage, get_network(), entropy=entropy, max_mixdepth=0)

    monkeypatch.setattr(LegacyWallet, '_get_bip32_base_path',
                        BIP32Wallet._get_bip32_base_path)
    monkeypatch.setattr(LegacyWallet, '_create_master_key',
                        BIP32Wallet._create_master_key)

    wallet = LegacyWallet(storage)

    assert wallet.get_bip32_priv_export() == 'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U'
    assert wallet.get_bip32_pub_export() == 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
    assert wallet.get_bip32_priv_export(0) == 'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt'
    assert wallet.get_bip32_pub_export(0) == 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH'
    # there are more test vectors but those don't match joinmarket's wallet
    # structure, hence they make litte sense to test here


def test_bip32_test_vector_3(monkeypatch, setup_wallet):
    jm_single().config.set('BLOCKCHAIN', 'network', 'mainnet')

    entropy = unhexlify('4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be')
    storage = VolatileStorage()
    LegacyWallet.initialize(
        storage, get_network(), entropy=entropy, max_mixdepth=0)

    # test vector 3 is using hardened derivation for the account/mixdepth level
    monkeypatch.setattr(LegacyWallet, '_get_mixdepth_from_path',
                        BIP49Wallet._get_mixdepth_from_path)
    monkeypatch.setattr(LegacyWallet, '_get_bip32_mixdepth_path_level',
                        BIP49Wallet._get_bip32_mixdepth_path_level)
    monkeypatch.setattr(LegacyWallet, '_get_bip32_base_path',
                        BIP32Wallet._get_bip32_base_path)
    monkeypatch.setattr(LegacyWallet, '_create_master_key',
                        BIP32Wallet._create_master_key)

    wallet = LegacyWallet(storage)

    assert wallet.get_bip32_priv_export() == 'xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6'
    assert wallet.get_bip32_pub_export() == 'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13'
    assert wallet.get_bip32_priv_export(0) == 'xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L'
    assert wallet.get_bip32_pub_export(0) == 'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y'


@pytest.mark.parametrize('mixdepth,internal,index,address,wif', [
    [0, 0, 0, 'mpCX9EbdXpcrKMtjEe1fqFhvzctkfzMYTX', 'cVqtSSoVxFyPqTRGfeESi31uCYfgTF4tGWRtGeVs84fzybiX5TPk'],
    [0, 0, 5, 'mtj85a3pFppRhrxNcFig1k7ECshrZjJ9XC', 'cMsFXc4TRw9PTcCTv7x9mr88rDeGXBTLEV67mKaw2cxCkjkhL32G'],
    [0, 1, 3, 'n1EaQuqvTRm719hsSJ7yRsj49JfoG1C86q', 'cUgSTqnAtvYoQRXCYy4wCFfaks2Zrz1d55m6mVhFyVhQbkDi7JGJ'],
    [2, 1, 2, 'mfxkBk7uDhmF5PJGS9d1NonGiAxPwJqQP4', 'cPcZXSiXPuS5eiT4oDrDKi1mFumw5D1RcWzK2gkGdEHjEz99eyXn']
])
def test_bip32_addresses_p2pkh(monkeypatch, setup_wallet, mixdepth, internal, index, address, wif):
    """
    Test with a random but fixed entropy
    """
    jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')

    entropy = unhexlify('2e0339ba89b4a1272cdf78b27ee62669ee01992a59e836e2807051be128ca817')
    storage = VolatileStorage()
    LegacyWallet.initialize(
        storage, get_network(), entropy=entropy, max_mixdepth=3)

    monkeypatch.setattr(LegacyWallet, '_get_bip32_base_path',
                        BIP32Wallet._get_bip32_base_path)
    monkeypatch.setattr(LegacyWallet, '_create_master_key',
                        BIP32Wallet._create_master_key)

    wallet = LegacyWallet(storage)

    # wallet needs to know about all intermediate keys
    for i in range(index + 1):
        wallet.get_new_script(mixdepth, internal)

    assert wif == wallet.get_wif(mixdepth, internal, index)
    assert address == wallet.get_addr(mixdepth, internal, index)


@pytest.mark.parametrize('mixdepth,internal,index,address,wif', [
    [0, 0, 0, '2MzY5yyonUY7zpHspg7jB7WQs1uJxKafQe4', 'cRAGLvPmhpzJNgdMT4W2gVwEW3fusfaDqdQWM2vnWLgXKzCWKtcM'],
    [0, 0, 5, '2MsKvqPGStp3yXT8UivuAaGwfPzT7xYwSWk', 'cSo3h7nRuV4fwhVPXeTDJx6cBCkjAzS9VM8APXViyjoSaMq85ZKn'],
    [0, 1, 3, '2N7k6wiQqkuMaApwGhk3HKrifprUSDydqUv', 'cTwq3UsZa8STVmwZR94dDphgqgdLFeuaRFD1Ea44qjbjFfKEb1n5'],
    [2, 1, 2, '2MtE6gzHgmEXeWzKsmCJFEqkrpNuBDvoRnz', 'cPV8FZuCvrRpk4RhmhpjnSucHhaQZUan4Vbyo1NVQtuAxurW9grb']
])
def test_bip32_addresses_p2sh_p2wpkh(setup_wallet, mixdepth, internal, index, address, wif):
    """
    Test with a random but fixed entropy
    """
    jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')

    entropy = unhexlify('2e0339ba89b4a1272cdf78b27ee62669ee01992a59e836e2807051be128ca817')
    storage = VolatileStorage()
    SegwitLegacyWallet.initialize(
        storage, get_network(), entropy=entropy, max_mixdepth=3)
    wallet = SegwitLegacyWallet(storage)

    # wallet needs to know about all intermediate keys
    for i in range(index + 1):
        wallet.get_new_script(mixdepth, internal)

    assert wif == wallet.get_wif(mixdepth, internal, index)
    assert address == wallet.get_addr(mixdepth, internal, index)


def test_import_key(setup_wallet):
    jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
    storage = VolatileStorage()
    SegwitLegacyWallet.initialize(storage, get_network())
    wallet = SegwitLegacyWallet(storage)

    wallet.import_private_key(
        0, 'cRAGLvPmhpzJNgdMT4W2gVwEW3fusfaDqdQWM2vnWLgXKzCWKtcM',
        cryptoengine.TYPE_P2SH_P2WPKH)
    wallet.import_private_key(
        1, 'cVqtSSoVxFyPqTRGfeESi31uCYfgTF4tGWRtGeVs84fzybiX5TPk',
        cryptoengine.TYPE_P2PKH)

    with pytest.raises(WalletError):
        wallet.import_private_key(
            1, 'cRAGLvPmhpzJNgdMT4W2gVwEW3fusfaDqdQWM2vnWLgXKzCWKtcM',
            cryptoengine.TYPE_P2SH_P2WPKH)

    # test persist imported keys
    wallet.save()
    data = storage.file_data

    del wallet
    del storage

    storage = VolatileStorage(data=data)
    wallet = SegwitLegacyWallet(storage)

    imported_paths_md0 = list(wallet.yield_imported_paths(0))
    imported_paths_md1 = list(wallet.yield_imported_paths(1))
    assert len(imported_paths_md0) == 1
    assert len(imported_paths_md1) == 1

    # verify imported addresses
    assert wallet.get_address_from_path(imported_paths_md0[0]) == '2MzY5yyonUY7zpHspg7jB7WQs1uJxKafQe4'
    assert wallet.get_address_from_path(imported_paths_md1[0]) == 'mpCX9EbdXpcrKMtjEe1fqFhvzctkfzMYTX'

    # test remove key
    wallet.remove_imported_key(path=imported_paths_md0[0])
    assert not list(wallet.yield_imported_paths(0))

    assert wallet.get_details(imported_paths_md1[0]) == (1, 'imported', 0)


@pytest.mark.parametrize('wif,keytype,type_check', [
    ['cVqtSSoVxFyPqTRGfeESi31uCYfgTF4tGWRtGeVs84fzybiX5TPk',
     cryptoengine.TYPE_P2PKH, assert_not_segwit],
    ['cRAGLvPmhpzJNgdMT4W2gVwEW3fusfaDqdQWM2vnWLgXKzCWKtcM',
     cryptoengine.TYPE_P2SH_P2WPKH, assert_segwit]
])
def test_signing_imported(setup_wallet, wif, keytype, type_check):
    jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
    storage = VolatileStorage()
    SegwitLegacyWallet.initialize(storage, get_network())
    wallet = SegwitLegacyWallet(storage)

    MIXDEPTH = 0
    path = wallet.import_private_key(MIXDEPTH, wif, keytype)
    utxo = fund_wallet_addr(wallet, wallet.get_address_from_path(path))
    # The dummy output is constructed as an unspendable p2sh:
    tx = btc.deserialize(btc.mktx(['{}:{}'.format(
        hexlify(utxo[0]).decode('ascii'), utxo[1])],
        [btc.p2sh_scriptaddr(b"\x00",magicbyte=196) + ':' + str(10**8 - 9000)]))
    script = wallet.get_script_from_path(path)
    tx = wallet.sign_tx(tx, {0: (script, 10**8)})
    type_check(tx)
    txout = jm_single().bc_interface.pushtx(btc.serialize(tx))
    assert txout


@pytest.mark.parametrize('wallet_cls,type_check', [
    [LegacyWallet, assert_not_segwit],
    [SegwitLegacyWallet, assert_segwit],
    [SegwitWallet, assert_segwit],
])
def test_signing_simple(setup_wallet, wallet_cls, type_check):
    jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
    storage = VolatileStorage()
    wallet_cls.initialize(storage, get_network())
    wallet = wallet_cls(storage)
    utxo = fund_wallet_addr(wallet, wallet.get_internal_addr(0))
    # The dummy output is constructed as an unspendable p2sh:
    tx = btc.deserialize(btc.mktx(['{}:{}'.format(
        hexlify(utxo[0]).decode('ascii'), utxo[1])],
        [btc.p2sh_scriptaddr(b"\x00",magicbyte=196) + ':' + str(10**8 - 9000)]))
    script = wallet.get_script(0, 1, 0)
    tx = wallet.sign_tx(tx, {0: (script, 10**8)})
    type_check(tx)
    txout = jm_single().bc_interface.pushtx(btc.serialize(tx))
    assert txout

def test_get_bbm(setup_wallet):
    jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
    amount = 10**8
    num_tx = 3
    wallet = get_populated_wallet(amount, num_tx)
    # disable a utxo and check we can correctly report
    # balance with the disabled flag off:
    utxo_1 = list(wallet._utxos.get_utxos_by_mixdepth()[0].keys())[0]
    wallet.disable_utxo(*utxo_1)
    balances = wallet.get_balance_by_mixdepth(include_disabled=True)
    assert balances[0] == num_tx * amount
    balances = wallet.get_balance_by_mixdepth()
    assert balances[0] == (num_tx - 1) * amount
    wallet.toggle_disable_utxo(*utxo_1)
    balances = wallet.get_balance_by_mixdepth()
    assert balances[0] == num_tx * amount

def test_add_utxos(setup_wallet):
    jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
    amount = 10**8
    num_tx = 3

    wallet = get_populated_wallet(amount, num_tx)

    balances = wallet.get_balance_by_mixdepth()
    assert balances[0] == num_tx * amount
    for md in range(1, wallet.max_mixdepth + 1):
        assert balances[md] == 0

    utxos = wallet.get_utxos_by_mixdepth_()
    assert len(utxos[0]) == num_tx
    for md in range(1, wallet.max_mixdepth + 1):
        assert not utxos[md]

    with pytest.raises(Exception):
        # no funds in mixdepth
        wallet.select_utxos_(1, amount)

    with pytest.raises(Exception):
        # not enough funds
        wallet.select_utxos_(0, amount * (num_tx + 1))

    wallet.reset_utxos()
    assert wallet.get_balance_by_mixdepth()[0] == 0


def test_select_utxos(setup_wallet):
    jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
    amount = 10**8

    wallet = get_populated_wallet(amount)
    utxos = wallet.select_utxos_(0, amount // 2)

    assert len(utxos) == 1
    utxos = list(utxos.keys())

    more_utxos = wallet.select_utxos_(0, int(amount * 1.5), utxo_filter=utxos)
    assert len(more_utxos) == 2
    assert utxos[0] not in more_utxos


def test_add_new_utxos(setup_wallet):
    jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
    wallet = get_populated_wallet(num=1)

    scripts = [wallet.get_new_script(x, True) for x in range(3)]
    tx_scripts = list(scripts)
    tx_scripts.append(b'\x22'*17)

    tx = btc.deserialize(btc.mktx(
        ['0'*64 + ':2'], [{'script': hexlify(s).decode('ascii'), 'value': 10**8}
                          for s in tx_scripts]))
    binarize_tx(tx)
    txid = b'\x01' * 32
    added = wallet.add_new_utxos_(tx, txid, 1)
    assert len(added) == len(scripts)

    added_scripts = {x['script'] for x in added.values()}
    for s in scripts:
        assert s in added_scripts

    balances = wallet.get_balance_by_mixdepth()
    assert balances[0] == 2 * 10**8
    assert balances[1] == 10**8
    assert balances[2] == 10**8
    assert len(balances) == wallet.max_mixdepth + 1


def test_remove_old_utxos(setup_wallet):
    jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
    wallet = get_populated_wallet()

    # add some more utxos to mixdepth 1
    for i in range(3):
        txin = jm_single().bc_interface.grab_coins(
            wallet.get_internal_addr(1), 1)
        wallet.add_utxo(unhexlify(txin), 0, wallet.get_script(1, 1, i), 10**8, 1)

    inputs = wallet.select_utxos_(0, 10**8)
    inputs.update(wallet.select_utxos_(1, 2 * 10**8))
    assert len(inputs) == 3

    tx_inputs = list(inputs.keys())
    tx_inputs.append((b'\x12'*32, 6))

    tx = btc.deserialize(btc.mktx(
        ['{}:{}'.format(hexlify(txid).decode('ascii'), i) for txid, i in tx_inputs],
        ['0' * 36 + ':' + str(3 * 10**8 - 1000)]))
    binarize_tx(tx)

    removed = wallet.remove_old_utxos_(tx)
    assert len(removed) == len(inputs)

    for txid in removed:
        assert txid in inputs

    balances = wallet.get_balance_by_mixdepth()
    assert balances[0] == 2 * 10**8
    assert balances[1] == 10**8
    assert balances[2] == 0
    assert len(balances) == wallet.max_mixdepth + 1


def test_initialize_twice(setup_wallet):
    wallet = get_populated_wallet(num=0)
    storage = wallet._storage
    with pytest.raises(WalletError):
        SegwitLegacyWallet.initialize(storage, get_network())


def test_is_known(setup_wallet):
    wallet = get_populated_wallet(num=0)
    script = wallet.get_new_script(1, True)
    addr = wallet.get_external_addr(2)

    assert wallet.is_known_script(script)
    assert wallet.is_known_addr(addr)
    assert wallet.is_known_addr(wallet.script_to_addr(script))
    assert wallet.is_known_script(wallet.addr_to_script(addr))

    assert not wallet.is_known_script(b'\x12' * len(script))
    assert not wallet.is_known_addr('2MzY5yyonUY7zpHspg7jB7WQs1uJxKafQe4')


def test_wallet_save(setup_wallet):
    wallet = get_populated_wallet()

    script = wallet.get_external_script(1)

    wallet.save()
    storage = wallet._storage
    data = storage.file_data

    del wallet
    del storage

    storage = VolatileStorage(data=data)
    wallet = SegwitLegacyWallet(storage)

    assert wallet.get_next_unused_index(0, True) == 3
    assert wallet.get_next_unused_index(0, False) == 0
    assert wallet.get_next_unused_index(1, True) == 0
    assert wallet.get_next_unused_index(1, False) == 1
    assert wallet.is_known_script(script)


def test_set_next_index(setup_wallet):
    wallet = get_populated_wallet()

    assert wallet.get_next_unused_index(0, True) == 3

    with pytest.raises(Exception):
        # cannot advance index without force=True
        wallet.set_next_index(0, True, 5)

    wallet.set_next_index(0, True, 1)
    assert wallet.get_next_unused_index(0, True) == 1

    wallet.set_next_index(0, True, 20, force=True)
    assert wallet.get_next_unused_index(0, True) == 20

    script = wallet.get_new_script(0, True)
    path = wallet.script_to_path(script)
    index = wallet.get_details(path)[2]
    assert index == 20


def test_path_repr(setup_wallet):
    wallet = get_populated_wallet()
    path = wallet.get_path(2, False, 0)
    path_repr = wallet.get_path_repr(path)
    path_new = wallet.path_repr_to_path(path_repr)

    assert path_new == path


def test_path_repr_imported(setup_wallet):
    wallet = get_populated_wallet(num=0)
    path = wallet.import_private_key(
        0, 'cRAGLvPmhpzJNgdMT4W2gVwEW3fusfaDqdQWM2vnWLgXKzCWKtcM',
        cryptoengine.TYPE_P2SH_P2WPKH)
    path_repr = wallet.get_path_repr(path)
    path_new = wallet.path_repr_to_path(path_repr)

    assert path_new == path


def test_wrong_wallet_cls(setup_wallet):
    storage = VolatileStorage()
    SegwitLegacyWallet.initialize(storage, get_network())
    wallet = SegwitLegacyWallet(storage)

    wallet.save()
    data = storage.file_data

    del wallet
    del storage

    storage = VolatileStorage(data=data)

    with pytest.raises(Exception):
        LegacyWallet(storage)


def test_wallet_id(setup_wallet):
    storage1 = VolatileStorage()
    SegwitLegacyWallet.initialize(storage1, get_network())
    wallet1 = SegwitLegacyWallet(storage1)

    storage2 = VolatileStorage()
    LegacyWallet.initialize(storage2, get_network(), entropy=wallet1._entropy)
    wallet2 = LegacyWallet(storage2)

    assert wallet1.get_wallet_id() != wallet2.get_wallet_id()

    storage2 = VolatileStorage()
    SegwitLegacyWallet.initialize(storage2, get_network(),
                                  entropy=wallet1._entropy)
    wallet2 = SegwitLegacyWallet(storage2)

    assert wallet1.get_wallet_id() == wallet2.get_wallet_id()


def test_addr_script_conversion(setup_wallet):
    wallet = get_populated_wallet(num=1)

    path = wallet.get_path(0, True, 0)
    script = wallet.get_script_from_path(path)
    addr = wallet.script_to_addr(script)

    assert script == wallet.addr_to_script(addr)
    addr_path = wallet.addr_to_path(addr)
    assert path == addr_path


def test_imported_key_removed(setup_wallet):
    wif = 'cRAGLvPmhpzJNgdMT4W2gVwEW3fusfaDqdQWM2vnWLgXKzCWKtcM'
    key_type = cryptoengine.TYPE_P2SH_P2WPKH

    storage = VolatileStorage()
    SegwitLegacyWallet.initialize(storage, get_network())
    wallet = SegwitLegacyWallet(storage)

    path = wallet.import_private_key(1, wif, key_type)
    script = wallet.get_script_from_path(path)
    assert wallet.is_known_script(script)

    wallet.remove_imported_key(path=path)
    assert not wallet.is_known_script(script)

    with pytest.raises(WalletError):
        wallet.get_script_from_path(path)


def test_wallet_mixdepth_simple(setup_wallet):
    wallet = get_populated_wallet(num=0)
    mixdepth = wallet.mixdepth
    assert wallet.max_mixdepth == mixdepth

    wallet.close()
    storage_data = wallet._storage.file_data

    new_wallet = type(wallet)(VolatileStorage(data=storage_data))
    assert new_wallet.mixdepth == mixdepth
    assert new_wallet.max_mixdepth == mixdepth


def test_wallet_mixdepth_increase(setup_wallet):
    wallet = get_populated_wallet(num=0)
    mixdepth = wallet.mixdepth

    wallet.close()
    storage_data = wallet._storage.file_data

    new_mixdepth = mixdepth + 2
    new_wallet = type(wallet)(
        VolatileStorage(data=storage_data), mixdepth=new_mixdepth)
    assert new_wallet.mixdepth == new_mixdepth
    assert new_wallet.max_mixdepth == new_mixdepth


def test_wallet_mixdepth_decrease(setup_wallet):
    wallet = get_populated_wallet(num=1)

    # setup
    max_mixdepth = wallet.max_mixdepth
    assert max_mixdepth >= 1, "bad default value for mixdepth for this test"
    utxo = fund_wallet_addr(wallet, wallet.get_internal_addr(max_mixdepth), 1)
    assert wallet.get_balance_by_mixdepth()[max_mixdepth] == 10**8
    wallet.close()
    storage_data = wallet._storage.file_data

    # actual test
    new_mixdepth = max_mixdepth - 1
    new_wallet = type(wallet)(
        VolatileStorage(data=storage_data), mixdepth=new_mixdepth)
    assert new_wallet.max_mixdepth == max_mixdepth
    assert new_wallet.mixdepth == new_mixdepth
    sync_test_wallet(True, WalletService(new_wallet))

    assert max_mixdepth not in new_wallet.get_balance_by_mixdepth()
    assert max_mixdepth not in new_wallet.get_utxos_by_mixdepth()

    # wallet.select_utxos will still return utxos from higher mixdepths
    # because we explicitly ask for a specific mixdepth
    assert utxo in new_wallet.select_utxos_(max_mixdepth, 10**7)


@pytest.fixture(scope='module')
def setup_wallet():
    load_test_config()
    #see note in cryptoengine.py:
    cryptoengine.BTC_P2WPKH.VBYTE = 100
    jm_single().bc_interface.tick_forward_chain_interval = 2
