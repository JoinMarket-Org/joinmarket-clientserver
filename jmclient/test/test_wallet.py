'''Wallet functionality tests.'''

import os
import json
from binascii import hexlify, unhexlify

import pytest
import jmbitcoin as btc
from commontest import ensure_bip65_activated
from jmbase import get_log, hextobin
from jmclient import load_test_config, jm_single, BaseWallet, \
    SegwitLegacyWallet,BIP32Wallet, BIP49Wallet, LegacyWallet,\
    VolatileStorage, get_network, cryptoengine, WalletError,\
    SegwitWallet, WalletService, SegwitLegacyWalletFidelityBonds,\
    create_wallet, open_test_wallet_maybe, \
    FidelityBondMixin, FidelityBondWatchonlyWallet, wallet_gettimelockaddress
from test_blockchaininterface import sync_test_wallet

testdir = os.path.dirname(os.path.realpath(__file__))

test_create_wallet_filename = "testwallet_for_create_wallet_test"

log = get_log()


def signed_tx_is_segwit(tx):
    return tx.has_witness()


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
    # special case, grab_coins returns hex from rpc:
    txin_id = hextobin(jm_single().bc_interface.grab_coins(addr, value_btc))
    txinfo = jm_single().bc_interface.get_transaction(txin_id)
    txin = btc.CMutableTransaction.deserialize(btc.x(txinfo["hex"]))
    utxo_in = wallet.add_new_utxos(txin, 1)
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
        entropy_extension='TREZOR', max_mixdepth=4)
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
    [0, BaseWallet.ADDRESS_TYPE_EXTERNAL, 0, 'mpCX9EbdXpcrKMtjEe1fqFhvzctkfzMYTX', 'cVqtSSoVxFyPqTRGfeESi31uCYfgTF4tGWRtGeVs84fzybiX5TPk'],
    [0, BaseWallet.ADDRESS_TYPE_EXTERNAL, 5, 'mtj85a3pFppRhrxNcFig1k7ECshrZjJ9XC', 'cMsFXc4TRw9PTcCTv7x9mr88rDeGXBTLEV67mKaw2cxCkjkhL32G'],
    [0, BaseWallet.ADDRESS_TYPE_INTERNAL, 3, 'n1EaQuqvTRm719hsSJ7yRsj49JfoG1C86q', 'cUgSTqnAtvYoQRXCYy4wCFfaks2Zrz1d55m6mVhFyVhQbkDi7JGJ'],
    [2, BaseWallet.ADDRESS_TYPE_INTERNAL, 2, 'mfxkBk7uDhmF5PJGS9d1NonGiAxPwJqQP4', 'cPcZXSiXPuS5eiT4oDrDKi1mFumw5D1RcWzK2gkGdEHjEz99eyXn']
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

@pytest.mark.parametrize('index,timenumber,address,wif', [
    [0, 0, 'bcrt1qndcqwedwa4lu77ryqpvp738d6p034a2fv8mufw3pw5smfcn39sgqpesn76', 'cST4g5R3mKp44K4J8PRVyys4XJu6EFavZyssq67PJKCnbhjdEdBY'],
    [0, 50, 'bcrt1q73zhrfcu0ttkk4er9esrmvnpl6wpzhny5aly97jj9nw52agf8ncqjv8rda', 'cST4g5R3mKp44K4J8PRVyys4XJu6EFavZyssq67PJKCnbhjdEdBY'],
    [5, 0, 'bcrt1qz5208jdm6399ja309ra28d0a34qlt0859u77uxc94v5mgk7auhtssau4pw', 'cRnUaBYTmyZURPe72YCrtvgxpBMvLKPZaCoXvKuWRPMryeJeAZx2'],
    [9, 1, 'bcrt1qa7pd6qnadpmlm29vtvqnykalc34tr33eclaz7eeqal59n4gwr28qwnka2r', 'cQCxEPCWMwXVB16zCikDBTXMUccx6ioHQipPhYEp1euihkJUafyD']
])
def test_bip32_timelocked_addresses(setup_wallet, index, timenumber, address, wif):
    jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')

    entropy = unhexlify('2e0339ba89b4a1272cdf78b27ee62669ee01992a59e836e2807051be128ca817')
    storage = VolatileStorage()
    SegwitLegacyWalletFidelityBonds.initialize(
        storage, get_network(), entropy=entropy, max_mixdepth=1)
    wallet = SegwitLegacyWalletFidelityBonds(storage)
    mixdepth = FidelityBondMixin.FIDELITY_BOND_MIXDEPTH
    address_type = FidelityBondMixin.BIP32_TIMELOCK_ID

    #wallet needs to know about the script beforehand
    wallet.get_script_and_update_map(mixdepth, address_type, index, timenumber)

    assert address == wallet.get_addr(mixdepth, address_type, index, timenumber)
    assert wif == wallet.get_wif_path(wallet.get_path(mixdepth, address_type, index, timenumber))

@pytest.mark.parametrize('timenumber,locktime_string', [
    [0, "2020-01"],
    [20, "2021-09"],
    [100, "2028-05"],
    [150, "2032-07"],
    [350, "2049-03"]
])
def test_gettimelockaddress_method(setup_wallet, timenumber, locktime_string):
    storage = VolatileStorage()
    SegwitLegacyWalletFidelityBonds.initialize(storage, get_network())
    wallet = SegwitLegacyWalletFidelityBonds(storage)

    m = FidelityBondMixin.FIDELITY_BOND_MIXDEPTH
    address_type = FidelityBondMixin.BIP32_TIMELOCK_ID
    index = wallet.get_next_unused_index(m, address_type)
    script = wallet.get_script_and_update_map(m, address_type, index,
        timenumber)
    addr = wallet.script_to_addr(script)

    addr_from_method = wallet_gettimelockaddress(wallet, locktime_string)

    assert addr == addr_from_method

@pytest.mark.parametrize('index,wif', [
    [0, 'cMg9eH3fW2JDSyggvXucjmECRwiheCMDo2Qik8y1keeYaxynzrYa'],
    [9, 'cURA1Qgxhd7QnhhwxCnCHD4pZddVrJdu2BkTdzNaTp9owRSkUvPy'],
    [50, 'cRTaHZ1eezb8s6xsT2V7EAevYToQMi7cxQD9vgFZzaJZDfhMhf3c']
])
def test_bip32_burn_keys(setup_wallet, index, wif):
    jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')

    entropy = unhexlify('2e0339ba89b4a1272cdf78b27ee62669ee01992a59e836e2807051be128ca817')
    storage = VolatileStorage()
    SegwitLegacyWalletFidelityBonds.initialize(
        storage, get_network(), entropy=entropy, max_mixdepth=1)
    wallet = SegwitLegacyWalletFidelityBonds(storage)
    mixdepth = FidelityBondMixin.FIDELITY_BOND_MIXDEPTH
    address_type = FidelityBondMixin.BIP32_BURN_ID

    #advance index_cache enough
    wallet.set_next_index(mixdepth, address_type, index, force=True)

    assert wif == wallet.get_wif_path(wallet.get_path(mixdepth, address_type, index))

def test_import_key(setup_wallet):
    jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
    storage = VolatileStorage()
    SegwitLegacyWallet.initialize(storage, get_network())
    wallet = SegwitLegacyWallet(storage)

    wallet.import_private_key(
        0, 'cRAGLvPmhpzJNgdMT4W2gVwEW3fusfaDqdQWM2vnWLgXKzCWKtcM')
    wallet.import_private_key(
        1, 'cVqtSSoVxFyPqTRGfeESi31uCYfgTF4tGWRtGeVs84fzybiX5TPk')

    with pytest.raises(WalletError):
        wallet.import_private_key(
            1, 'cRAGLvPmhpzJNgdMT4W2gVwEW3fusfaDqdQWM2vnWLgXKzCWKtcM')

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
    assert wallet.get_address_from_path(imported_paths_md1[0]) == '2MwbXnJrPP4rnwpgRhvNPP44J6tMokDexZB'

    # test remove key
    wallet.remove_imported_key(path=imported_paths_md0[0])
    assert not list(wallet.yield_imported_paths(0))

    assert wallet.get_details(imported_paths_md1[0]) == (1, 'imported', 0)


@pytest.mark.parametrize('wif, type_check', [
    ['cRAGLvPmhpzJNgdMT4W2gVwEW3fusfaDqdQWM2vnWLgXKzCWKtcM', assert_segwit]
])
def test_signing_imported(setup_wallet, wif, type_check):
    jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
    storage = VolatileStorage()
    SegwitLegacyWallet.initialize(storage, get_network())
    wallet = SegwitLegacyWallet(storage)

    MIXDEPTH = 0
    path = wallet.import_private_key(MIXDEPTH, wif)
    utxo = fund_wallet_addr(wallet, wallet.get_address_from_path(path))
    # The dummy output is constructed as an unspendable p2sh:
    tx = btc.mktx([utxo],
                [{"address": str(btc.CCoinAddress.from_scriptPubKey(
                    btc.CScript(b"\x00").to_p2sh_scriptPubKey())),
                  "value": 10**8 - 9000}])    
    script = wallet.get_script_from_path(path)
    success, msg = wallet.sign_tx(tx, {0: (script, 10**8)})
    assert success, msg
    type_check(tx)
    txout = jm_single().bc_interface.pushtx(tx.serialize())
    assert txout


@pytest.mark.parametrize('wallet_cls,type_check', [
    [LegacyWallet, assert_not_segwit],
    [SegwitLegacyWallet, assert_segwit],
    [SegwitWallet, assert_segwit],
])
def test_signing_simple(setup_wallet, wallet_cls, type_check):
    jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
    storage = VolatileStorage()
    wallet_cls.initialize(storage, get_network(), entropy=b"\xaa"*16)
    wallet = wallet_cls(storage)
    utxo = fund_wallet_addr(wallet, wallet.get_internal_addr(0))
    # The dummy output is constructed as an unspendable p2sh:
    tx = btc.mktx([utxo],
            [{"address": str(btc.CCoinAddress.from_scriptPubKey(
                btc.CScript(b"\x00").to_p2sh_scriptPubKey())),
              "value": 10**8 - 9000}])    
    script = wallet.get_script(0, BaseWallet.ADDRESS_TYPE_INTERNAL, 0)
    success, msg = wallet.sign_tx(tx, {0: (script, 10**8)})
    assert success, msg
    type_check(tx)
    txout = jm_single().bc_interface.pushtx(tx.serialize())
    assert txout

def test_timelocked_output_signing(setup_wallet):
    jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
    ensure_bip65_activated()
    storage = VolatileStorage()
    SegwitLegacyWalletFidelityBonds.initialize(storage, get_network())
    wallet = SegwitLegacyWalletFidelityBonds(storage)

    index = 0
    timenumber = 0
    script = wallet.get_script_and_update_map(
        FidelityBondMixin.FIDELITY_BOND_MIXDEPTH,
        FidelityBondMixin.BIP32_TIMELOCK_ID, index, timenumber)
    utxo = fund_wallet_addr(wallet, wallet.script_to_addr(script))
    timestamp = wallet._time_number_to_timestamp(timenumber)

    tx = btc.mktx([utxo], [{"address": str(btc.CCoinAddress.from_scriptPubKey(
        btc.standard_scripthash_scriptpubkey(btc.Hash160(b"\x00")))),
        "value":10**8 - 9000}], locktime=timestamp+1)
    success, msg = wallet.sign_tx(tx, {0: (script, 10**8)})
    assert success, msg
    txout = jm_single().bc_interface.pushtx(tx.serialize())
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

    utxos = wallet.get_utxos_by_mixdepth()
    assert len(utxos[0]) == num_tx
    for md in range(1, wallet.max_mixdepth + 1):
        assert not utxos[md]

    with pytest.raises(Exception):
        # no funds in mixdepth
        wallet.select_utxos(1, amount)

    with pytest.raises(Exception):
        # not enough funds
        wallet.select_utxos(0, amount * (num_tx + 1))

    wallet.reset_utxos()
    assert wallet.get_balance_by_mixdepth()[0] == 0


def test_select_utxos(setup_wallet):
    jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
    amount = 10**8

    wallet = get_populated_wallet(amount)
    utxos = wallet.select_utxos(0, amount // 2)

    assert len(utxos) == 1
    utxos = list(utxos.keys())

    more_utxos = wallet.select_utxos(0, int(amount * 1.5), utxo_filter=utxos)
    assert len(more_utxos) == 2
    assert utxos[0] not in more_utxos


def test_add_new_utxos(setup_wallet):
    jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
    wallet = get_populated_wallet(num=1)

    scripts = [wallet.get_new_script(x,
                BaseWallet.ADDRESS_TYPE_INTERNAL) for x in range(3)]
    tx_scripts = list(scripts)
    tx = btc.mktx(
            [(b"\x00"*32, 2)],
            [{"address": wallet.script_to_addr(s),
              "value": 10**8} for s in tx_scripts])
    added = wallet.add_new_utxos(tx, 1)
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
        wallet.add_utxo(btc.x(txin), 0, wallet.get_script(1,
                    BaseWallet.ADDRESS_TYPE_INTERNAL, i), 10**8, 1)

    inputs = wallet.select_utxos(0, 10**8)
    inputs.update(wallet.select_utxos(1, 2 * 10**8))
    assert len(inputs) == 3

    tx_inputs = list(inputs.keys())
    tx_inputs.append((b'\x12'*32, 6))

    tx = btc.mktx(tx_inputs,
        [{"address": "2N9gfkUsFW7Kkb1Eurue7NzUxUt7aNJiS1U",
          "value": 3 * 10**8 - 1000}])

    removed = wallet.remove_old_utxos(tx)
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
    script = wallet.get_new_script(1, BaseWallet.ADDRESS_TYPE_INTERNAL)
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

    assert wallet.get_next_unused_index(0, BaseWallet.ADDRESS_TYPE_INTERNAL) == 3
    assert wallet.get_next_unused_index(0, BaseWallet.ADDRESS_TYPE_EXTERNAL) == 0
    assert wallet.get_next_unused_index(1, BaseWallet.ADDRESS_TYPE_INTERNAL) == 0
    assert wallet.get_next_unused_index(1, BaseWallet.ADDRESS_TYPE_EXTERNAL) == 1
    assert wallet.is_known_script(script)


def test_set_next_index(setup_wallet):
    wallet = get_populated_wallet()

    assert wallet.get_next_unused_index(0,
                BaseWallet.ADDRESS_TYPE_INTERNAL) == 3

    with pytest.raises(Exception):
        # cannot advance index without force=True
        wallet.set_next_index(0, BaseWallet.ADDRESS_TYPE_INTERNAL, 5)

    wallet.set_next_index(0, BaseWallet.ADDRESS_TYPE_INTERNAL, 1)
    assert wallet.get_next_unused_index(0, BaseWallet.ADDRESS_TYPE_INTERNAL) == 1

    wallet.set_next_index(0, BaseWallet.ADDRESS_TYPE_INTERNAL, 20, force=True)
    assert wallet.get_next_unused_index(0, BaseWallet.ADDRESS_TYPE_INTERNAL) == 20

    script = wallet.get_new_script(0, BaseWallet.ADDRESS_TYPE_INTERNAL)
    path = wallet.script_to_path(script)
    index = wallet.get_details(path)[2]
    assert index == 20


def test_path_repr(setup_wallet):
    wallet = get_populated_wallet()
    path = wallet.get_path(2, BIP32Wallet.ADDRESS_TYPE_EXTERNAL, 0)
    path_repr = wallet.get_path_repr(path)
    path_new = wallet.path_repr_to_path(path_repr)

    assert path_new == path


def test_path_repr_imported(setup_wallet):
    wallet = get_populated_wallet(num=0)
    path = wallet.import_private_key(
        0, 'cRAGLvPmhpzJNgdMT4W2gVwEW3fusfaDqdQWM2vnWLgXKzCWKtcM')
    path_repr = wallet.get_path_repr(path)
    path_new = wallet.path_repr_to_path(path_repr)

    assert path_new == path

@pytest.mark.parametrize('timenumber,timestamp', [
    [0, 1577836800],
    [50, 1709251200],
    [300, 2366841600],
    [400, None], #too far in the future
    [-1, None] #before epoch
])
def test_timenumber_to_timestamp(setup_wallet, timenumber, timestamp):
    try:
        implied_timestamp = FidelityBondMixin._time_number_to_timestamp(
            timenumber)
        assert implied_timestamp == timestamp
    except ValueError:
        #None means the timenumber is intentionally invalid
        assert timestamp == None

@pytest.mark.parametrize('timestamp,timenumber', [
    [1577836800, 0],
    [1709251200, 50],
    [2366841600, 300],
    [1577836801, None], #not exactly midnight on first of month
    [2629670400, None], #too far in future
    [1575158400, None] #before epoch
])
def test_timestamp_to_timenumber(setup_wallet, timestamp, timenumber):
    try:
        implied_timenumber = FidelityBondMixin.timestamp_to_time_number(
            timestamp)
        assert implied_timenumber == timenumber
    except ValueError:
        assert timenumber == None

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

    path = wallet.get_path(0, BaseWallet.ADDRESS_TYPE_INTERNAL, 0)
    script = wallet.get_script_from_path(path)
    addr = wallet.script_to_addr(script)

    assert script == wallet.addr_to_script(addr)
    addr_path = wallet.addr_to_path(addr)
    assert path == addr_path


def test_imported_key_removed(setup_wallet):
    wif = 'cRAGLvPmhpzJNgdMT4W2gVwEW3fusfaDqdQWM2vnWLgXKzCWKtcM'

    storage = VolatileStorage()
    SegwitLegacyWallet.initialize(storage, get_network())
    wallet = SegwitLegacyWallet(storage)

    path = wallet.import_private_key(1, wif)
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
    bci = jm_single().bc_interface
    unspent_list = bci.listunspent(0)
    # filter on label, but note (a) in certain circumstances (in-
    # wallet transfer) it is possible for the utxo to be labeled
    # with the external label, and (b) the wallet will know if it
    # belongs or not anyway (is_known_addr):
    our_unspent_list = [x for x in unspent_list if (
        bci.is_address_labeled(x, wallet.get_wallet_name()))]
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
    assert utxo in new_wallet.select_utxos(max_mixdepth, 10**7)

def test_watchonly_wallet(setup_wallet):
    jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
    storage = VolatileStorage()
    SegwitLegacyWalletFidelityBonds.initialize(storage, get_network())
    wallet = SegwitLegacyWalletFidelityBonds(storage)

    paths = [
        "m/49'/1'/0'/0/0",
        "m/49'/1'/0'/1/0",
        "m/49'/1'/0'/2/0:1577836800",
        "m/49'/1'/0'/2/0:2314051200"
    ]
    burn_path = "m/49'/1'/0'/3/0"

    scripts = [wallet.get_script_from_path(wallet.path_repr_to_path(path))
        for path in paths]
    privkey, engine = wallet._get_key_from_path(wallet.path_repr_to_path(burn_path))
    burn_pubkey = engine.privkey_to_pubkey(privkey)

    master_pub_key = wallet.get_bip32_pub_export(
        FidelityBondMixin.FIDELITY_BOND_MIXDEPTH)
    watchonly_storage = VolatileStorage()
    entropy = FidelityBondMixin.get_xpub_from_fidelity_bond_master_pub_key(
        master_pub_key).encode()
    FidelityBondWatchonlyWallet.initialize(watchonly_storage, get_network(),
        entropy=entropy)
    watchonly_wallet = FidelityBondWatchonlyWallet(watchonly_storage)

    watchonly_scripts = [watchonly_wallet.get_script_from_path(
        watchonly_wallet.path_repr_to_path(path)) for path in paths]
    privkey, engine = wallet._get_key_from_path(wallet.path_repr_to_path(burn_path))
    watchonly_burn_pubkey = engine.privkey_to_pubkey(privkey)

    for script, watchonly_script in zip(scripts, watchonly_scripts):
        assert script == watchonly_script
    assert burn_pubkey == watchonly_burn_pubkey

def test_calculate_timelocked_fidelity_bond_value(setup_wallet):
    EPSILON = 0.000001
    YEAR = 60*60*24*356.25

    #the function should be flat anywhere before the locktime ends
    values = [FidelityBondMixin.calculate_timelocked_fidelity_bond_value(
        utxo_value=100000000,
        confirmation_time=0,
        locktime=6*YEAR,
        current_time=y*YEAR,
        interest_rate=0.01
        )
        for y in range(4)
    ]
    value_diff = [values[i] - values[i+1] for i in range(len(values)-1)]
    for vd in value_diff:
        assert abs(vd) < EPSILON

    #after locktime, the value should go down
    values = [FidelityBondMixin.calculate_timelocked_fidelity_bond_value(
        utxo_value=100000000,
        confirmation_time=0,
        locktime=6*YEAR,
        current_time=(6+y)*YEAR,
        interest_rate=0.01
        )
        for y in range(5)
    ]
    value_diff = [values[i+1] - values[i] for i in range(len(values)-1)]
    for vrd in value_diff:
        assert vrd < 0

    #value of a bond goes up as the locktime goes up
    values = [FidelityBondMixin.calculate_timelocked_fidelity_bond_value(
        utxo_value=100000000,
        confirmation_time=0,
        locktime=y*YEAR,
        current_time=0,
        interest_rate=0.01
        )
        for y in range(5)
    ]
    value_ratio = [values[i] / values[i+1] for i in range(len(values)-1)]
    value_ratio_diff = [value_ratio[i] - value_ratio[i+1] for i in range(len(value_ratio)-1)]
    for vrd in value_ratio_diff:
        assert vrd < 0

    #value of a bond locked into the far future is constant, clamped at the value of burned coins
    values = [FidelityBondMixin.calculate_timelocked_fidelity_bond_value(
        utxo_value=100000000,
        confirmation_time=0,
        locktime=(200+y)*YEAR,
        current_time=0,
        interest_rate=0.01
        )
        for y in range(5)
    ]
    value_diff = [values[i] - values[i+1] for i in range(len(values)-1)]
    for vd in value_diff:
        assert abs(vd) < EPSILON

@pytest.mark.parametrize('password, wallet_cls', [
    ["hunter2", SegwitLegacyWallet],
    ["hunter2", SegwitWallet],
])
def test_create_wallet(setup_wallet, password, wallet_cls):
    wallet_name = test_create_wallet_filename
    password = password.encode("utf-8")
    # test mainnet (we are not transacting)
    btc.select_chain_params("bitcoin")
    wallet = create_wallet(wallet_name, password, 4, wallet_cls)
    mnemonic = wallet.get_mnemonic_words()[0]
    firstkey = wallet.get_key_from_addr(wallet.get_addr(0,0,0))
    print("Created mnemonic, firstkey: ", mnemonic, firstkey)
    wallet.close()
    # ensure that the wallet file created is openable with the password,
    # and has the parameters that were claimed on creation:
    new_wallet = open_test_wallet_maybe(wallet_name, "", 4,
                        password=password, ask_for_password=False)
    assert new_wallet.get_mnemonic_words()[0] == mnemonic
    assert new_wallet.get_key_from_addr(
        new_wallet.get_addr(0,0,0)) == firstkey
    os.remove(wallet_name)
    btc.select_chain_params("bitcoin/regtest")

@pytest.fixture(scope='module')
def setup_wallet(request):
    load_test_config()
    btc.select_chain_params("bitcoin/regtest")
    #see note in cryptoengine.py:
    cryptoengine.BTC_P2WPKH.VBYTE = 100
    jm_single().bc_interface.tick_forward_chain_interval = 2
    def teardown():
        if os.path.exists(test_create_wallet_filename):
            os.remove(test_create_wallet_filename)
    request.addfinalizer(teardown)
