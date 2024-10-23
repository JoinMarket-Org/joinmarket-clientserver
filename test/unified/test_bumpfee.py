import pytest
from jmbase import hextobin
import jmbitcoin as btc
from jmclient import load_test_config, cryptoengine, jm_single, SegwitWallet, \
    VolatileStorage, get_network, WalletService
from scripts.bumpfee import (
    check_valid_candidate, compute_bump_fee,
    create_bumped_tx, sign_transaction, sign_psbt)

def fund_wallet_addr(wallet, addr, value_btc=1):
    # special case, grab_coins returns hex from rpc:
    txin_id = hextobin(jm_single().bc_interface.grab_coins(addr, value_btc))
    txinfo = jm_single().bc_interface.get_transaction(txin_id)
    txin = btc.CMutableTransaction.deserialize(btc.x(txinfo["hex"]))
    utxo_in = wallet.add_new_utxos(txin, 1)
    assert len(utxo_in) == 1
    return list(utxo_in.keys())[0]

def test_tx_vsize(setup_wallet):
    # tests that we correctly compute the transaction size
    wallet = setup_wallet[0]
    wallet_service = setup_wallet[1]
    wallet_service.resync_wallet()
    addr = wallet.get_external_addr(0)
    utxo = fund_wallet_addr(wallet, addr)
    amount_sats = 10**7
    tx = btc.mktx([utxo],
                  [{"address": str(btc.CCoinAddress.from_scriptPubKey(
                      btc.CScript(b"\x00").to_p2sh_scriptPubKey())),
                    "value": amount_sats},
                   {"address": wallet.get_internal_addr(0),
                    "value": 10**8 - amount_sats - 142}])
    tx.vin[0].nSequence = 0xffffffff - 2  # mark as replaceable
    success, msg = wallet.sign_tx(tx, {0: (wallet.addr_to_script(addr), 10**8)})

    assert btc.tx_vsize(tx) in (142, 143)  # transaction size may vary due to signature

def test_check_valid_candidate_confirmed_tx(setup_wallet):
    # test that the replaceable transaction is unconfirmed
    wallet = setup_wallet[0]
    wallet_service = setup_wallet[1]
    wallet_service.resync_wallet()
    addr = wallet.get_external_addr(0)
    utxo = fund_wallet_addr(wallet, addr)
    amount_sats = 10**7
    tx = btc.mktx([utxo],
                  [{"address": str(btc.CCoinAddress.from_scriptPubKey(
                      btc.CScript(b"\x00").to_p2sh_scriptPubKey())),
                    "value": amount_sats},
                   {"address": wallet.get_internal_addr(0),
                    "value": 10**8 - amount_sats - 142}])
    success, msg = wallet.sign_tx(tx, {0: (wallet.addr_to_script(addr), 10**8)})
    success = jm_single().bc_interface.pushtx(tx.serialize())
    jm_single().bc_interface.tick_forward_chain(1)

    with pytest.raises(RuntimeWarning, match="Transaction already confirmed. Nothing to do."):
        check_valid_candidate(tx, wallet)

def test_check_valid_candidate_unowned_input(setup_wallet):
    # tests that all inputs in the replaceable transaction belong to the wallet
    wallet = setup_wallet[0]
    wallet_service = setup_wallet[1]
    wallet_service.resync_wallet()
    addr = wallet.get_external_addr(0)
    utxo = fund_wallet_addr(wallet, addr)
    amount_sats = 10**7

    mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
    entropy = SegwitWallet.entropy_from_mnemonic(mnemonic)
    storage = VolatileStorage()
    SegwitWallet.initialize(
        storage, get_network(), entropy=entropy, max_mixdepth=0)
    wallet_ext = SegwitWallet(storage)
    addr_ext = wallet_ext.get_external_addr(0)
    utxo_ext = fund_wallet_addr(wallet_ext, addr_ext)

    tx = btc.mktx([utxo, utxo_ext],
                  [{"address": str(btc.CCoinAddress.from_scriptPubKey(
                      btc.CScript(b"\x00").to_p2sh_scriptPubKey())),
                    "value": amount_sats},
                   {"address": wallet.get_internal_addr(0),
                    "value": (2 * 10**8) - amount_sats - 210}])
    tx.vin[0].nSequence = 0xffffffff - 2  # mark as replaceable
    success, msg = wallet.sign_tx(tx, {0: (wallet.addr_to_script(addr), 10**8)})
    success, msg = wallet_ext.sign_tx(tx, {1: (wallet_ext.addr_to_script(addr_ext), 10**8)})
    success = jm_single().bc_interface.pushtx(tx.serialize())

    with pytest.raises(ValueError, match="Transaction inputs should belong to the wallet."):
        check_valid_candidate(tx, wallet)

def test_check_valid_candidate_explicit_output_index(setup_wallet):
    # tests that there's at least one output that we own and can deduct fees
    wallet = setup_wallet[0]
    wallet_service = setup_wallet[1]
    wallet_service.resync_wallet()
    addr = wallet.get_external_addr(0)
    utxo = fund_wallet_addr(wallet, addr)
    amount_sats = 10**7
    tx = btc.mktx([utxo],
                  [{"address": str(btc.CCoinAddress.from_scriptPubKey(
                      btc.CScript(b"\x00").to_p2sh_scriptPubKey())),
                    "value": 10**8 - amount_sats - 143},
                   {"address": str(btc.CCoinAddress.from_scriptPubKey(
                      btc.CScript(b"\x01").to_p2sh_scriptPubKey())),
                    "value": amount_sats}])
    tx.vin[0].nSequence = 0xffffffff - 2  # mark as replaceable
    success, msg = wallet.sign_tx(tx, {0: (wallet.addr_to_script(addr), 10**8)})
    success = jm_single().bc_interface.pushtx(tx.serialize())

    assert check_valid_candidate(tx, wallet, 0) == None

def test_check_valid_candidate_one_output(setup_wallet):
    # tests that there's at least one output that we own and can deduct fees
    wallet = setup_wallet[0]
    wallet_service = setup_wallet[1]
    wallet_service.resync_wallet()
    addr = wallet.get_external_addr(0)
    utxo = fund_wallet_addr(wallet, addr)
    amount_sats = 10**7
    tx = btc.mktx([utxo],
                  [{"address": str(btc.CCoinAddress.from_scriptPubKey(
                      btc.CScript(b"\x00").to_p2sh_scriptPubKey())),
                    "value": 10**8 - 111}])
    tx.vin[0].nSequence = 0xffffffff - 2  # mark as replaceable
    success, msg = wallet.sign_tx(tx, {0: (wallet.addr_to_script(addr), 10**8)})
    success = jm_single().bc_interface.pushtx(tx.serialize())

    assert check_valid_candidate(tx, wallet) == None

def test_check_valid_candidate_no_owned_outputs(setup_wallet):
    # tests that there's at least one output that we own and can deduct fees
    wallet = setup_wallet[0]
    wallet_service = setup_wallet[1]
    wallet_service.resync_wallet()
    addr = wallet.get_external_addr(0)
    utxo = fund_wallet_addr(wallet, addr)
    amount_sats = 10**7
    tx = btc.mktx([utxo],
                  [{"address": str(btc.CCoinAddress.from_scriptPubKey(
                      btc.CScript(b"\x00").to_p2sh_scriptPubKey())),
                    "value": 10**8 - amount_sats - 143},
                   {"address": str(btc.CCoinAddress.from_scriptPubKey(
                      btc.CScript(b"\x01").to_p2sh_scriptPubKey())),
                    "value": amount_sats}])
    tx.vin[0].nSequence = 0xffffffff - 2  # mark as replaceable
    success, msg = wallet.sign_tx(tx, {0: (wallet.addr_to_script(addr), 10**8)})
    success = jm_single().bc_interface.pushtx(tx.serialize())

    with pytest.raises(ValueError, match="Transaction has no obvious output we can deduct fees from. "
                       "Specify the output to pay from using the -o option."):
        check_valid_candidate(tx, wallet)

def test_check_valid_candidate(setup_wallet):
    # tests that all checks are passed for a valid replaceable transaction
    wallet = setup_wallet[0]
    wallet_service = setup_wallet[1]
    wallet_service.resync_wallet()
    addr = wallet.get_external_addr(0)
    utxo = fund_wallet_addr(wallet, addr)
    amount_sats = 10**7
    tx = btc.mktx([utxo],
                  [{"address": str(btc.CCoinAddress.from_scriptPubKey(
                      btc.CScript(b"\x00").to_p2sh_scriptPubKey())),
                    "value": amount_sats},
                   {"address": wallet.get_internal_addr(0),
                    "value": 10**8 - amount_sats - 142}])
    tx.vin[0].nSequence = 0xffffffff - 2  # mark as replaceable
    success, msg = wallet.sign_tx(tx, {0: (wallet.addr_to_script(addr), 10**8)})
    success = jm_single().bc_interface.pushtx(tx.serialize())

    assert check_valid_candidate(tx, wallet) == None

def test_compute_bump_fee(setup_wallet):
    # tests that the compute_bump_fee method correctly calculates
    # the fee by which to bump the transaction
    wallet = setup_wallet[0]
    wallet_service = setup_wallet[1]
    wallet_service.resync_wallet()
    addr = wallet.get_external_addr(0)
    utxo = fund_wallet_addr(wallet, addr)
    amount_sats = 10**7
    tx = btc.mktx([utxo],
                  [{"address": str(btc.CCoinAddress.from_scriptPubKey(
                      btc.CScript(b"\x00").to_p2sh_scriptPubKey())),
                    "value": amount_sats},
                   {"address": wallet.get_internal_addr(0),
                    "value": 10**8 - amount_sats - 142}])
    tx.vin[0].nSequence = 0xffffffff - 2  # mark as replaceable
    success, msg = wallet.sign_tx(tx, {0: (wallet.addr_to_script(addr), 10**8)})
    success = jm_single().bc_interface.pushtx(tx.serialize())

    assert compute_bump_fee(tx, 2000) in (142, 144)  # will vary depending on signature size

def test_create_bumped_tx(setup_wallet):
    # tests that the bumped transaction has a change output with amount
    # less the bump fee
    wallet = setup_wallet[0]
    wallet_service = setup_wallet[1]
    wallet_service.resync_wallet()
    addr = wallet.get_external_addr(0)
    utxo = fund_wallet_addr(wallet, addr)
    amount_sats = 10**7
    tx = btc.mktx([utxo],
                  [{"address": str(btc.CCoinAddress.from_scriptPubKey(
                      btc.CScript(b"\x00").to_p2sh_scriptPubKey())),
                    "value": amount_sats},
                   {"address": wallet.get_internal_addr(0),
                    "value": 10**8 - amount_sats - 142}])
    tx.vin[0].nSequence = 0xffffffff - 2  # mark as replaceable
    success, msg = wallet.sign_tx(tx, {0: (wallet.addr_to_script(addr), 10**8)})
    success = jm_single().bc_interface.pushtx(tx.serialize())
    orig_tx = tx.clone()

    bumped_tx = create_bumped_tx(tx, 2000, wallet)

    assert orig_tx.vin[0] == bumped_tx.vin[0]
    assert orig_tx.vout[0] == bumped_tx.vout[0]
    assert (orig_tx.vout[1].nValue - bumped_tx.vout[1].nValue) in (142, 144)

def test_create_bumped_tx_dust_change(setup_wallet):
    # tests that the change output gets dropped when it's at or below dust
    wallet = setup_wallet[0]
    wallet_service = setup_wallet[1]
    wallet_service.resync_wallet()
    addr = wallet.get_external_addr(0)
    utxo = fund_wallet_addr(wallet, addr)
    amount_sats = 10**8 - jm_single().BITCOIN_DUST_THRESHOLD - 142
    change_sats = 10**8 - amount_sats - 142
    tx = btc.mktx([utxo],
                  [{"address": str(btc.CCoinAddress.from_scriptPubKey(
                      btc.CScript(b"\x00").to_p2sh_scriptPubKey())),
                    "value": amount_sats},
                   {"address": wallet.get_internal_addr(0),
                    "value": change_sats}])
    tx.vin[0].nSequence = 0xffffffff - 2  # mark as replaceable
    success, msg = wallet.sign_tx(tx, {0: (wallet.addr_to_script(addr), 10**8)})
    success = jm_single().bc_interface.pushtx(tx.serialize())
    orig_tx = tx.clone()

    bumped_tx = create_bumped_tx(tx, 2000, wallet)

    assert orig_tx.vin[0] == bumped_tx.vin[0]
    assert orig_tx.vout[0] == bumped_tx.vout[0]
    assert len(bumped_tx.vout) == 1

def test_create_bumped_tx_multi_dust_change(setup_wallet):
    # tests that several change outputs get dropped when they are at or below dust
    # to fulfill fee requirements
    wallet = setup_wallet[0]
    wallet_service = setup_wallet[1]
    wallet_service.resync_wallet()
    addr = wallet.get_external_addr(0)
    utxo = fund_wallet_addr(wallet, addr)
    amount_sats = 10**8 - (546*18) - 669
    change_sats = 546
    tx = btc.mktx([utxo],
                  [{"address": str(btc.CCoinAddress.from_scriptPubKey(
                      btc.CScript(b"\x00").to_p2sh_scriptPubKey())),
                    "value": amount_sats}] +
                   [{"address": wallet.get_internal_addr(0),
                    "value": change_sats} for ix in range(18)])
    tx.vin[0].nSequence = 0xffffffff - 2  # mark as replaceable
    success, msg = wallet.sign_tx(tx, {0: (wallet.addr_to_script(addr), 10**8)})
    success = jm_single().bc_interface.pushtx(tx.serialize())
    orig_tx = tx.clone()

    bumped_tx = create_bumped_tx(tx, 3000, wallet)

    assert orig_tx.vin[0] == bumped_tx.vin[0]
    assert orig_tx.vout[0] == bumped_tx.vout[0]
    assert len(bumped_tx.vout) == 16

def test_create_bumped_tx_single_output(setup_wallet):
    # tests that fees are deducted from the only output available
    # in the transaction
    wallet = setup_wallet[0]
    wallet_service = setup_wallet[1]
    wallet_service.resync_wallet()
    addr = wallet.get_external_addr(0)
    utxo = fund_wallet_addr(wallet, addr)
    amount_sats = 10**8 - 111
    tx = btc.mktx([utxo],
                  [{"address": str(btc.CCoinAddress.from_scriptPubKey(
                      btc.CScript(b"\x00").to_p2sh_scriptPubKey())),
                    "value": amount_sats}])
    tx.vin[0].nSequence = 0xffffffff - 2  # mark as replaceable
    success, msg = wallet.sign_tx(tx, {0: (wallet.addr_to_script(addr), 10**8)})
    success = jm_single().bc_interface.pushtx(tx.serialize())
    orig_tx = tx.clone()

    bumped_tx = create_bumped_tx(tx, 2000, wallet)

    assert orig_tx.vin[0] == bumped_tx.vin[0]
    assert (orig_tx.vout[0].nValue - bumped_tx.vout[0].nValue) in (111, 113)

def test_create_bumped_tx_output_index(setup_wallet):
    # tests that the bumped transaction deducts its fee from the specified
    # output even if it is an external wallet address
    wallet = setup_wallet[0]
    wallet_service = setup_wallet[1]
    wallet_service.resync_wallet()
    addr = wallet.get_external_addr(0)
    utxo = fund_wallet_addr(wallet, addr)
    amount_sats = 10**7
    tx = btc.mktx([utxo],
                  [{"address": str(btc.CCoinAddress.from_scriptPubKey(
                      btc.CScript(b"\x00").to_p2sh_scriptPubKey())),
                    "value": amount_sats},
                   {"address": wallet.get_internal_addr(0),
                    "value": 10**8 - amount_sats - 142}])
    tx.vin[0].nSequence = 0xffffffff - 2  # mark as replaceable
    success, msg = wallet.sign_tx(tx, {0: (wallet.addr_to_script(addr), 10**8)})
    success = jm_single().bc_interface.pushtx(tx.serialize())
    orig_tx = tx.clone()

    bumped_tx = create_bumped_tx(tx, 2000, wallet, 0)

    assert orig_tx.vin[0] == bumped_tx.vin[0]
    assert orig_tx.vout[1] == bumped_tx.vout[1]
    assert (orig_tx.vout[0].nValue - bumped_tx.vout[0].nValue) in (142, 144)

def test_create_bumped_tx_no_change(setup_wallet):
    # tests that the bumped transaction is the same as the original if fees
    # cannot be deducted
    wallet = setup_wallet[0]
    wallet_service = setup_wallet[1]
    wallet_service.resync_wallet()
    addr = wallet.get_external_addr(0)
    utxo = fund_wallet_addr(wallet, addr, 0.00002843)
    amount_sats = 2730
    tx = btc.mktx([utxo],
                  [{"address": str(btc.CCoinAddress.from_scriptPubKey(
                      btc.CScript(b"\x00").to_p2sh_scriptPubKey())),
                    "value": amount_sats}])
    tx.vin[0].nSequence = 0xffffffff - 2  # mark as replaceable
    success, msg = wallet.sign_tx(tx, {0: (wallet.addr_to_script(addr), 2843)})
    success = jm_single().bc_interface.pushtx(tx.serialize())
    orig_tx = tx.clone()

    bumped_tx = create_bumped_tx(tx, 3000, wallet)

    assert orig_tx.vin[0] == bumped_tx.vin[0]
    assert orig_tx.vout[0] == bumped_tx.vout[0]

def test_sign_and_broadcast(setup_wallet):
    # tests that we can correctly sign and broadcast a replaced transaction
    wallet = setup_wallet[0]
    wallet_service = setup_wallet[1]
    wallet_service.resync_wallet()
    addr = wallet.get_external_addr(0)
    utxo = fund_wallet_addr(wallet, addr)
    amount_sats = 10**8 - jm_single().BITCOIN_DUST_THRESHOLD - 142
    change_sats = 10**8 - amount_sats - 142
    tx = btc.mktx([utxo],
                  [{"address": str(btc.CCoinAddress.from_scriptPubKey(
                      btc.CScript(b"\x00").to_p2sh_scriptPubKey())),
                    "value": amount_sats},
                   {"address": wallet.get_internal_addr(0),
                    "value": change_sats}])
    tx.vin[0].nSequence = 0xffffffff - 2  # mark as replaceable
    success, msg = wallet.sign_tx(tx, {0: (wallet.addr_to_script(addr), 10**8)})
    success = jm_single().bc_interface.pushtx(tx.serialize())
    orig_tx = tx.clone()

    bumped_tx = create_bumped_tx(tx, 2000, wallet)
    sign_transaction(bumped_tx, orig_tx, wallet_service)

    assert jm_single().bc_interface.pushtx(bumped_tx.serialize()) == True

def test_sign_psbt_broadcast(setup_wallet):
    # tests that we can correctly sign and broadcast a replaced psbt transaction
    wallet = setup_wallet[0]
    wallet_service = setup_wallet[1]
    wallet_service.resync_wallet()
    addr = wallet.get_external_addr(0)
    utxo = fund_wallet_addr(wallet, addr)
    amount_sats = 10**8 - jm_single().BITCOIN_DUST_THRESHOLD - 142
    change_sats = 10**8 - amount_sats - 142
    tx = btc.mktx([utxo],
                  [{"address": str(btc.CCoinAddress.from_scriptPubKey(
                      btc.CScript(b"\x00").to_p2sh_scriptPubKey())),
                    "value": amount_sats},
                   {"address": wallet.get_internal_addr(0),
                    "value": change_sats}])
    tx.vin[0].nSequence = 0xffffffff - 2  # mark as replaceable
    success, msg = wallet.sign_tx(tx, {0: (wallet.addr_to_script(addr), 10**8)})
    success = jm_single().bc_interface.pushtx(tx.serialize())
    orig_tx = tx.clone()

    bumped_tx = create_bumped_tx(tx, 2000, wallet)
    psbt = sign_psbt(bumped_tx, orig_tx, wallet_service)

    assert jm_single().bc_interface.pushtx(psbt.extract_transaction().serialize()) == True


@pytest.fixture(scope='module')
def setup_wallet(request):
    load_test_config()
    btc.select_chain_params("bitcoin/regtest")
    #see note in cryptoengine.py:
    cryptoengine.BTC_P2WPKH.VBYTE = 100
    jm_single().bc_interface.tick_forward_chain_interval = 2
    jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
    mnemonic = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo abstract'
    entropy = SegwitWallet.entropy_from_mnemonic(mnemonic)
    storage = VolatileStorage()
    SegwitWallet.initialize(
        storage, get_network(), entropy=entropy, max_mixdepth=1)
    wallet = SegwitWallet(storage)
    wallet_service = WalletService(wallet)
    return [wallet, wallet_service]
