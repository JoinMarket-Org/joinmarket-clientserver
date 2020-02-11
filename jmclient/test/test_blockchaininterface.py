
"""Blockchaininterface functionality tests."""

import binascii
from commontest import create_wallet_for_sync

import pytest
from jmbase import get_log
from jmclient import load_test_config, jm_single

log = get_log()


def sync_test_wallet(fast, wallet_service):
    sync_count = 0
    wallet_service.synced = False
    while not wallet_service.synced:
        wallet_service.sync_wallet(fast=fast)
        sync_count += 1
        # avoid infinite loop
        assert sync_count < 10
        log.debug("Tried " + str(sync_count) + " times")


@pytest.mark.parametrize('fast', (False, True))
def test_empty_wallet_sync(setup_wallets, fast):
    wallet_service = create_wallet_for_sync([0, 0, 0, 0, 0], ['test_empty_wallet_sync'])

    sync_test_wallet(fast, wallet_service)

    broken = True
    for md in range(wallet_service.max_mixdepth + 1):
        for internal in (True, False):
            broken = False
            assert 0 == wallet_service.get_next_unused_index(md, internal)
    assert not broken


@pytest.mark.parametrize('fast,internal', (
        (False, False), (False, True),
        (True, False), (True, True)))
def test_sequentially_used_wallet_sync(setup_wallets, fast, internal):
    used_count = [1, 3, 6, 2, 23]
    wallet_service = create_wallet_for_sync(
        used_count, ['test_sequentially_used_wallet_sync'],
        populate_internal=internal)

    sync_test_wallet(fast, wallet_service)

    broken = True
    for md in range(len(used_count)):
        broken = False
        assert used_count[md] == wallet_service.get_next_unused_index(md, internal)
    assert not broken


@pytest.mark.parametrize('fast', (False,))
def test_gap_used_wallet_sync(setup_wallets, fast):
    """ After careful examination this test now only includes the Recovery sync.
    Note: pre-Aug 2019, because of a bug, this code was not in fact testing both
    Fast and Recovery sync, but only Recovery (twice). Also, the scenario set
    out in this test (where coins are funded to a wallet which has no index-cache,
    and initially no imports) is only appropriate for recovery-mode sync, not for
    fast-mode (the now default).
    """
    used_count = [1, 3, 6, 2, 23]
    wallet_service = create_wallet_for_sync(used_count, ['test_gap_used_wallet_sync'])
    wallet_service.gap_limit = 20

    for md in range(len(used_count)):
        x = -1
        for x in range(md):
            assert x <= wallet_service.gap_limit, "test broken"
            # create some unused addresses
            wallet_service.get_new_script(md, True)
            wallet_service.get_new_script(md, False)
        used_count[md] += x + 2
        jm_single().bc_interface.grab_coins(wallet_service.get_new_addr(md, True), 1)
        jm_single().bc_interface.grab_coins(wallet_service.get_new_addr(md, False), 1)

    # reset indices to simulate completely unsynced wallet
    for md in range(wallet_service.max_mixdepth + 1):
        wallet_service.set_next_index(md, True, 0)
        wallet_service.set_next_index(md, False, 0)
    sync_test_wallet(fast, wallet_service)

    broken = True
    for md in range(len(used_count)):
        broken = False
        assert md + 1 == wallet_service.get_next_unused_index(md, True)
        assert used_count[md] == wallet_service.get_next_unused_index(md, False)
    assert not broken


@pytest.mark.parametrize('fast', (False,))
def test_multigap_used_wallet_sync(setup_wallets, fast):
    """ See docstring for test_gap_used_wallet_sync; exactly the
    same applies here.
    """
    start_index = 5
    used_count = [start_index, 0, 0, 0, 0]
    wallet_service = create_wallet_for_sync(used_count, ['test_multigap_used_wallet_sync'])
    wallet_service.gap_limit = 5

    mixdepth = 0
    for w in range(5):
        for x in range(int(wallet_service.gap_limit * 0.6)):
            assert x <= wallet_service.gap_limit, "test broken"
            # create some unused addresses
            wallet_service.get_new_script(mixdepth, True)
            wallet_service.get_new_script(mixdepth, False)
        used_count[mixdepth] += x + 2
        jm_single().bc_interface.grab_coins(wallet_service.get_new_addr(mixdepth, True), 1)
        jm_single().bc_interface.grab_coins(wallet_service.get_new_addr(mixdepth, False), 1)

    # reset indices to simulate completely unsynced wallet
    for md in range(wallet_service.max_mixdepth + 1):
        wallet_service.set_next_index(md, True, 0)
        wallet_service.set_next_index(md, False, 0)

    sync_test_wallet(fast, wallet_service)

    assert used_count[mixdepth] - start_index == wallet_service.get_next_unused_index(mixdepth, True)
    assert used_count[mixdepth] == wallet_service.get_next_unused_index(mixdepth, False)


@pytest.mark.parametrize('fast', (False, True))
def test_retain_unused_indices_wallet_sync(setup_wallets, fast):
    used_count = [0, 0, 0, 0, 0]
    wallet_service = create_wallet_for_sync(used_count, ['test_retain_unused_indices_wallet_sync'])

    for x in range(9):
        wallet_service.get_new_script(0, 1)

    sync_test_wallet(fast, wallet_service)

    assert wallet_service.get_next_unused_index(0, 1) == 9


@pytest.mark.parametrize('fast', (False, True))
def test_imported_wallet_sync(setup_wallets, fast):
    used_count = [0, 0, 0, 0, 0]
    wallet_service = create_wallet_for_sync(used_count, ['test_imported_wallet_sync'])
    source_wallet_service = create_wallet_for_sync(used_count, ['test_imported_wallet_sync_origin'])

    address = source_wallet_service.get_internal_addr(0)
    wallet_service.import_private_key(0, source_wallet_service.get_wif(0, 1, 0))
    txid = binascii.unhexlify(jm_single().bc_interface.grab_coins(address, 1))

    sync_test_wallet(fast, wallet_service)

    assert wallet_service._utxos.have_utxo(txid, 0) == 0


@pytest.fixture(scope='module')
def setup_wallets():
    load_test_config()
    jm_single().bc_interface.tick_forward_chain_interval = 1
