#! /usr/bin/env python
'''Wallet functionality tests.'''

"""BitcoinCoreNoHistoryInterface functionality tests."""

from commontest import create_wallet_for_sync

import pytest
from jmbase import get_log
from jmclient import (load_test_config, SegwitLegacyWallet,
                      SegwitWallet, jm_single)
from jmbitcoin import select_chain_params

log = get_log()

def test_fast_sync_unavailable(setup_sync):
    wallet_service = create_wallet_for_sync([0, 0, 0, 0, 0],
        ['test_fast_sync_unavailable'])
    with pytest.raises(RuntimeError) as e_info:
        wallet_service.sync_wallet(fast=True)

@pytest.mark.parametrize('internal, wallet_cls', [(False, SegwitLegacyWallet),
                                                  (True, SegwitLegacyWallet),
                                                  (False, SegwitWallet),
                                                  (True, SegwitWallet)])
def test_sync(setup_sync, internal, wallet_cls):
    used_count = [1, 3, 6, 2, 23]
    wallet_service = create_wallet_for_sync(used_count, ['test_sync'],
        populate_internal=internal, wallet_cls=wallet_cls)
    ##the gap limit should be not zero before sync
    assert wallet_service.gap_limit > 0
    for md in range(len(used_count)):
        ##obtaining an address should be possible without error before sync
        wallet_service.get_new_script(md, internal)

    # TODO bci should probably not store this state globally,
    # in case syncing is needed for multiple wallets (as in this test):
    jm_single().bc_interface.import_addresses_call_count = 0
    wallet_service.sync_wallet(fast=False)

    for md in range(len(used_count)):
        ##plus one to take into account the one new script obtained above
        assert used_count[md] + 1 == wallet_service.get_next_unused_index(md,
            internal)
    #gap limit is zero after sync
    assert wallet_service.gap_limit == 0
    #obtaining an address leads to an error after sync
    with pytest.raises(RuntimeError) as e_info:
        wallet_service.get_new_script(0, internal)


@pytest.fixture(scope='module')
def setup_sync():
    load_test_config(bs="bitcoin-rpc-no-history")
    # a special case needed for the bitcoin core
    # no history interface: it does not use
    # 'blockchain_source' to distinguish regtest,
    # so it must be set specifically for the test
    # here:
    select_chain_params("bitcoin/regtest")
