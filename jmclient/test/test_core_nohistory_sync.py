#! /usr/bin/env python
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401
'''Wallet functionality tests.'''

"""BitcoinCoreNoHistoryInterface functionality tests."""

from commontest import create_wallet_for_sync

import pytest
from jmbase import get_log
from jmclient import load_program_config

log = get_log()

def test_fast_sync_unavailable(setup_sync):
    load_program_config(bs="bitcoin-rpc-no-history")
    wallet_service = create_wallet_for_sync([0, 0, 0, 0, 0],
        ['test_fast_sync_unavailable'])
    with pytest.raises(RuntimeError) as e_info:
        wallet_service.sync_wallet(fast=True)

@pytest.mark.parametrize('internal', (False, True))
def test_sync(setup_sync, internal):
    load_program_config(bs="bitcoin-rpc-no-history")
    used_count = [1, 3, 6, 2, 23]
    wallet_service = create_wallet_for_sync(used_count, ['test_sync'],
        populate_internal=internal)
    ##the gap limit should be not zero before sync
    assert wallet_service.gap_limit > 0
    for md in range(len(used_count)):
        ##obtaining an address should be possible without error before sync
        wallet_service.get_new_script(md, internal)

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
    pass
