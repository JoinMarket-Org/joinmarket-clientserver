from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401

"""
Test doing full coinjoins, bypassing IRC
"""

import os
import sys
import pytest
from twisted.internet import reactor

from jmclient import load_program_config, jm_single, get_log,\
    YieldGeneratorBasic, Taker, sync_wallet, LegacyWallet, SegwitLegacyWallet
from jmclient.podle import set_commitment_file
from commontest import make_wallets, binarize_tx
from test_taker import dummy_filter_orderbook
import jmbitcoin as btc

testdir = os.path.dirname(os.path.realpath(__file__))
log = get_log()


def make_wallets_to_list(make_wallets_data):
    wallets = [None for x in range(len(make_wallets_data))]
    for i in make_wallets_data:
        wallets[i] = make_wallets_data[i]['wallet']
    assert all(wallets)
    return wallets


def sync_wallets(wallets):
    for w in wallets:
        w.gap_limit = 0
        jm_single().bc_interface.wallet_synced = False
        for x in range(20):
            if jm_single().bc_interface.wallet_synced:
                break
            sync_wallet(w)
        else:
            assert False, "Failed to sync wallet"


def create_orderbook(makers):
    orderbook = []
    for i in range(len(makers)):
        m = makers[i]
        assert len(m.offerlist) == 1
        m.offerlist[0]['counterparty'] = str(i)
        orderbook.extend(m.offerlist)
    return orderbook


def create_taker(wallet, schedule, monkeypatch):
    def on_finished_callback(*args, **kwargs):
        log.debug("on finished called with: {}, {}".format(args, kwargs))
        on_finished_callback.status = args[0]
        on_finished_callback.called = True
    on_finished_callback.called = False
    on_finished_callback.status = None
    taker = Taker(wallet, schedule, callbacks=(dummy_filter_orderbook, None,
                                               on_finished_callback))

    # we have skipped irc key setup and key exchange, handled by jmdaemon
    monkeypatch.setattr(taker, 'auth_counterparty', lambda *args: True)
    return taker


def init_coinjoin(taker, makers, orderbook, cj_amount):
    init_data = taker.initialize(orderbook)
    assert init_data[0], "taker.initialize error"
    active_orders = init_data[4]
    maker_data = {}
    for mid in init_data[4]:
        m = makers[int(mid)]
        # note: '00' is kphex, usually set up by jmdaemon
        response = m.on_auth_received(
            'TAKER', init_data[4][mid], init_data[2][1:],
            init_data[3], init_data[1], '00')
        assert response[0], "maker.on_auth_received error"

        ioauth_data = list(response[1:])
        ioauth_data[0] = list(ioauth_data[0].keys())
        # maker_pk which is set up by jmdaemon
        ioauth_data.append(None)
        maker_data[mid] = ioauth_data

        # this is handled by jmdaemon
        active_orders[mid]['utxos'] = response[1]
        active_orders[mid]['cjaddr'] = ioauth_data[2]
        active_orders[mid]['changeaddr'] = ioauth_data[3]
        active_orders[mid]['offer'] = m.offerlist[0]
        active_orders[mid]['amount'] = cj_amount
    return active_orders, maker_data


def do_tx_signing(taker, makers, active_orders, txdata):
    taker_final_result = 'not called'
    maker_signatures = {}  # left here for easier debugging
    for mid in txdata[1]:
        m = makers[int(mid)]
        result = m.on_tx_received('TAKER', txdata[2], active_orders[mid])
        assert result[0], "maker.on_tx_received error"
        maker_signatures[mid] = result[1]
        for sig in result[1]:
            taker_final_result = taker.on_sig(mid, sig)

    assert taker_final_result != 'not called'
    return taker_final_result


@pytest.mark.parametrize('wallet_cls', (LegacyWallet, SegwitLegacyWallet))
def test_simple_coinjoin(monkeypatch, tmpdir, setup_cj, wallet_cls):
    def raise_exit(i):
        raise Exception("sys.exit called")
    monkeypatch.setattr(sys, 'exit', raise_exit)
    set_commitment_file(str(tmpdir.join('commitments.json')))

    MAKER_NUM = 3
    wallets = make_wallets_to_list(make_wallets(
        MAKER_NUM + 1, wallet_structures=[[4, 0, 0, 0, 0]] * (MAKER_NUM + 1),
        mean_amt=1, wallet_cls=wallet_cls))

    jm_single().bc_interface.tickchain()
    sync_wallets(wallets)

    makers = [YieldGeneratorBasic(
        wallets[i],
        [0, 2000, 0, 'swabsoffer', 10**7]) for i in range(MAKER_NUM)]

    orderbook = create_orderbook(makers)
    assert len(orderbook) == MAKER_NUM

    cj_amount = int(1.1 * 10**8)
    # mixdepth, amount, counterparties, dest_addr, waittime
    schedule = [(0, cj_amount, MAKER_NUM, 'INTERNAL', 0)]
    taker = create_taker(wallets[-1], schedule, monkeypatch)

    active_orders, maker_data = init_coinjoin(taker, makers,
                                              orderbook, cj_amount)

    txdata = taker.receive_utxos(maker_data)
    assert txdata[0], "taker.receive_utxos error"

    taker_final_result = do_tx_signing(taker, makers, active_orders, txdata)
    assert taker_final_result is not False
    assert taker.on_finished_callback.status is not False


def test_coinjoin_mixdepth_wrap_taker(monkeypatch, tmpdir, setup_cj):
    def raise_exit(i):
        raise Exception("sys.exit called")
    monkeypatch.setattr(sys, 'exit', raise_exit)
    set_commitment_file(str(tmpdir.join('commitments.json')))

    MAKER_NUM = 3
    wallets = make_wallets_to_list(make_wallets(
        MAKER_NUM + 1,
        wallet_structures=[[4, 0, 0, 0, 0]] * MAKER_NUM + [[0, 0, 0, 0, 3]],
        mean_amt=1))

    for w in wallets:
        assert w.max_mixdepth == 4

    jm_single().bc_interface.tickchain()
    jm_single().bc_interface.tickchain()
    sync_wallets(wallets)

    cj_fee = 2000
    makers = [YieldGeneratorBasic(
        wallets[i],
        [0, cj_fee, 0, 'swabsoffer', 10**7]) for i in range(MAKER_NUM)]

    orderbook = create_orderbook(makers)
    assert len(orderbook) == MAKER_NUM

    cj_amount = int(1.1 * 10**8)
    # mixdepth, amount, counterparties, dest_addr, waittime
    schedule = [(4, cj_amount, MAKER_NUM, 'INTERNAL', 0)]
    taker = create_taker(wallets[-1], schedule, monkeypatch)

    active_orders, maker_data = init_coinjoin(taker, makers,
                                              orderbook, cj_amount)

    txdata = taker.receive_utxos(maker_data)
    assert txdata[0], "taker.receive_utxos error"

    taker_final_result = do_tx_signing(taker, makers, active_orders, txdata)
    assert taker_final_result is not False

    tx = btc.deserialize(txdata[2])
    binarize_tx(tx)

    w = wallets[-1]
    w.remove_old_utxos_(tx)
    w.add_new_utxos_(tx, b'\x00' * 32)  # fake txid

    balances = w.get_balance_by_mixdepth()
    assert balances[0] == cj_amount
    # <= because of tx fee
    assert balances[4] <= 3 * 10**8 - cj_amount - (cj_fee * MAKER_NUM)


def test_coinjoin_mixdepth_wrap_maker(monkeypatch, tmpdir, setup_cj):
    def raise_exit(i):
        raise Exception("sys.exit called")
    monkeypatch.setattr(sys, 'exit', raise_exit)
    set_commitment_file(str(tmpdir.join('commitments.json')))

    MAKER_NUM = 2
    wallets = make_wallets_to_list(make_wallets(
        MAKER_NUM + 1,
        wallet_structures=[[0, 0, 0, 0, 4]] * MAKER_NUM + [[3, 0, 0, 0, 0]],
        mean_amt=1))

    for w in wallets:
        assert w.max_mixdepth == 4

    jm_single().bc_interface.tickchain()
    jm_single().bc_interface.tickchain()
    sync_wallets(wallets)

    cj_fee = 2000
    makers = [YieldGeneratorBasic(
        wallets[i],
        [0, cj_fee, 0, 'swabsoffer', 10**7]) for i in range(MAKER_NUM)]

    orderbook = create_orderbook(makers)
    assert len(orderbook) == MAKER_NUM

    cj_amount = int(1.1 * 10**8)
    # mixdepth, amount, counterparties, dest_addr, waittime
    schedule = [(0, cj_amount, MAKER_NUM, 'INTERNAL', 0)]
    taker = create_taker(wallets[-1], schedule, monkeypatch)

    active_orders, maker_data = init_coinjoin(taker, makers,
                                              orderbook, cj_amount)

    txdata = taker.receive_utxos(maker_data)
    assert txdata[0], "taker.receive_utxos error"

    taker_final_result = do_tx_signing(taker, makers, active_orders, txdata)
    assert taker_final_result is not False

    tx = btc.deserialize(txdata[2])
    binarize_tx(tx)

    for i in range(MAKER_NUM):
        w = wallets[i]
        w.remove_old_utxos_(tx)
        w.add_new_utxos_(tx, b'\x00' * 32)  # fake txid

        balances = w.get_balance_by_mixdepth()
        assert balances[0] == cj_amount
        assert balances[4] == 4 * 10**8 - cj_amount + cj_fee


@pytest.mark.parametrize('wallet_cls,wallet_cls_sec', (
    (SegwitLegacyWallet, LegacyWallet),
    (LegacyWallet, SegwitLegacyWallet)
))
def test_coinjoin_mixed_maker_addresses(monkeypatch, tmpdir, setup_cj,
                                        wallet_cls, wallet_cls_sec):
    set_commitment_file(str(tmpdir.join('commitments.json')))

    MAKER_NUM = 2
    wallets = make_wallets_to_list(make_wallets(
        MAKER_NUM + 1,
        wallet_structures=[[1, 0, 0, 0, 0]] * MAKER_NUM + [[3, 0, 0, 0, 0]],
        mean_amt=1, wallet_cls=wallet_cls))
    wallets_sec = make_wallets_to_list(make_wallets(
        MAKER_NUM,
        wallet_structures=[[1, 0, 0, 0, 0]] * MAKER_NUM,
        mean_amt=1, wallet_cls=wallet_cls_sec))

    for i in range(MAKER_NUM):
        wif = wallets_sec[i].get_wif(0, False, 0)
        wallets[i].import_private_key(0, wif, key_type=wallets_sec[i].TYPE)

    jm_single().bc_interface.tickchain()
    jm_single().bc_interface.tickchain()
    sync_wallets(wallets)

    makers = [YieldGeneratorBasic(
        wallets[i],
        [0, 2000, 0, 'swabsoffer', 10**7]) for i in range(MAKER_NUM)]

    orderbook = create_orderbook(makers)

    cj_amount = int(1.1 * 10**8)
    # mixdepth, amount, counterparties, dest_addr, waittime
    schedule = [(0, cj_amount, MAKER_NUM, 'INTERNAL', 0)]
    taker = create_taker(wallets[-1], schedule, monkeypatch)

    active_orders, maker_data = init_coinjoin(taker, makers,
                                              orderbook, cj_amount)

    txdata = taker.receive_utxos(maker_data)
    assert txdata[0], "taker.receive_utxos error"

    taker_final_result = do_tx_signing(taker, makers, active_orders, txdata)
    assert taker_final_result is not False
    assert taker.on_finished_callback.status is not False


@pytest.fixture(scope='module')
def setup_cj():
    load_program_config()
    jm_single().config.set('POLICY', 'tx_broadcast', 'self')
    jm_single().bc_interface.tick_forward_chain_interval = 5
    jm_single().bc_interface.simulate_blocks()
    yield None
    # teardown
    for dc in reactor.getDelayedCalls():
        dc.cancel()
