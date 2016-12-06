#! /usr/bin/env python
from __future__ import absolute_import
'''test of the add_tx_notify() timeouts and related callbacks'''

import sys

import time
from commontest import make_wallets
import subprocess
import jmbitcoin as bitcoin
import pytest
from jmclient import (load_program_config, jm_single, get_log, Wallet, sync_wallet)

log = get_log()

unconfirm_called = [False]
confirm_called = [False]
timeout_unconfirm_called = [False]
timeout_confirm_called = [False]

def unconfirm_callback(txd, txid):
    unconfirm_called[0] = True
    log.debug('unconfirm callback()')

def confirm_callback(txd, txid, confirmations):
    confirm_called[0] = True
    log.debug('confirm callback()')

def timeout_callback(confirmed):
    if not confirmed:
        timeout_unconfirm_called[0] = True
        log.debug('timeout unconfirm callback()')
    else:
        timeout_confirm_called[0] = True
        log.debug('timeout confirm callback()')

def test_notify_handler_errors(setup_tx_notify):
    #TODO this has hardcoded 62612 which is from regtest_joinmarket.cfg
    #default testing config
    txhex = make_tx_add_notify()
    with pytest.raises(subprocess.CalledProcessError) as e_info:
        res = subprocess.check_output(["curl", "-I", "--connect-timeout", "1",
        "http://localhost:62612/walletnotify?abcd"])
    with pytest.raises(subprocess.CalledProcessError) as e_info:
        res = subprocess.check_output(["curl", "-I", "--connect-timeout", "1",
                                "http://localhost:62612/walletnotify?xxXX"])        
    #unrecognised calls are returned an error message, not a curl failure
    res = subprocess.check_output(["curl", "-I", "--connect-timeout", "1",
            "http://localhost:62612/dummycommand"])
    #alertnotifys with an alert message should be accepted (todo, deprecate)
    res = subprocess.check_output(["curl", "-I", "--connect-timeout", "1",
                "http://localhost:62612/alertnotify?dummyalertmessage"])    

def test_no_timeout(setup_tx_notify):
    txhex = make_tx_add_notify()
    jm_single().bc_interface.pushtx(txhex)
    time.sleep(6)
    assert unconfirm_called[0]
    assert confirm_called[0]
    assert not timeout_unconfirm_called[0]
    assert not timeout_confirm_called[0]
    return True

def test_unconfirm_timeout(setup_tx_notify):
    txhex = make_tx_add_notify()
    #dont pushtx
    time.sleep(6)
    assert not unconfirm_called[0]
    assert not confirm_called[0]
    assert timeout_unconfirm_called[0]
    assert not timeout_confirm_called[0]
    return True

def test_confirm_timeout(setup_tx_notify):
    txhex = make_tx_add_notify()
    jm_single().bc_interface.tick_forward_chain_interval = -1
    jm_single().bc_interface.pushtx(txhex)
    time.sleep(10)
    jm_single().bc_interface.tick_forward_chain_interval = 2
    assert unconfirm_called[0]
    assert not confirm_called[0]
    assert not timeout_unconfirm_called[0]
    assert timeout_confirm_called[0]
    return True

def make_tx_add_notify():
    wallet_dict = make_wallets(1, [[1, 0, 0, 0, 0]], mean_amt=4, sdev_amt=0)[0]
    amount = 250000000
    txfee = 10000
    wallet = wallet_dict['wallet']
    sync_wallet(wallet)
    inputs = wallet.select_utxos(0, amount)
    ins = inputs.keys()
    input_value = sum([i['value'] for i in inputs.values()])
    output_addr = wallet.get_new_addr(1, 0)
    change_addr = wallet.get_new_addr(0, 1)
    outs = [{'value': amount, 'address': output_addr},
            {'value': input_value - amount - txfee, 'address': change_addr}]
    tx = bitcoin.mktx(ins, outs)
    de_tx = bitcoin.deserialize(tx)
    for index, ins in enumerate(de_tx['ins']):
        utxo = ins['outpoint']['hash'] + ':' + str(ins['outpoint']['index'])
        addr = inputs[utxo]['address']
        priv = wallet.get_key_from_addr(addr)
        tx = bitcoin.sign(tx, index, priv)

    unconfirm_called[0] = confirm_called[0] = False
    timeout_unconfirm_called[0] = timeout_confirm_called[0] = False
    jm_single().bc_interface.add_tx_notify(
        bitcoin.deserialize(tx), unconfirm_callback,
        confirm_callback, output_addr, timeout_callback)
    return tx

@pytest.fixture(scope="module")
def setup_tx_notify():
    load_program_config()
    jm_single().config.set('TIMEOUT', 'unconfirm_timeout_sec', '3')
    jm_single().config.set('TIMEOUT', 'confirm_timeout_hours', str(6.0 / 60 / 60))
    jm_single().bc_interface.tick_forward_chain_interval = 2

