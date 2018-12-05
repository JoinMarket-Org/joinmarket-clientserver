from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401

from jmclient.wallet import UTXOManager
from test_storage import MockStorage
import pytest

from jmclient import load_program_config
import jmclient
from commontest import DummyBlockchainInterface


def select(unspent, value):
    return unspent


def test_utxomanager_persist(setup_env_nodeps):
    storage = MockStorage(None, 'wallet.jmdat', None, create=True)
    UTXOManager.initialize(storage)
    um = UTXOManager(storage, select)

    txid = b'\x00' * UTXOManager.TXID_LEN
    index = 0
    path = (0,)
    mixdepth = 0
    value = 500

    um.add_utxo(txid, index, path, value, mixdepth)
    um.add_utxo(txid, index+1, path, value, mixdepth+1)

    um.save()
    del um

    um = UTXOManager(storage, select)

    assert um.have_utxo(txid, index) == mixdepth
    assert um.have_utxo(txid, index+1) == mixdepth + 1
    assert um.have_utxo(txid, index+2) == False

    utxos = um.get_utxos_by_mixdepth()
    assert len(utxos[mixdepth]) == 1
    assert len(utxos[mixdepth+1]) == 1
    assert len(utxos[mixdepth+2]) == 0

    balances = um.get_balance_by_mixdepth()
    assert balances[mixdepth] == value
    assert balances[mixdepth+1] == value

    um.remove_utxo(txid, index, mixdepth)
    assert um.have_utxo(txid, index) == False

    um.save()
    del um

    um = UTXOManager(storage, select)

    assert um.have_utxo(txid, index) == False
    assert um.have_utxo(txid, index+1) == mixdepth + 1

    utxos = um.get_utxos_by_mixdepth()
    assert len(utxos[mixdepth]) == 0
    assert len(utxos[mixdepth+1]) == 1

    balances = um.get_balance_by_mixdepth()
    assert balances[mixdepth] == 0
    assert balances[mixdepth+1] == value
    assert balances[mixdepth+2] == 0


def test_utxomanager_select(setup_env_nodeps):
    storage = MockStorage(None, 'wallet.jmdat', None, create=True)
    UTXOManager.initialize(storage)
    um = UTXOManager(storage, select)

    txid = b'\x00' * UTXOManager.TXID_LEN
    index = 0
    path = (0,)
    mixdepth = 0
    value = 500

    um.add_utxo(txid, index, path, value, mixdepth)

    assert len(um.select_utxos(mixdepth, value)) is 1
    assert len(um.select_utxos(mixdepth+1, value)) is 0

    um.add_utxo(txid, index+1, path, value, mixdepth)
    assert len(um.select_utxos(mixdepth, value)) is 2


@pytest.fixture
def setup_env_nodeps(monkeypatch):
    monkeypatch.setattr(jmclient.configure, 'get_blockchain_interface_instance',
                        lambda x: DummyBlockchainInterface())
    load_program_config()
