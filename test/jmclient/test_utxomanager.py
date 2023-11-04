
from jmclient.wallet import UTXOManager
from test_storage import MockStorage
import pytest

from jmclient import load_test_config
import jmclient
from commontest import DummyBlockchainInterface


def select(unspent, value):
    return unspent


def test_utxomanager_persist(setup_env_nodeps):
    """ Tests that the utxo manager's data is correctly
    persisted and can be recreated from storage.
    This persistence is currently only used for metadata
    (specifically, disabling coins for coin control).
    """

    storage = MockStorage(None, 'wallet.jmdat', None, create=True)
    UTXOManager.initialize(storage)
    um = UTXOManager(storage, select)

    txid = b'\x00' * UTXOManager.TXID_LEN
    index = 0
    path = (0,)
    mixdepth = 0
    value = 500

    um.add_utxo(txid, index, path, value, mixdepth, 1)
    um.add_utxo(txid, index+1, path, value, mixdepth+1, 2)
    # the third utxo will be disabled and we'll check if
    # the disablement persists in the storage across UM instances
    um.add_utxo(txid, index+2, path, value, mixdepth+1, 3)
    um.disable_utxo(txid, index+2)
    um.save()

    # Remove and recreate the UM from the same storage.

    del um

    um = UTXOManager(storage, select)

    assert um.have_utxo(txid, index) == mixdepth
    assert um.have_utxo(txid, index+1) == mixdepth + 1
    # The third should not be registered as present given flag:
    assert um.have_utxo(txid, index+2, include_disabled=False) == False
    # check is_disabled works:
    assert not um.is_disabled(txid, index)
    assert not um.is_disabled(txid, index+1)
    assert um.is_disabled(txid, index+2)
    # check re-enabling works
    um.enable_utxo(txid, index+2)
    assert not um.is_disabled(txid, index+2)
    um.disable_utxo(txid, index+2)

    assert len(um.get_utxos_at_mixdepth(mixdepth)) == 1
    assert len(um.get_utxos_at_mixdepth(mixdepth+1)) == 2
    assert len(um.get_utxos_at_mixdepth(mixdepth+2)) == 0

    assert um.get_balance_at_mixdepth(mixdepth) == value
    assert um.get_balance_at_mixdepth(mixdepth+1) == value * 2

    um.remove_utxo(txid, index, mixdepth)
    assert um.have_utxo(txid, index) == False
    # check that removing a utxo does not remove the metadata
    um.remove_utxo(txid, index+2, mixdepth+1)
    assert um.is_disabled(txid, index+2)

    um.save()
    del um

    um = UTXOManager(storage, select)

    assert um.have_utxo(txid, index) == False
    assert um.have_utxo(txid, index+1) == mixdepth + 1

    assert len(um.get_utxos_at_mixdepth(mixdepth)) == 0
    assert len(um.get_utxos_at_mixdepth(mixdepth+1)) == 1

    assert um.get_balance_at_mixdepth(mixdepth) == 0
    assert um.get_balance_at_mixdepth(mixdepth+1) == value
    assert um.get_balance_at_mixdepth(mixdepth+2) == 0


def test_utxomanager_select(setup_env_nodeps):
    storage = MockStorage(None, 'wallet.jmdat', None, create=True)
    UTXOManager.initialize(storage)
    um = UTXOManager(storage, select)

    txid = b'\x00' * UTXOManager.TXID_LEN
    index = 0
    path = (0,)
    mixdepth = 0
    value = 500

    um.add_utxo(txid, index, path, value, mixdepth, 100)

    assert len(um.select_utxos(mixdepth, value)) == 1
    assert len(um.select_utxos(mixdepth+1, value)) == 0

    um.add_utxo(txid, index+1, path, value, mixdepth, None)
    assert len(um.select_utxos(mixdepth, value)) == 2

    # ensure that added utxos that are disabled do not
    # get used by the selector
    um.add_utxo(txid, index+2, path, value, mixdepth, 101)
    um.disable_utxo(txid, index+2)
    assert len(um.select_utxos(mixdepth, value)) == 2

    # ensure that unconfirmed coins are not selected if
    # dis-requested:
    assert len(um.select_utxos(mixdepth, value, maxheight=105)) == 1


@pytest.fixture
def setup_env_nodeps(monkeypatch):
    monkeypatch.setattr(jmclient.configure, 'get_blockchain_interface_instance',
                        lambda x: DummyBlockchainInterface())
    load_test_config()
