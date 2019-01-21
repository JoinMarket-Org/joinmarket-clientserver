from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

from jmclient.boltzmann import Boltzmann

from test_storage import MockStorage
import pytest

from jmclient import load_program_config
import jmclient
from commontest import DummyBlockchainInterface


def test_boltzmann_persist():
    storage = MockStorage(None, 'wallet.jmdat', None, create=True)
    Boltzmann.initialize(storage)
    bz = Boltzmann(storage)

    script0 = b'\x00' * 7
    script1 = b'\x01' * 7
    script2 = b'\x02' * 7
    rate0 = 3
    rate1 = 5 ** 13

    bz.set_rate(script0, rate0)
    bz.set_rate(script1, rate1)

    bz.save()
    del bz

    bz = Boltzmann(storage)

    assert bz.get_rate(script0) == rate0
    assert bz.has_script(script0)
    assert bz.get_rate(script1) == rate1
    assert bz.has_script(script1)
    assert bz.get_rate(script2) == 1
    assert not bz.has_script(script2)

    bz.remove_script(script1)

    bz.save()
    del bz

    bz = Boltzmann(storage)

    assert bz.has_script(script0)
    assert not bz.has_script(script1)
    assert not bz.has_script(script2)

    bz.reset()
    bz.save()
    del bz

    bz = Boltzmann(storage)

    assert not bz.has_script(script0)


@pytest.mark.parametrize("ins_scripts, outs, cjscript, changescript, amount", [
    (['00'], [{'script': '00', 'value': 123}], '00', None, 123),
])
def test_boltzmann(setup_env_nodeps, ins_scripts, outs, cjscript, changescript, amount):
    storage = MockStorage(None, 'wallet.jmdat', None, create=True)
    Boltzmann.initialize(storage)
    bz = Boltzmann(storage)

    bz.boltzmann(ins_scripts, outs, cjscript, changescript, amount)


@pytest.fixture
def setup_env_nodeps(monkeypatch):
    monkeypatch.setattr(jmclient.configure, 'get_blockchain_interface_instance',
                        lambda x: DummyBlockchainInterface())
    load_program_config()
