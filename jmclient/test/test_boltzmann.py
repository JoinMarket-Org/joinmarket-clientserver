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

    script0 = '00' * 7
    script1 = '01' * 7
    script2 = '02' * 7
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


@pytest.fixture
def setup_env_nodeps(monkeypatch):
    monkeypatch.setattr(jmclient.configure, 'get_blockchain_interface_instance',
                        lambda x: DummyBlockchainInterface())
    load_program_config()


def set_initial(bz, setup):
    for s, r in setup:
        bz.set_rate(s, r)


def check_result(bz, expected):
    for s, r in expected:
        assert bz.get_rate(s) == r


@pytest.mark.parametrize("ins_scripts, outs, cjscript, changescript, amount, setup, expected", [
    # 1->1
    (['00'], [{'script': '01', 'value': 100}], '01', None, 100, [], [('01', 1)]),
    (['00'], [{'script': '01', 'value': 100}], '01', None, 100, [('00', 2)], [('01', 2)]),
    # 1->2
    (['00'], [{'script': '01', 'value': 100},
              {'script': '02', 'value': 100}], '01', None, 100, [('00', 2)], [('01', 4)]),
    # 1->1 + change
    (['00'], [{'script': '01', 'value': 100},
              {'script': '02', 'value': 10}], '01', '02', 100, [('00', 2)], [('01', 2),
                                                                             ('02', 2)]),
    # 2->1
    (['00',
      '01'], [{'script': '02', 'value': 100}], '02', None, 100, [('00', 5),
                                                                 ('01', 7)], [('02', 5)]),
    # 2->2
    (['00',
      '01'], [{'script': '02', 'value': 100},
              {'script': '03', 'value': 100}], '02', None, 100, [('00', 5),
                                                                 ('01', 7)], [('02', 10)]),
    # 2->3 + change
    (['00',
      '01'], [{'script': '02', 'value': 100},
              {'script': '03', 'value': 10},
              {'script': '04', 'value': 100},
              {'script': '05', 'value': 100},
              {'script': '06', 'value': 110},
              {'script': '07', 'value': 20},
              {'script': '08', 'value': 30}], '02', '03', 100, [('00', 5),
                                                                ('01', 7)], [('02', 15),
                                                                             ('03', 5)]),
])
def test_update(ins_scripts, outs, cjscript, changescript, amount, setup, expected):
    storage = MockStorage(None, 'wallet.jmdat', None, create=True)
    Boltzmann.initialize(storage)
    bz = Boltzmann(storage)
    set_initial(bz, setup)

    bz.update(ins_scripts, outs, cjscript, changescript, amount)

    check_result(bz, expected)
