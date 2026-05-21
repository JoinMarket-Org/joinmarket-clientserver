'''test configure module.'''

import copy
from configparser import ConfigParser

import pytest

from jmclient import jm_single, load_test_config
from jmclient.configure import get_blockchain_interface_instance, override

pytestmark = pytest.mark.usefixtures("setup_regtest_bitcoind")


def test_attribute_dict():
    from jmclient.configure import AttributeDict
    ad = AttributeDict(foo=1, bar=2, baz={"x":3, "y":4})
    assert ad.foo == 1
    assert ad.bar == 2
    assert ad.baz.x == 3
    assert ad["foo"] == 1


def test_load_config(tmpdir):
    load_test_config(bs="regtest")
    jm_single().config_location = "joinmarket.cfg"
    with pytest.raises(SystemExit):
        load_test_config(config_path=str(tmpdir), bs="regtest")
    jm_single().config_location = "joinmarket.cfg"
    load_test_config()
    ref = copy.deepcopy(jm_single().config)
    assert override(jm_single().config) == ref


def test_blockchain_sources():
    load_test_config()
    for src in ["dummy"]:
        jm_single().config.set("BLOCKCHAIN", "blockchain_source", src)
        if src == "dummy":
            with pytest.raises(ValueError) as e_info:
                get_blockchain_interface_instance(jm_single().config)
        else:
            get_blockchain_interface_instance(jm_single().config)
    load_test_config()


@pytest.fixture
def overrides(monkeypatch):
    overrides = {
        "JM_BLOCKCHAIN_BLOCKCHAIN_SOURCE": "no-blockchain",
        "JM_POLICY_TX_FEES": "12345678",
        "JM_MESSAGING_ONION_TYPE": "lorem-ipsum",
    }
    for key, value in overrides.items():
        monkeypatch.setenv(key, value)
    return overrides


def test_override(overrides):
    config = ConfigParser()
    override(config)
    assert (
        config.get("BLOCKCHAIN", "blockchain_source")
        == overrides["JM_BLOCKCHAIN_BLOCKCHAIN_SOURCE"]
    )
    assert config.get("POLICY", "tx_fees") == overrides["JM_POLICY_TX_FEES"]
    assert config.get("MESSAGING:onion", "type") == overrides["JM_MESSAGING_ONION_TYPE"]


def test_load_program_config_overrides(overrides):
    load_test_config()
    assert jm_single().config.get("POLICY", "tx_fees") == overrides["JM_POLICY_TX_FEES"]
    assert jm_single().config.get("MESSAGING:onion", "socks5_port") == "9050"
