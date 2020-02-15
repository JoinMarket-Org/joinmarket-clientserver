'''test configure module.'''

import pytest
import struct
from jmclient import load_test_config, jm_single, get_irc_mchannels
from jmclient.configure import (get_config_irc_channel, get_p2sh_vbyte,
                                get_p2pk_vbyte, get_blockchain_interface_instance)


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


def test_config_get_irc_channel():
    load_test_config()
    channel = "dummy"
    assert get_config_irc_channel(channel) == "#dummy-test"
    jm_single().config.set("BLOCKCHAIN", "network", "mainnet")
    assert get_config_irc_channel(channel) == "#dummy"
    get_irc_mchannels()
    load_test_config()


def test_net_byte():
    load_test_config()
    assert struct.unpack('B', get_p2pk_vbyte())[0] == 0x6f
    assert struct.unpack('B', get_p2sh_vbyte())[0] == 196


def test_blockchain_sources():
    load_test_config()
    for src in ["electrum", "dummy"]:
        jm_single().config.set("BLOCKCHAIN", "blockchain_source", src)
        if src=="electrum":
            jm_single().config.set("BLOCKCHAIN", "network", "mainnet")
        if src == "dummy":
            with pytest.raises(ValueError) as e_info:
                get_blockchain_interface_instance(jm_single().config)
        else:
            get_blockchain_interface_instance(jm_single().config)
    load_test_config()
