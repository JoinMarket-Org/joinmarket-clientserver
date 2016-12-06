#! /usr/bin/env python
from __future__ import absolute_import
'''test schedule module.'''

import pytest
from jmclient import (load_program_config, jm_single, get_irc_mchannels,
                      BTC_P2PK_VBYTE, BTC_P2SH_VBYTE, check_utxo_blacklist,
                      validate_address)
from jmclient.configure import (get_config_irc_channel, get_p2sh_vbyte,
                                get_p2pk_vbyte, get_blockchain_interface_instance)
import jmbitcoin as bitcoin
import copy
import os


def test_config_get_irc_channel():
    load_program_config()
    channel = "dummy"
    assert get_config_irc_channel(channel) == "#dummy-test"
    jm_single().config.set("BLOCKCHAIN", "network", "mainnet")
    assert get_config_irc_channel(channel) == "#dummy"
    get_irc_mchannels()
    load_program_config()

def test_net_byte():
    load_program_config()
    assert get_p2pk_vbyte() == 0x6f
    assert get_p2sh_vbyte() == 196

def test_check_blacklist():
    load_program_config()
    jm_single().nickname = "fortestnick"
    fn = "blacklist" + "_" + jm_single().nickname
    if os.path.exists(fn):
        os.remove(fn)
    assert check_utxo_blacklist("aa"*32, False)
    with open(fn, "wb") as f:
        f.write("aa"*32 + "\n")
    assert not check_utxo_blacklist("aa"*32, False)
    assert check_utxo_blacklist("bb"*32, False)
    assert check_utxo_blacklist("bb"*32, True)
    assert not check_utxo_blacklist("bb"*32, False)
    assert not check_utxo_blacklist("bb"*32, True)
    
def test_blockchain_sources():
    load_program_config()
    for src in ["blockr", "electrum", "dummy"]:
        jm_single().config.set("BLOCKCHAIN", "blockchain_source", src)
        if src=="electrum":
            jm_single().config.set("BLOCKCHAIN", "network", "mainnet")
        if src == "dummy":
            with pytest.raises(ValueError) as e_info:
                get_blockchain_interface_instance(jm_single().config)
        else:
            get_blockchain_interface_instance(jm_single().config)
    load_program_config()

        

        
    