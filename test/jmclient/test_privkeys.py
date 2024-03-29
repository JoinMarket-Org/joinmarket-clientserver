#! /usr/bin/env python
'''Public and private key validity and formatting tests.'''

import jmbitcoin as btc
from jmbase import hextobin
from jmclient import BTCEngine, jm_single, load_test_config
import json
import pytest
import os

pytestmark = pytest.mark.usefixtures("setup_regtest_bitcoind")

testdir = os.path.dirname(os.path.realpath(__file__))

def test_read_raw_privkeys(setup_keys):
    badkeys = [b'', b'\x07'*31,b'\x07'*34, b'\x07'*33]
    for b in badkeys:
        with pytest.raises(Exception) as e_info:
            c, k = btc.read_privkey(b)
    goodkeys = [(b'\x07'*32, False), (b'\x07'*32 + b'\x01', True)]
    for g in goodkeys:
        c, k = btc.read_privkey(g[0])
        assert c == g[1]

def test_wif_privkeys_invalid(setup_keys):
    #first try to create wif privkey from key of wrong length
    bad_privs = [b'\x01\x02'*17] #some silly private key but > 33 bytes

    #next try to create wif with correct length but wrong compression byte
    bad_privs.append(b'\x07'*32 + b'\x02')
    
    for priv in bad_privs:
        with pytest.raises(Exception) as e_info:
            fake_wif = BTCEngine.privkey_to_wif(priv)

    #Create a wif with wrong length
    bad_wif1 = btc.bin_to_b58check(b'\x01\x02'*34, b'\x80')
    #Create a wif with wrong compression byte
    bad_wif2 = btc.bin_to_b58check(b'\x07'*33, b'\x80')
    for bw in [bad_wif1, bad_wif2]:
        with pytest.raises(Exception) as e_info:
            fake_priv, keytype = BTCEngine.wif_to_privkey(bw)

    #Some invalid b58 from bitcoin repo;
    #none of these are valid as any kind of key or address
    with open(os.path.join(testdir,"base58_keys_invalid.json"), "r") as f:
        json_data = f.read()
    invalid_key_list = json.loads(json_data)
    for k in invalid_key_list:
        bad_key = k[0]
        for netval in ["mainnet", "testnet"]:
            #if using pytest -s ; sanity check to see what's actually being tested
            print('testing this key: ' + bad_key)
            #should throw exception
            with pytest.raises(Exception) as e_info:
                from_wif_key, keytype = BTCEngine.wif_to_privkey(bad_key)
                #in case the b58 check encoding is valid, we should
                #also check if the leading version byte is in the
                #expected set, and throw an error if not.
                if chr(btc.get_version_byte(bad_key)) not in b'\x80\xef':
                    raise Exception("Invalid version byte")

def test_wif_privkeys_valid(setup_keys):
    with open(os.path.join(testdir,"base58_keys_valid.json"), "r") as f:
        json_data = f.read()
    valid_keys_list = json.loads(json_data)
    for a in valid_keys_list:
        key, hex_key, prop_dict = a
        if prop_dict["isPrivkey"]:
            netval = "testnet" if prop_dict["isTestnet"] else "mainnet"
            jm_single().config.set("BLOCKCHAIN", "network", netval)
            print('testing this key: ' + key)
            assert btc.get_version_byte(
                key) in b'\x80\xef', "not valid network byte"
            comp = prop_dict["isCompressed"]
            if not comp:
                # we only handle compressed keys
                continue
            from_wif_key, keytype = BTCEngine.wif_to_privkey(key)
            expected_key = hextobin(hex_key) + b"\x01"
            assert from_wif_key == expected_key, "Incorrect key decoding: " + \
                   str(from_wif_key) + ", should be: " + str(expected_key)
    jm_single().config.set("BLOCKCHAIN", "network", "testnet")

@pytest.fixture(scope='module')
def setup_keys():
    load_test_config()