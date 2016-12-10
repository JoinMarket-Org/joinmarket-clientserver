from jmclient.configure import validate_address, load_program_config
from jmclient import jm_single
import json
import pytest
import os
testdir = os.path.dirname(os.path.realpath(__file__))

def test_non_addresses(setup_addresses):
    #could flesh this out with other examples
    res, msg = validate_address(2)
    assert res == False, "Incorrectly accepted number"

def test_b58_invalid_addresses(setup_addresses):
    #none of these are valid as any kind of key or address
    with open(os.path.join(testdir,"base58_keys_invalid.json"), "r") as f:
        json_data = f.read()
    invalid_key_list = json.loads(json_data)
    for k in invalid_key_list:
        bad_key = k[0]
        res, message = validate_address(bad_key)
        assert res == False, "Incorrectly validated address: " + bad_key + " with message: " + message


def test_b58_valid_addresses():
    with open(os.path.join(testdir,"base58_keys_valid.json"), "r") as f:
        json_data = f.read()
    valid_keys_list = json.loads(json_data)
    for a in valid_keys_list:
        addr, pubkey, prop_dict = a
        if not prop_dict["isPrivkey"]:
            if prop_dict["isTestnet"]:
                jm_single().config.set("BLOCKCHAIN", "network", "testnet")
            else:
                jm_single().config.set("BLOCKCHAIN", "network", "mainnet")
            #if using py.test -s ; sanity check to see what's actually being tested
            print 'testing this address: ' + addr
            res, message = validate_address(addr)
            assert res == True, "Incorrectly failed to validate address: " + addr + " with message: " + message


@pytest.fixture(scope="module")
def setup_addresses():
    load_program_config()
