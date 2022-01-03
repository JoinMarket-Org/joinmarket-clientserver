#! /usr/bin/env python
'''Tests ECIES implementation as defined in BIP-SNICKER
(and will be updated if that is).'''

from jmbase import hextobin
import jmbitcoin as btc
import base64
import os
import json
testdir = os.path.dirname(os.path.realpath(__file__))

def test_ecies():
    """Tests encryption and decryption of random messages using
    the ECIES module.
    TODO these tests are very minimal.
    """
    with open(os.path.join(testdir,"base58_keys_valid.json"), "r") as f:
        json_data = f.read()
        valid_keys_list = json.loads(json_data)
        print("got valid keys list")
        extracted_privkeys = []
        for a in valid_keys_list:
            key, hex_key, prop_dict = a
            if prop_dict["isPrivkey"]:
                c, k = btc.read_privkey(hextobin(hex_key))

                extracted_privkeys.append(k)
    extracted_pubkeys = [btc.privkey_to_pubkey(x) for x in extracted_privkeys]
    for (priv, pub) in zip(extracted_privkeys, extracted_pubkeys):
        test_message = base64.b64encode(os.urandom(15)*20)
        assert btc.ecies_decrypt(priv, btc.ecies_encrypt(test_message, pub)) == test_message
