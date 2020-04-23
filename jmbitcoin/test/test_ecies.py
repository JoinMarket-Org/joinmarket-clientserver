#! /usr/bin/env python
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401
'''Tests ECIES implementation as defined in BIP-SNICKER
(and will be updated if that is).'''

from jmbase import hextobin
import jmbitcoin as btc
import base64
import os
import json
testdir = os.path.dirname(os.path.realpath(__file__))

def test_ecies():
    """Using private key test vectors from Bitcoin Core.
    1. Import a set of private keys from the json file.
    2. Calculate the corresponding public keys.
    3. Do ECDH on the cartesian product (x, Y), with x private
    and Y public keys, for all combinations.
    4. Compare the result from CoinCurve with the manual
    multiplication xY following by hash (sha256). Note that
    sha256(xY) is the default hashing function used for ECDH
    in libsecp256k1.

    Since there are about 20 private keys in the json file, this
    creates around 400 test cases (note xX is still valid).
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
