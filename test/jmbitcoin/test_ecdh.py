#! /usr/bin/env python
'''Tests python-bitcointx binding to libsecp256k1 ecdh module code'''

import hashlib
import jmbitcoin as btc
from jmbase import hextobin
import pytest
import os
import json
testdir = os.path.dirname(os.path.realpath(__file__))

def test_ecdh():
    """Using private key test vectors from Bitcoin Core.
    1. Import a set of private keys from the json file.
    2. Calculate the corresponding public keys.
    3. Do ECDH on the cartesian product (x, Y), with x private
    and Y public keys, for all combinations.
    4. Compare the result from secp256k1_main.ecdh with the manual
    multiplication xY following by hash (sha256). Note that
    sha256(xY) is the default hashing function used for ECDH
    in libsecp256k1.

    Since there are about 20 private keys in the json file, this
    creates around 400 test cases (note xX is still valid).
    """
    with open(os.path.join(testdir,"base58_keys_valid.json"), "r") as f:
        json_data = f.read()
        valid_keys_list = json.loads(json_data)
        extracted_privkeys = []
        for a in valid_keys_list:
            key, hex_key, prop_dict = a
            if prop_dict["isPrivkey"]:
                c, k = btc.read_privkey(hextobin(hex_key))
                extracted_privkeys.append(k + b"\x01")
    extracted_pubkeys = [btc.privkey_to_pubkey(x) for x in extracted_privkeys]
    for p in extracted_privkeys:
        for P in extracted_pubkeys:
            c, k = btc.read_privkey(p)
            shared_secret = btc.ecdh(k + b"\x01", P)
            assert len(shared_secret) == 32
            # try recreating the shared secret manually:
            pre_secret = btc.multiply(k, P)
            derived_secret = hashlib.sha256(pre_secret).digest()
            assert derived_secret == shared_secret

    # test some important failure cases; null key, overflow case
    privkeys_invalid = [b'\x00'*32, hextobin(
        'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')]
    for p in privkeys_invalid:
        with pytest.raises(Exception) as e_info:
            shared_secret = btc.ecdh(p, extracted_pubkeys[0])
    pubkeys_invalid = [b'0xff' + extracted_pubkeys[0][1:], b'0x00'*12]
    for p in extracted_privkeys:
        with pytest.raises(Exception) as e_info:
            shared_secret = btc.ecdh(p, pubkeys_invalid[0])
        with pytest.raises(Exception) as e_info:
            shared_secret = btc.ecdh(p, pubkeys_invalid[1])
