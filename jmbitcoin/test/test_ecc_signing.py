#! /usr/bin/env python
'''Test ECDSA signing and other key operations, including legacy message
signature conversion.'''

import jmbitcoin as btc
import binascii
from jmbase import bintohex
import json
import pytest
import os
testdir = os.path.dirname(os.path.realpath(__file__))
vectors = None

def test_valid_sigs(setup_ecc):
    for v in vectors['vectors']:
        msg, sig, priv = (binascii.unhexlify(
            v[a]) for a in ["msg", "sig", "privkey"])
        res = btc.ecdsa_raw_sign(msg, priv, rawmsg=True)+ b'\x01'
        if not sig == res:
            print("failed on sig {} from msg {} with priv {}".format(bintohex(sig), bintohex(msg), bintohex(priv)))
            print("we got instead: {}".format(bintohex(res)))
            assert False
        # check that the signature verifies against the key(pair)
        pubkey = btc.privkey_to_pubkey(priv)
        assert btc.ecdsa_raw_verify(msg, pubkey, sig[:-1], rawmsg=True)
        # check that it fails to verify against corrupted signatures
        for i in [0,1,2,4,7,25,55]:
            # corrupt one byte
            checksig = sig[:i] + chr(
                (ord(sig[i:i+1])+1) %256).encode() + sig[i+1:-1]
            
            # this kind of corruption will sometimes lead to an assert
            # failure (if the DER format is corrupted) and sometimes lead
            # to a signature verification failure.
            try:
                res = btc.ecdsa_raw_verify(msg, pubkey, checksig, rawmsg=True)
            except:
                continue
            assert res==False


@pytest.fixture(scope='module')
def setup_ecc():
    global vectors
    with open(os.path.join(testdir, "ecc_sigs_rfc6979_valid.json"), "r") as f:
        json_data = f.read()
    vectors = json.loads(json_data)    