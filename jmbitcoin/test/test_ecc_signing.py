#! /usr/bin/env python
from __future__ import absolute_import
'''Test ECDSA signing and other key operations, including legacy message
signature conversion.'''

import jmbitcoin as btc
import binascii
import json
import pytest
import os
testdir = os.path.dirname(os.path.realpath(__file__))
vectors = None

def test_valid_sigs(setup_ecc):
    for v in vectors['vectors']:
        msg = v['msg']
        sig = v['sig']
        priv = v['privkey']
        assert sig == btc.ecdsa_raw_sign(msg, priv, True, rawmsg=True)+'01'
        #check that the signature verifies against the key(pair)
        pubkey = btc.privtopub(priv)
        assert btc.ecdsa_raw_verify(msg, pubkey, sig[:-2], True, rawmsg=True)
        #check that it fails to verify against corrupted signatures
        for i in [0,1,2,4,7,25,55]:
            #corrupt one byte
            binsig = binascii.unhexlify(sig)
            checksig = binascii.hexlify(binsig[:i] + chr(
                (ord(binsig[i])+1) %256) + binsig[i+1:-1])
            
            #this kind of corruption will sometimes lead to an assert
            #failure (if the DER format is corrupted) and sometimes lead
            #to a signature verification failure.
            try:
                res = btc.ecdsa_raw_verify(msg, pubkey, checksig, True, rawmsg=True)
            except:
                continue
            assert res==False

@pytest.fixture(scope='module')
def setup_ecc():
    global vectors
    with open(os.path.join(testdir, "ecc_sigs_rfc6979_valid.json"), "r") as f:
        json_data = f.read()
    vectors = json.loads(json_data)    