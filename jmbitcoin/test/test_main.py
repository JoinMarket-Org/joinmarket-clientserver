#! /usr/bin/env python
from __future__ import absolute_import
'''Testing mostly exceptional cases in secp256k1_main.
   Some of these may represent code that should be removed, TODO.'''

import jmbitcoin as btc
import binascii
import json
import pytest
import os
testdir = os.path.dirname(os.path.realpath(__file__))

def test_hex2b58check():
    assert btc.hex_to_b58check("aa"*32) == "12JAT9y2EcnV6DPUGikLJYjWwk5UmUEFXRiQVmTbfSLbL3njFzp"

def test_bindblsha():
    assert btc.bin_dbl_sha256("abc") == binascii.unhexlify(
        "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358")

def test_lpad():
    assert btc.lpad("aaaa", "b", 5) == "baaaa"
    assert btc.lpad("aaaa", "b", 4) == "aaaa"
    assert btc.lpad("aaaa", "b", 3) == "aaaa"
    
def test_safe_from_hex():
    assert btc.safe_from_hex('ff0100') == b'\xff\x01\x00'

def test_hash2int():
    assert btc.hash_to_int("aa"*32) == \
    77194726158210796949047323339125271902179989777093709359638389338608753093290

@btc.hexbin
def dummyforwrap(a, b, c, d="foo", e="bar"):
    newa = a+b"\x01"
    x, y = b
    newb = [x+b"\x02", y+b"\x03"]
    if d == "foo":
        return newb[1]
    else:
        return newb[0]

def test_hexbin():
    assert dummyforwrap("aa", ["bb", "cc"], True) == b"cc03"
    assert dummyforwrap("aa", ["bb", "cc"], True, d="baz") == b"bb02"
    assert dummyforwrap(b"\xaa", [b"\xbb", b"\xcc"], False) == b"\xcc\x03"

def test_add_privkeys():
    with pytest.raises(Exception) as e_info:
        btc.add_privkeys("aa"*32, "bb"*32+"01", True)

def test_ecdsa_raw_sign():
    msg = "aa"*31
    with pytest.raises(Exception) as e_info:
        btc.ecdsa_raw_sign(msg, None, None, rawmsg=True)
    assert e_info.match("Invalid hash input")
    #build non-raw priv object as input
    privraw = "aa"*32
    msghash = b"\xbb"*32
    sig = binascii.hexlify(btc.ecdsa_raw_sign(msghash, privraw, False, rawpriv=False, rawmsg=True))
    assert sig == b"3045022100b81960b4969b423199dea555f562a66b7f49dea5836a0168361f1a5f8a3c8298022003eea7d7ee4462e3e9d6d59220f950564caeb77f7b1cdb42af3c83b013ff3b2f"


    