#! /usr/bin/env python
from __future__ import absolute_import
'''Test bitcoin module data handling'''

import jmbitcoin as btc
import pytest
import binascii
import hashlib

#used in p2sh addresses
def test_hash160():
    assert '0e3397b4abc7a382b3ea2365883c3c7ca5f07600' == \
           btc.hash160('The quick brown fox jumps over the lazy dog')

def test_bad_code_string():
    for i in [1,9,257,-3,"256"]:
        with pytest.raises(ValueError) as e_info:
            btc.get_code_string(i)

@pytest.mark.parametrize(
    "st, frm, to, minlen, res",
    [
        ("0101aa", 16, 16, 12, "0000000101aa"),
    ])
def test_changebase(st, frm, to, minlen, res):
    assert btc.changebase(st, frm, to, minlen) == res


#Tests of compactsize encoding, see:
#https://bitcoin.org/en/developer-reference#compactsize-unsigned-integers
#note that little endian is used.
@pytest.mark.parametrize(
    "num, compactsize",
    [
        (252, "fc"),
        (253, "fdfd00"),
        (254, "fdfe00"),
        (515, "fd0302"),
        (65535, "fdffff"),
        (65536, "fe00000100"),
        (65537, "fe01000100"),
        (4294967295, "feffffffff"),
        (4294967296, "ff0000000001000000"),
        
    ])
def test_compact_size(num, compactsize):
    assert btc.num_to_var_int(num) == binascii.unhexlify(compactsize)
