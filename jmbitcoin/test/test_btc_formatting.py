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
           btc.hash160(btc.from_string_to_bytes('The quick brown fox jumps over the lazy dog'))

def test_bad_code_string():
    for i in [1,9,257,-3,"256"]:
        with pytest.raises(ValueError) as e_info:
            btc.get_code_string(i)

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

@pytest.mark.parametrize("frm, to", [
    (("16001405481b7f1d90c5a167a15b00e8af76eb6984ea59"),
     ["001405481b7f1d90c5a167a15b00e8af76eb6984ea59"]),
    (("483045022100ad0dda327945e581a5effd83d75d76a9f07c3128f4dc6d25a54"
      "e5ad5dd629bd00220487a992959bd540dbc335c655e6485ebfb394129eb48038f"
      "0a2d319782f7cb690121039319452b6abafb5fcf06096196d0c141b8bd18a3de7"
      "e9b9352da800d671ccd84"),
     ["3045022100ad0dda327945e581a5effd83d75d76a9f07c3128f4dc6d25a54e5ad5dd629bd00220487a992959bd540dbc335c655e6485ebfb394129eb48038f0a2d319782f7cb6901",
      "039319452b6abafb5fcf06096196d0c141b8bd18a3de7e9b9352da800d671ccd84"]),
    (("51"), [1]),
    (("00"), [None]),
    (("510000"), [1, None, None]),
    (("636505aaaaaaaaaa53"), [99, 101, "aaaaaaaaaa", 3]),
    (("51" + "4d0101" + "aa"*257), [1, "aa"*257]),
    (("4d0101" + "aa"*257), ["aa"*257]),
    #TODO: will not load into pytest in Py3 (confirmed manually that the conversion works)
    #(("4e" + "03000100" + "aa"*65539), ["aa"*65539]),
])
def test_deserialize_script(frm, to):
    assert btc.deserialize_script(binascii.unhexlify(frm)) == to
    assert btc.serialize_script(to) == btc.from_string_to_bytes(frm)
