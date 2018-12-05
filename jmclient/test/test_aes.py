from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401
import jmclient.slowaes as sa
"""test general AES operation; probably not needed.
   Not included in coverage, but should be included in suite."""
import os
import sys
import pytest

def test_pkcs7_bad_padding():
    #used in seed decryption; check that it throws
    #if wrongly padded (this caused a REAL bug before!)
    bad_padded = [b'\x07'*14, b'\x07'*31, b'\x07'*31+b'\x11', b'\x07'*31+b'\x00',
                  b'\x07'*14+b'\x01\x02']
    for b in bad_padded:
        with pytest.raises(Exception) as e_info:
            fake_unpadded = sa.strip_PKCS7_padding(b)

def test_aes():
    cleartext = "This is a test!"
    iv = [103, 35, 148, 239, 76, 213, 47, 118, 255, 222, 123, 176, 106, 134, 98,
          92]
    for ks in [16,24,32]:
        for mode in ["CFB", "CBC", "OFB"]:
            if sys.version_info >= (3,0):
              cypherkey = list(map(int, os.urandom(ks)))
            else:
              cypherkey = list(map(ord, os.urandom(ks)))
            moo = sa.AESModeOfOperation()
            mode, orig_len, ciph = moo.encrypt(cleartext, moo.modeOfOperation[mode],
                                               cypherkey, ks,
                                               iv)
            decr = moo.decrypt(ciph, orig_len, mode, cypherkey,
                               ks, iv)
            assert decr==cleartext