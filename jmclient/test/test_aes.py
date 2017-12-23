import jmclient.slowaes as sa
"""test general AES operation; probably not needed.
   Not included in coverage, but should be included in suite."""
import os
import pytest

def test_pkcs7_bad_padding():
    #used in seed decryption; check that it throws
    #if wrongly padded (this caused a REAL bug before!)
    bad_padded = ['\x07'*14, '\x07'*31, '\x07'*31+'\x11', '\x07'*31+'\x00',
                  '\x07'*14+'\x01\x02']
    for b in bad_padded:
        with pytest.raises(Exception) as e_info:
            fake_unpadded = sa.strip_PKCS7_padding(b)

def test_aes():
    cleartext = "This is a test!"
    iv = [103, 35, 148, 239, 76, 213, 47, 118, 255, 222, 123, 176, 106, 134, 98,
          92]
    for ks in [16,24,32]:
        for mode in ["CFB", "CBC", "OFB"]:
            cypherkey = list(os.urandom(ks))
            moo = sa.AESModeOfOperation()
            mode, orig_len, ciph = moo.encrypt(cleartext, moo.modeOfOperation[mode],
                                               cypherkey, ks,
                                               iv)
            decr = moo.decrypt(ciph, orig_len, mode, cypherkey,
                               ks, iv)
            assert decr==cleartext