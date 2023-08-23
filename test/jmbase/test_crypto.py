#! /usr/bin/env python
import os
from binascii import unhexlify

import pytest

from jmbase import crypto


@pytest.mark.parametrize("data", [b"surely a secret message", b"joinmarket"])
def test_aes_cbc_padding(data):
    key, iv = os.urandom(32), os.urandom(16)
    encrypted = crypto.aes_cbc_encrypt(key, data, iv)
    assert crypto.aes_cbc_decrypt(key, encrypted, iv) == data


@pytest.mark.parametrize(
    "key, iv, ciphertext, plaintext",
    [
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "000102030405060708090a0b0c0d0e0f",
            "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        ),
        (
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            "000102030405060708090a0b0c0d0e0f",
            "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd",
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        ),
        (
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "000102030405060708090a0b0c0d0e0f",
            "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        ),
    ],
)
def test_aes_cbc_nist_vectors(key, iv, ciphertext, plaintext):
    _key = unhexlify(key)
    _iv = unhexlify(iv)
    ct = unhexlify(ciphertext)
    pt = unhexlify(plaintext)

    assert crypto.aes_cbc_encrypt(_key, pt, _iv) == ct
    assert crypto.aes_cbc_decrypt(_key, ct, _iv) == pt