#!/usr/bin/python
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401
import coincurve as secp256k1

def ecdh(privkey, pubkey):
    """ Take a privkey in raw byte serialization,
    and a pubkey serialized in compressed, binary format (33 bytes),
    and output the shared secret as a 32 byte hash digest output.
    The exact calculation is:
    shared_secret = SHA256(privkey * pubkey)
    .. where * is elliptic curve scalar multiplication.
    See https://github.com/bitcoin/bitcoin/blob/master/src/secp256k1/src/modules/ecdh/main_impl.h
    for implementation details.
    """
    secp_privkey = secp256k1.PrivateKey(privkey)
    return secp_privkey.ecdh(pubkey)
