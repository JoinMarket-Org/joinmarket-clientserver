from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401

# A wrapper for public key
# authenticated encryption
# using Diffie Hellman key
# exchange to set up a
# symmetric encryption.

import binascii
import base64


from libnacl import public

class NaclError(Exception):
    pass

def init_keypair(fname=None):
    """Create a new encryption
    keypair; stored in file fname
    if provided. The keypair object
    is returned.
    """
    kp = public.SecretKey()
    if fname:
        # Note: handles correct file permissions
        kp.save(fname)
    return kp


# the next two functions are useful
# for exchaging pubkeys with counterparty
def get_pubkey(kp, as_hex=False):
    """Given a keypair object,
    return its public key,
    optionally in hex."""
    if not isinstance(kp, public.SecretKey):
        raise NaclError("Object is not a nacl keypair")
    return kp.hex_pk().decode('ascii') if as_hex else kp.pk


def init_pubkey(hexpk, fname=None):
    """Create a pubkey object from a
    hex formatted string.
    Save to file fname if specified.
    """
    try:
        bin_pk = binascii.unhexlify(hexpk)
    except (TypeError, binascii.Error):
        raise NaclError("Invalid hex")
    if not len(bin_pk) == 32:
        raise NaclError("Public key must be 32 bytes")
    pk = public.PublicKey(binascii.unhexlify(hexpk))
    if fname:
        pk.save(fname)
    return pk


def as_init_encryption(kp, c_pk):
    """Given an initialised
    keypair kp and a counterparty
    pubkey c_pk, create a Box
    ready for encryption/decryption.
    """
    if not isinstance(c_pk, public.PublicKey):
        raise NaclError("Object is not a public key")
    if not isinstance(kp, public.SecretKey):
        raise NaclError("Object is not a nacl keypair")
    return public.Box(kp.sk, c_pk)


'''
After initialisation, it's possible
to use the box object returned from
as_init_encryption to directly change
from plaintext to ciphertext:
    ciphertext = box.encrypt(plaintext)
    plaintext = box.decrypt(ciphertext)
Notes:
 1. use binary format for ctext/ptext
 2. Nonce is handled at the implementation layer.
'''


# TODO: Sign, verify. At the moment we are using
# bitcoin signatures so it isn't necessary.


# encoding for passing over the wire
def encrypt_encode(msg, box):
    encrypted = box.encrypt(msg)
    return base64.b64encode(encrypted).decode('ascii')


def decode_decrypt(msg, box):
    decoded = base64.b64decode(msg)
    return box.decrypt(decoded)
