#!/usr/bin/python

import coincurve as secp256k1
import base64
import hmac
import hashlib
import pyaes
import os
import jmbitcoin as btc

ECIES_MAGIC_BYTES = b'BIE1'

class ECIESDecryptionError(Exception):
    pass

# AES primitives. See BIP-SNICKER for specification.
def aes_encrypt(key, data, iv):
    encrypter = pyaes.Encrypter(
        pyaes.AESModeOfOperationCBC(key, iv=iv))
    enc_data = encrypter.feed(data)
    enc_data += encrypter.feed()

    return enc_data

def aes_decrypt(key, data, iv):
    decrypter = pyaes.Decrypter(
        pyaes.AESModeOfOperationCBC(key, iv=iv))
    try:
        dec_data = decrypter.feed(data)
        dec_data += decrypter.feed()
    except ValueError:
        # note decryption errors can come from PKCS7 padding errors
        raise ECIESDecryptionError()
    return dec_data

def ecies_encrypt(message, pubkey):
    """ Take a message in bytes and a secp256k1 public key
    in compressed byte serialization, and output the
    ECIES encryption, using magic bytes as defined in this module,
    sha512 for the key expansion, and AES-CBC for the encryption;
    these choices are aligned with that used by Electrum.
    """
    # create an ephemeral pubkey for this encryption:
    while True:
        r = os.urandom(32)
        # use compressed serialization of the pubkey R:
        try:
            R = btc.privkey_to_pubkey(r + b"\x01")
            break
        except:
            # accounts for improbable overflow:
            continue
    # note that this is *not* ECDH as in the secp256k1_ecdh module,
    # since it uses sha512:
    ecdh_key = btc.multiply(r, pubkey)
    key = hashlib.sha512(ecdh_key).digest()
    iv, key_e, key_m = key[0:16], key[16:32], key[32:]
    ciphertext = aes_encrypt(key_e, message, iv=iv)
    encrypted = ECIES_MAGIC_BYTES + R + ciphertext
    mac = hmac.new(key_m, encrypted, hashlib.sha256).digest()
    return base64.b64encode(encrypted + mac)    

def ecies_decrypt(privkey, encrypted):
    if len(privkey) == 33 and privkey[-1] == 1:
        privkey = privkey[:32]
    encrypted = base64.b64decode(encrypted)
    if len(encrypted) < 85:
        raise Exception('invalid ciphertext: length')
    magic = encrypted[:4]
    if magic != ECIES_MAGIC_BYTES:
        raise ECIESDecryptionError()
    ephemeral_pubkey = encrypted[4:37]
    try:
        testR = secp256k1.PublicKey(ephemeral_pubkey)
    except:
        raise ECIESDecryptionError()
    ciphertext = encrypted[37:-32]
    mac = encrypted[-32:]
    ecdh_key = btc.multiply(privkey, ephemeral_pubkey)
    key = hashlib.sha512(ecdh_key).digest()
    iv, key_e, key_m = key[0:16], key[16:32], key[32:]
    if mac != hmac.new(key_m, encrypted[:-32], hashlib.sha256).digest():
        raise ECIESDecryptionError()
    return aes_decrypt(key_e, ciphertext, iv=iv)    

