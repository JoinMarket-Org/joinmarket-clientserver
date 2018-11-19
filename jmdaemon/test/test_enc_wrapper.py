from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401
import base64
import string
import random

import pytest

from jmdaemon import (init_keypair, get_pubkey, init_pubkey, as_init_encryption,
                      NaclError, encrypt_encode, decode_decrypt)


@pytest.mark.parametrize("ab_message,ba_message,num_iterations",
                         [
                             # short ascii
                             (b"Attack at dawn", b"Not tonight Josephine!", 5),
                             # long base64 encoded
                             (base64.b64encode(''.join(random.choice(
                                 string.ascii_letters) for _ in range(5000))),
                              base64.b64encode(''.join(random.choice(
                                  string.ascii_letters) for _ in range(5000))),
                              5,),
                             # large number of messages on the same connection
                             (b'rand', b'rand', 40000),
                             # 1 character
                             (b'\x00', b'\x00', 5),
                         ])
def test_enc_wrapper(alice_bob_boxes, ab_message, ba_message, num_iterations):
    alice_box, bob_box = alice_bob_boxes

    for i in range(num_iterations):
        ab_message = (''.join(
            random.choice(string.ascii_letters)
            for x in range(100))).encode('ascii') if ab_message == b'rand' else ab_message
        ba_message = (''.join(
            random.choice(string.ascii_letters)
            for x in range(100))).encode('ascii') if ba_message == b'rand' else ba_message
        otw_amsg = alice_box.encrypt(ab_message)
        bob_ptext = bob_box.decrypt(otw_amsg)

        assert bob_ptext == ab_message, "Encryption test: FAILED. Alice sent: {}, Bob received: {}".format(
            ab_message, bob_ptext)

        otw_bmsg = bob_box.encrypt(ba_message)
        alice_ptext = alice_box.decrypt(otw_bmsg)
        assert alice_ptext == ba_message, "Encryption test: FAILED. Bob sent: {}, Alice received: {}".format(
            ba_message, alice_ptext)
        assert decode_decrypt(encrypt_encode(ab_message, bob_box), bob_box) == ab_message

@pytest.mark.parametrize("invalid_pubkey",
                         [
                             # short ascii
                             ("abcdef"),
                             ("tt"*32),
                             ("ab"*33),
                             ("cd"*31),
                         ])
def test_invalid_nacl_keys(alice_bob_boxes, invalid_pubkey):
    with pytest.raises(NaclError) as e_info:
        x = init_pubkey(invalid_pubkey)
    with pytest.raises(NaclError) as e_info:
        alice_kp = init_keypair()
        box = as_init_encryption(alice_kp, invalid_pubkey)
    #also try when using the wrong object type as a keypair
    with pytest.raises(NaclError) as e_info:
        alice_bad_kp = init_pubkey("02"*32)
        box = as_init_encryption(alice_bad_kp, alice_bad_kp)
    #try to load a pubkey from a non-keypair object
    with pytest.raises(NaclError) as e_info:
        pk = get_pubkey(invalid_pubkey)

@pytest.fixture()
def alice_bob_boxes():
    alice_kp = init_keypair("alicekey")
    bob_kp = init_keypair("bobkey")

    # this is the DH key exchange part
    bob_otwpk = get_pubkey(bob_kp, True)
    alice_otwpk = get_pubkey(alice_kp, True)

    bob_pk = init_pubkey(bob_otwpk)
    alice_box = as_init_encryption(alice_kp, bob_pk)
    alice_pk = init_pubkey(alice_otwpk, "alicepubkey")
    bob_box = as_init_encryption(bob_kp, alice_pk)

    # now Alice and Bob can use their 'box'
    # constructs (both of which utilise the same
    # shared secret) to perform encryption/decryption
    # to test the encryption functionality
    return (alice_box, bob_box)
