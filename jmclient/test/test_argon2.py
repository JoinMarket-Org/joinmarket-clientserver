from __future__ import print_function, absolute_import, division, unicode_literals

from jmclient import Argon2Hash, get_random_bytes


def test_argon2_sanity():
    pwd = b'password'
    salt = b'saltsalt'

    h = Argon2Hash(pwd, salt, 16)

    assert len(h.hash) == 16
    assert h.salt == salt
    assert h.hash == b'\x05;V\xd7fy\xdfI\xa4\xe7F$_\\3\xcb'


def test_get_random_bytes():
    assert len(get_random_bytes(16)) == 16
    assert get_random_bytes(16) != get_random_bytes(16)


def test_argon2():
    pwd = b'testpass'
    h = Argon2Hash(pwd, hash_len=16, salt_len=22)

    assert len(h.hash) == 16
    assert len(h.salt) == 22

    h2 = Argon2Hash(pwd, h.salt, hash_len=16)

    assert h.settings == h2.settings
    assert h.hash == h2.hash
    assert h.salt == h2.salt

