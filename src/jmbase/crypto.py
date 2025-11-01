from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _pad(data: bytes) -> bytes:
    if len(data) % 16 == 0:
        return data
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def _unpad(data: bytes) -> bytes:
    try:
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(data) + unpadder.finalize()
    except ValueError:
        return data


def aes_cbc_encrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    encrypter = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encrypter.update(_pad(data)) + encrypter.finalize()


def aes_cbc_decrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    decrypter = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return _unpad(decrypter.update(data) + decrypter.finalize())
