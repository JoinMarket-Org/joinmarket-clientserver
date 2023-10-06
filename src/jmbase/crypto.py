import pyaes

def aes_cbc_encrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    encrypter = pyaes.Encrypter(
        pyaes.AESModeOfOperationCBC(key, iv=iv))
    enc_data = encrypter.feed(data)
    enc_data += encrypter.feed()
    return enc_data

def aes_cbc_decrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    decrypter = pyaes.Decrypter(
        pyaes.AESModeOfOperationCBC(key, iv=iv))
    dec_data = decrypter.feed(data)
    dec_data += decrypter.feed()
    return dec_data
