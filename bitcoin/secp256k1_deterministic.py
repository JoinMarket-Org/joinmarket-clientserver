from bitcoin.secp256k1_main import *
import hmac
import hashlib
from binascii import hexlify

# Below code ASSUMES binary inputs and compressed pubkeys
MAINNET_PRIVATE = b'\x04\x88\xAD\xE4'
MAINNET_PUBLIC = b'\x04\x88\xB2\x1E'
TESTNET_PRIVATE = b'\x04\x35\x83\x94'
TESTNET_PUBLIC = b'\x04\x35\x87\xCF'
PRIVATE = [MAINNET_PRIVATE, TESTNET_PRIVATE]
PUBLIC = [MAINNET_PUBLIC, TESTNET_PUBLIC]

# BIP32 child key derivation

def raw_bip32_ckd(rawtuple, i):
    vbytes, depth, fingerprint, oldi, chaincode, key = rawtuple
    i = int(i)

    if vbytes in PRIVATE:
        priv = key
        pub = privtopub(key, False)
    else:
        pub = key

    if i >= 2**31:
        if vbytes in PUBLIC:
            raise Exception("Can't do private derivation on public key!")
        I = hmac.new(chaincode, b'\x00' + priv[:32] + encode(i, 256, 4),
                     hashlib.sha512).digest()
    else:
        I = hmac.new(chaincode, pub + encode(i, 256, 4),
                     hashlib.sha512).digest()

    if vbytes in PRIVATE:
        newkey = add_privkeys(I[:32] + B'\x01', priv, False)
        fingerprint = bin_hash160(privtopub(key, False))[:4]
    if vbytes in PUBLIC:
        newkey = add_pubkeys([privtopub(I[:32] + '\x01', False), key], False)
        fingerprint = bin_hash160(key)[:4]

    return (vbytes, depth + 1, fingerprint, i, I[32:], newkey)

def bip32_serialize(rawtuple):
    vbytes, depth, fingerprint, i, chaincode, key = rawtuple
    i = encode(i, 256, 4)
    chaincode = encode(hash_to_int(chaincode), 256, 32)
    keydata = b'\x00' + key[:-1] if vbytes in PRIVATE else key
    bindata = vbytes + from_int_to_byte(
        depth % 256) + fingerprint + i + chaincode + keydata
    return changebase(bindata + bin_dbl_sha256(bindata)[:4], 256, 58)

def bip32_deserialize(data):
    dbin = changebase(data, 58, 256)
    if bin_dbl_sha256(dbin[:-4])[:4] != dbin[-4:]:
        raise Exception("Invalid checksum")
    vbytes = dbin[0:4]
    depth = from_byte_to_int(dbin[4])
    fingerprint = dbin[5:9]
    i = decode(dbin[9:13], 256)
    chaincode = dbin[13:45]
    key = dbin[46:78] + b'\x01' if vbytes in PRIVATE else dbin[45:78]
    return (vbytes, depth, fingerprint, i, chaincode, key)

def raw_bip32_privtopub(rawtuple):
    vbytes, depth, fingerprint, i, chaincode, key = rawtuple
    newvbytes = MAINNET_PUBLIC if vbytes == MAINNET_PRIVATE else TESTNET_PUBLIC
    return (newvbytes, depth, fingerprint, i, chaincode, privtopub(key, False))

def bip32_privtopub(data):
    return bip32_serialize(raw_bip32_privtopub(bip32_deserialize(data)))

def bip32_ckd(data, i):
    return bip32_serialize(raw_bip32_ckd(bip32_deserialize(data), i))

def bip32_master_key(seed, vbytes=MAINNET_PRIVATE):
    I = hmac.new(
        from_string_to_bytes("Bitcoin seed"), seed, hashlib.sha512).digest()
    return bip32_serialize((vbytes, 0, b'\x00' * 4, 0, I[32:], I[:32] + b'\x01'
                           ))

def bip32_extract_key(data):
    return safe_hexlify(bip32_deserialize(data)[-1])

def bip32_descend(*args):
    if len(args) == 2:
        key, path = args
    else:
        key, path = args[0], map(int, args[1:])
    for p in path:
        key = bip32_ckd(key, p)
    return bip32_extract_key(key)
