from jmbitcoin.secp256k1_main import *
import hmac
import hashlib
import struct
from bitcointx.core import Hash160, Hash
from bitcointx import base58

# Below code ASSUMES binary inputs and compressed pubkeys
MAINNET_PRIVATE = b'\x04\x88\xAD\xE4'
MAINNET_PUBLIC = b'\x04\x88\xB2\x1E'
TESTNET_PRIVATE = b'\x04\x35\x83\x94'
TESTNET_PUBLIC = b'\x04\x35\x87\xCF'
SIGNET_PRIVATE = b'\x04\x35\x83\x94'
SIGNET_PUBLIC = b'\x04\x35\x87\xCF'
TESTNET4_PRIVATE = b'\x04\x35\x83\x94'
TESTNET4_PUBLIC = b'\x04\x35\x87\xCF'
PRIVATE = [MAINNET_PRIVATE, TESTNET_PRIVATE, SIGNET_PRIVATE, TESTNET4_PRIVATE]
PUBLIC = [MAINNET_PUBLIC, TESTNET_PUBLIC, SIGNET_PUBLIC, TESTNET4_PUBLIC]

privtopub = privkey_to_pubkey

# BIP32 child key derivation

def raw_bip32_ckd(rawtuple, i):
    vbytes, depth, fingerprint, oldi, chaincode, key = rawtuple
    i = int(i)

    if vbytes in PRIVATE:
        priv = key
        pub = privtopub(key)
    else:
        pub = key

    if i >= 2**31:
        if vbytes in PUBLIC:
            raise Exception("Can't do private derivation on public key!")
        I = hmac.new(chaincode, b'\x00' + priv[:32] + struct.pack(b'>L', i),
                     hashlib.sha512).digest()
    else:
        I = hmac.new(chaincode, pub + struct.pack(b'>L', i),
                     hashlib.sha512).digest()

    if vbytes in PRIVATE:
        newkey = add_privkeys(I[:32] + b'\x01', priv)
        fingerprint = Hash160(privtopub(key))[:4]
    if vbytes in PUBLIC:
        newkey = add_pubkeys([privtopub(I[:32] + b'\x01'), key])
        fingerprint = Hash160(key)[:4]

    return (vbytes, depth + 1, fingerprint, i, I[32:], newkey)

def bip32_serialize(rawtuple):
    vbytes, depth, fingerprint, i, chaincode, key = rawtuple
    if isinstance(i, int):
        i = struct.pack(b'>L', i)
    chaincode = chaincode
    keydata = b'\x00' + key[:-1] if vbytes in PRIVATE else key
    bindata = vbytes + struct.pack(b'B',depth % 256) + fingerprint + i + chaincode + keydata
    return base58.encode(bindata + Hash(bindata)[:4])

def bip32_deserialize(data):
    dbin = base58.decode(data)
    if Hash(dbin[:-4])[:4] != dbin[-4:]:
        raise Exception("Invalid checksum")
    vbytes = dbin[0:4]
    if vbytes not in PRIVATE and vbytes not in PUBLIC:
        raise Exception("Invalid vbytes {}".format(vbytes))
    depth = dbin[4]
    fingerprint = dbin[5:9]
    child_num = struct.unpack(b'>L',dbin[9:13])[0]
    if depth == 0 and (fingerprint != b'\x00'*4 or child_num != 0):
        raise Exception("Invalid master key, depth = {}, fingerprint = {}, child_num = {}".format(depth, fingerprint, child_num))
    chaincode = dbin[13:45]
    key = dbin[46:78] + b'\x01' if vbytes in PRIVATE else dbin[45:78]
    if vbytes in PUBLIC and not is_valid_pubkey(key):
        raise Exception("Invalid public key")
    if vbytes in PRIVATE:
        if dbin[45] != 0:
            raise Exception("Invalid private key")
        # check for validity, this will raise exception
        privkey_to_pubkey(key)
    return (vbytes, depth, fingerprint, child_num, chaincode, key)

def raw_bip32_privtopub(rawtuple):
    vbytes, depth, fingerprint, i, chaincode, key = rawtuple
    if vbytes in PUBLIC:
        return rawtuple
    newvbytes = MAINNET_PUBLIC if vbytes == MAINNET_PRIVATE else TESTNET_PUBLIC
    return (newvbytes, depth, fingerprint, i, chaincode, privtopub(key))

def bip32_privtopub(data):
    return bip32_serialize(raw_bip32_privtopub(bip32_deserialize(data)))

def bip32_ckd(data, i):
    return bip32_serialize(raw_bip32_ckd(bip32_deserialize(data), i))

def bip32_master_key(seed, vbytes=MAINNET_PRIVATE):
    I = hmac.new("Bitcoin seed".encode("utf-8"), seed, hashlib.sha512).digest()
    return bip32_serialize((vbytes, 0, b'\x00' * 4, 0, I[32:], I[:32] + b'\x01'
                           ))

def bip32_extract_key(data):
    return bip32_deserialize(data)[-1]

def bip32_descend(*args):
    if len(args) == 2:
        key, path = args
    else:
        key, path = args[0], map(int, args[1:])
    for p in path:
        key = bip32_ckd(key, p)
    return bip32_extract_key(key)
