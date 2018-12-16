#!/usr/bin/env python
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401
import argparse
import json
import os.path
from hashlib import sha256
from binascii import hexlify, unhexlify
from collections import defaultdict
from pyaes import AESModeOfOperationCBC, Decrypter

from jmclient import Storage, load_program_config
from jmclient.wallet_utils import get_password, get_wallet_cls,\
    cli_get_wallet_passphrase_check, get_wallet_path
from jmbitcoin import wif_compressed_privkey


class ConvertException(Exception):
    pass


def get_max_mixdepth(data):
    return max(1, len(data.get('index_cache', [1])) - 1,
               *data.get('imported', {}).keys())


def is_encrypted(wallet_data):
    return 'encrypted_seed' in wallet_data or 'encrypted_entropy' in wallet_data


def double_sha256(plaintext):
    return sha256(sha256(plaintext).digest()).digest()


def decrypt_data(key, data):
    decrypter = Decrypter(AESModeOfOperationCBC(key, iv=data[:16]))
    plain = decrypter.feed(data[16:])
    plain += decrypter.feed()
    return plain


def decrypt_entropy_extension(enc_data, key):
    data = decrypt_data(key, unhexlify(enc_data))
    if data[-9] != b'\xff':
        raise ConvertException("Wrong password.")
    chunks = data.split(b'\xff')
    if len(chunks) < 3 or data[-8:] != hexlify(double_sha256(chunks[1]).decode('ascii')[:4]):
        raise ConvertException("Wrong password.")
    return chunks[1]


def decrypt_wallet_data(data, password):
    key = double_sha256(password)

    enc_entropy = data.get('encrypted_seed') or data.get('encrypted_entropy')
    enc_entropy_ext = data.get('encrypted_mnemonic_extension')
    enc_imported = data.get('imported_keys')

    entropy = decrypt_data(key, unhexlify(enc_entropy))
    data['entropy'] = entropy
    if enc_entropy_ext:
        data['entropy_ext'] = decrypt_entropy_extension(enc_entropy_ext, key)

    if enc_imported:
        imported_keys = defaultdict(list)
        for e in enc_imported:
            md = int(e['mixdepth'])
            imported_enc_key = unhexlify(e['encrypted_privkey'])
            imported_key = decrypt_data(key, imported_enc_key)
            imported_keys[md].append(imported_key)
        data['imported'] = imported_keys


def new_wallet_from_data(data, file_name):
    print("Creating new wallet file.")
    new_pw = cli_get_wallet_passphrase_check()
    if new_pw is False:
        return False

    storage = Storage(file_name, create=True, password=new_pw)
    wallet_cls = get_wallet_cls()

    kwdata = {
        'entropy': data['entropy'],
        'timestamp': data.get('creation_time'),
        'max_mixdepth': get_max_mixdepth(data)
    }

    if 'entropy_ext' in data:
        kwdata['entropy_extension'] = data['entropy_ext']

    wallet_cls.initialize(storage, data['network'], **kwdata)
    wallet = wallet_cls(storage)

    if 'index_cache' in data:
        for md, indices in enumerate(data['index_cache']):
            wallet.set_next_index(md, 0, indices[0], force=True)
            wallet.set_next_index(md, 1, indices[1], force=True)

    if 'imported' in data:
        for md in data['imported']:
            for privkey in data['imported'][md]:
                privkey += b'\x01'
                wif = wif_compressed_privkey(hexlify(privkey).decode('ascii'))
                wallet.import_private_key(md, wif)

    wallet.save()
    wallet.close()
    return True


def parse_old_wallet(fh):
    file_data = json.load(fh)

    if is_encrypted(file_data):
        pw = get_password("Enter password for old wallet file: ")
        try:
            decrypt_wallet_data(file_data, pw)
        except ValueError:
            print("Failed to open wallet: bad password")
            return
        except Exception as e:
            print("Error: {}".format(e))
            print("Failed to open wallet. Wrong password?")
            return

    return file_data


def main():
    parser = argparse.ArgumentParser(
        description="Convert old joinmarket json wallet format to new jmdat "
                    "format")
    parser.add_argument('old_wallet_file', type=open)
    parser.add_argument('--name', '-n', required=False, dest='name',
                        help="Name of the new wallet file. Default: [old wallet name].jmdat")

    try:
        args = parser.parse_args()
    except Exception as e:
        print("Error: {}".format(e))
        return

    data = parse_old_wallet(args.old_wallet_file)

    if not data:
        return

    file_name = args.name or\
        os.path.split(args.old_wallet_file.name)[-1].rsplit('.', 1)[0] + '.jmdat'
    wallet_path = get_wallet_path(file_name, None)
    if new_wallet_from_data(data, wallet_path):
        print("New wallet file created at {}".format(wallet_path))
    else:
        print("Failed to convert wallet.")


if __name__ == '__main__':
    load_program_config()
    main()
