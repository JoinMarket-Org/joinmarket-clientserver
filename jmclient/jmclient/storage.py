import os
import shutil
import atexit
import bencoder
import pyaes
from hashlib import sha256
from argon2 import low_level
from .support import get_random_bytes


class Argon2Hash(object):
    def __init__(self, passphrase, salt=None, hash_len=32, salt_len=16,
                 time_cost=500, memory_cost=1000, parallelism=4,
                 argon2_type=low_level.Type.I, version=19):
        """
        args:
          passphrase: passphrase as bytes
          salt: salt in bytes or None to create random one, must have length >= 8
          hash_len: generated hash length in bytes
          salt_len: salt length in bytes, ignored if salt is not None, must be >= 8

        Other arguments are argon2 settings. Only change those if you know what
        you're doing. Optimized for slow hashing suitable for file encryption.
        """
        # Default and recommended settings from argon2.PasswordHasher are for
        # interactive logins. For encryption we want something much slower.
        self.settings = {
            'time_cost': time_cost,
            'memory_cost': memory_cost,
            'parallelism': parallelism,
            'hash_len': hash_len,
            'type': argon2_type,
            'version': version
        }
        self.salt = salt if salt is not None else get_random_bytes(salt_len)
        self.hash = low_level.hash_secret_raw(passphrase, self.salt,
                                              **self.settings)


class StorageError(Exception):
    pass


class RetryableStorageError(StorageError):
    pass


class StoragePassphraseError(RetryableStorageError):
    pass


class Storage(object):
    """
    Responsible for reading/writing [encrypted] data to disk.

    All data to be stored must be added to self.data which defaults to an
    empty dict.

    self.data must contain serializable data (dict, list, tuple, bytes, numbers)
    Having str objects anywhere in self.data will lead to undefined behaviour (py3).
    All dict keys must be bytes.

    KDF: argon2, ENC: AES-256-CBC
    """
    MAGIC_UNENC = b'JMWALLET'
    MAGIC_ENC =   b'JMENCWLT'
    MAGIC_DETECT_ENC = b'JMWALLET'

    ENC_KEY_BYTES = 32  # AES-256
    SALT_LENGTH = 16

    def __init__(self, path, passphrase=None, create=False, read_only=False):
        """
        args:
          path: file path to storage
          passphrase: bytes or None for unencrypted file
          create: create file if it does not exist
          read_only: do not change anything on the file system
        """
        self.path = path
        self._lock_file = None
        self._hash = None
        self._data_checksum = None
        self.data = None
        self.changed = False
        self.read_only = read_only
        self.newly_created = False

        if not os.path.isfile(path):
            if create and not read_only:
                self._create_new(passphrase)
                self._save_file()
                self.newly_created = True
            else:
                raise StorageError("File not found.")
        elif create:
            raise StorageError("File already exists.")
        else:
            self._load_file(passphrase)

        assert self.data is not None
        assert self._data_checksum is not None

        self._create_lock()

    def is_encrypted(self):
        return self._hash is not None

    def is_locked(self):
        return self._lock_file and os.path.exists(self._lock_file)

    def was_changed(self):
        """
        return True if data differs from data on disk
        """
        return self._data_checksum != self._get_data_checksum()

    def check_passphrase(self, passphrase):
        return self._hash.hash == self._hash_passphrase(passphrase, self._hash.salt).hash

    def change_passphrase(self, passphrase):
        if self.read_only:
            raise StorageError("Cannot change passphrase of read-only file.")
        self._set_hash(passphrase)
        self._save_file()

    def save(self):
        """
        Write file to disk if data was modified
        """
        #if not self.was_changed():
        #    return
        if self.read_only:
            raise StorageError("Read-only storage cannot be saved.")
        self._save_file()

    @classmethod
    def is_storage_file(cls, path):
        return cls._get_file_magic(path) in (cls.MAGIC_ENC, cls.MAGIC_UNENC)

    @classmethod
    def is_encrypted_storage_file(cls, path):
        return cls._get_file_magic(path) == cls.MAGIC_ENC

    @classmethod
    def _get_file_magic(cls, path):
        assert len(cls.MAGIC_ENC) == len(cls.MAGIC_UNENC)
        with open(path, 'rb') as fh:
            return fh.read(len(cls.MAGIC_ENC))

    def _get_data_checksum(self):
        if self.data is None:  #pragma: no cover
            return None
        return sha256(self._serialize(self.data)).digest()

    def _update_data_hash(self):
        self._data_checksum = self._get_data_checksum()

    def _create_new(self, passphrase):
        self.data = {}
        self._set_hash(passphrase)

    def _set_hash(self, passphrase):
        if passphrase is None:
            self._hash = None
        else:
            self._hash = self._hash_passphrase(passphrase)

    def _save_file(self):
        assert self.read_only == False
        data = self._serialize(self.data)
        enc_data = self._encrypt_file(data)

        magic = self.MAGIC_UNENC if data is enc_data else self.MAGIC_ENC
        self._write_file(magic + enc_data)
        self._update_data_hash()

    def _load_file(self, passphrase):
        data = self._read_file()
        assert len(self.MAGIC_ENC) == len(self.MAGIC_UNENC) == 8
        magic = data[:8]

        if magic not in (self.MAGIC_ENC, self.MAGIC_UNENC):
            raise StorageError("File does not appear to be a joinmarket wallet.")

        data = data[8:]

        if magic == self.MAGIC_ENC:
            if passphrase is None:
                raise RetryableStorageError("Passphrase required to open wallet.")
            data = self._decrypt_file(passphrase, data)
        else:
            assert magic == self.MAGIC_UNENC

        self.data = self._deserialize(data)
        self._update_data_hash()

    def _write_file(self, data):
        assert self.read_only is False

        if not os.path.exists(self.path):
            # newly created storage
            with open(self.path, 'wb') as fh:
                fh.write(data)
            return

        # using a tmpfile ensures the write is atomic
        tmpfile = '{}.tmp'.format(self.path)

        with open(tmpfile, 'wb') as fh:
            shutil.copystat(self.path, tmpfile)
            fh.write(data)

        #FIXME: behaviour with symlinks might be weird
        shutil.move(tmpfile, self.path)

    def _read_file(self):
        # this method mainly exists for easier mocking
        with open(self.path, 'rb') as fh:
            return fh.read()

    def get_location(self):
        return self.path

    @staticmethod
    def _serialize(data):
        return bencoder.bencode(data)

    @staticmethod
    def _deserialize(data):
        return bencoder.bdecode(data)

    def _encrypt_file(self, data):
        if not self.is_encrypted():
            return data

        iv = get_random_bytes(16)
        container = {
            b'enc': {b'salt': self._hash.salt, b'iv': iv},
            b'data': self._encrypt(data, iv)
        }
        return self._serialize(container)

    def _decrypt_file(self, passphrase, data):
        assert passphrase is not None

        container = self._deserialize(data)
        assert b'enc' in container
        assert b'data' in container

        self._hash = self._hash_passphrase(passphrase, container[b'enc'][b'salt'])

        return self._decrypt(container[b'data'], container[b'enc'][b'iv'])

    def _encrypt(self, data, iv):
        encrypter = pyaes.Encrypter(
                pyaes.AESModeOfOperationCBC(self._hash.hash, iv=iv))
        enc_data = encrypter.feed(self.MAGIC_DETECT_ENC + data)
        enc_data += encrypter.feed()

        return enc_data

    def _decrypt(self, data, iv):
        decrypter = pyaes.Decrypter(
                pyaes.AESModeOfOperationCBC(self._hash.hash, iv=iv))
        try:
            dec_data = decrypter.feed(data)
            dec_data += decrypter.feed()
        except ValueError:
            # in most "wrong passphrase" cases the pkcs7 padding will be wrong
            raise StoragePassphraseError("Wrong passphrase.")

        if not dec_data.startswith(self.MAGIC_DETECT_ENC):
            raise StoragePassphraseError("Wrong passphrase.")
        return dec_data[len(self.MAGIC_DETECT_ENC):]

    @classmethod
    def _hash_passphrase(cls, passphrase, salt=None):
        return Argon2Hash(passphrase, salt,
                          hash_len=cls.ENC_KEY_BYTES, salt_len=cls.SALT_LENGTH)

    def _create_lock(self):
        if self.read_only:
            return
        (path_head, path_tail) = os.path.split(self.path)
        lock_filename = os.path.join(path_head, '.' + path_tail + '.lock')
        self._lock_file = lock_filename
        if os.path.exists(self._lock_file):
            with open(self._lock_file, 'r') as f:
                locked_by_pid = f.read()
            self._lock_file = None
            raise RetryableStorageError(
                               "File is currently in use (locked by pid {}). "
                               "If this is a leftover from a crashed instance "
                               "you need to remove the lock file `{}` manually." .
                               format(locked_by_pid, lock_filename))
        #FIXME: in python >=3.3 use mode x
        with open(self._lock_file, 'w') as f:
            f.write(str(os.getpid()))

        atexit.register(self.close)

    def _remove_lock(self):
        if self._lock_file:
            os.remove(self._lock_file)
            self._lock_file = None

    def close(self):
        if not self.read_only and self.was_changed():
            self._save_file()
        self._remove_lock()
        self.read_only = True

    def __del__(self):
        self.close()


class VolatileStorage(Storage):
    """
    Storage that is never actually written to disk and only kept in memory.

    This exists for easier testing.
    """

    def __init__(self, passphrase=None, data=None):
        self.file_data = None
        super().__init__('VOLATILE', passphrase, create=True)
        if data:
            self.file_data = data
            self._load_file(passphrase)

    def _create_lock(self):
        pass

    def _remove_lock(self):
        pass

    def _write_file(self, data):
        self.file_data = data

    def _read_file(self):
        return self.file_data

    def get_location(self):
        return None
