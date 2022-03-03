
from jmclient import storage
import pytest


class MockStorage(storage.Storage):
    def __init__(self, data, *args, **kwargs):
        self.file_data = data
        self.locked = False
        super().__init__(*args, **kwargs)

    def _read_file(self):
        if hasattr(self, 'file_data'):
            return self.file_data
        return b''

    def _write_file(self, data):
        self.file_data = data

    def _create_lock(self):
        self.locked = not self.read_only

    def _remove_lock(self):
        self.locked = False


def test_storage():
    s = MockStorage(None, 'nonexistant', b'passphrase', create=True)
    assert s.file_data.startswith(s.MAGIC_ENC)
    assert s.locked
    assert s.is_encrypted()
    assert not s.was_changed()

    old_data = s.file_data

    s.data[b'mydata'] = b'test'
    assert s.was_changed()
    s.save()
    assert s.file_data != old_data
    enc_data = s.file_data

    old_data = s.file_data
    s.change_passphrase(b'newpass')
    assert s.is_encrypted()
    assert not s.was_changed()
    assert s.file_data != old_data

    old_data = s.file_data
    s.change_passphrase(None)
    assert not s.is_encrypted()
    assert not s.was_changed()
    assert s.file_data != old_data
    assert s.file_data.startswith(s.MAGIC_UNENC)

    s2 = MockStorage(enc_data, __file__, b'passphrase')
    assert s2.locked
    assert s2.is_encrypted()
    assert not s2.was_changed()
    assert s2.data[b'mydata'] == b'test'


def test_storage_invalid():
    with pytest.raises(storage.StorageError):
        MockStorage(None, 'nonexistant', b'passphrase')
        pytest.fail("File does not exist")

    s = MockStorage(None, 'nonexistant', b'passphrase', create=True)
    with pytest.raises(storage.StorageError):
        MockStorage(s.file_data, __file__, b'wrongpass')
        pytest.fail("Wrong passphrase")

    with pytest.raises(storage.StorageError):
        MockStorage(s.file_data, __file__)
        pytest.fail("No passphrase")

    with pytest.raises(storage.StorageError):
        MockStorage(b'garbagefile', __file__)
        pytest.fail("Non-wallet file, unencrypted")

    with pytest.raises(storage.StorageError):
        MockStorage(b'garbagefile', __file__, b'passphrase')
        pytest.fail("Non-wallet file, encrypted")

def test_storage_readonly():
    s = MockStorage(None, 'nonexistant', b'passphrase', create=True)
    s = MockStorage(s.file_data, __file__, b'passphrase', read_only=True)
    s.data[b'mydata'] = b'test'

    assert not s.locked
    assert s.was_changed()

    with pytest.raises(storage.StorageError):
        s.save()

    with pytest.raises(storage.StorageError):
        s.change_passphrase(b'newpass')


def test_storage_lock(tmpdir):
    p = str(tmpdir.join('test.jmdat'))
    pw = None

    with pytest.raises(storage.StorageError):
        storage.Storage(p, pw)
        pytest.fail("File does not exist")

    s = storage.Storage(p, pw, create=True)
    assert s.is_locked()
    assert not s.is_encrypted()
    assert s.data == {}

    with pytest.raises(storage.StorageError):
        storage.Storage(p, pw)
        pytest.fail("File is locked")

    assert storage.Storage.is_storage_file(p)
    assert not storage.Storage.is_encrypted_storage_file(p)

    s.data[b'test'] = b'value'
    s.save()
    s.close()
    del s

    s = storage.Storage(p, pw, read_only=True)
    assert not s.is_locked()
    assert s.data == {b'test': b'value'}
    s.close()
    del s

    s = storage.Storage(p, pw)
    assert s.is_locked()
    assert s.data == {b'test': b'value'}

