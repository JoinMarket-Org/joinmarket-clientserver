from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401

import numbers


def _int_to_bytestr(i):
    return str(i).encode('ascii')


class Boltzmann(object):
    STORAGE_KEY = b'boltzmann'

    def __init__(self, storage):
        self.storage = storage
        # {hex_script: int_rate}
        self._rates = None
        self._load_storage()
        assert self._rates is not None

    @classmethod
    def initialize(cls, storage):
        storage.data[cls.STORAGE_KEY] = {}

    def _load_storage(self):
        storage = self.storage.data[self.STORAGE_KEY]
        assert isinstance(storage, dict)
        assert all([isinstance(x, bytes) for x in storage.keys()])
        assert all([isinstance(x, bytes) for x in storage.values()])

        self._rates = {}
        for script, rate in storage.items():
            self._rates[script] = int(rate)

    def save(self, write=True):
        new_data = {}
        self.storage.data[self.STORAGE_KEY] = new_data
        for script, rate in self._rates.items():
            rate = _int_to_bytestr(rate)
            # storage keys must be bytes()
            new_data[script] = rate
        if write:
            self.storage.save()

    def reset(self):
        self._rates = {}

    def get_rate(self, script):
        assert isinstance(script, bytes) and len(script)

        return self._rates.get(script, 1)

    def has_script(self, script):
        assert isinstance(script, bytes) and len(script)

        return script in self._rates

    def remove_script(self, script):
        assert isinstance(script, bytes) and len(script)

        return self._rates.pop(script)

    def set_rate(self, script, rate):
        assert isinstance(script, bytes) and len(script)
        assert isinstance(rate, numbers.Integral) and rate > 0

        self._rates[script] = rate

    def boltzmann(self, tx):
        raise NotImplementedError
