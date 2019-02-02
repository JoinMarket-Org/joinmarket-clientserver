from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401

import numbers


def _int_to_bytestr(i):
    return str(i).encode('ascii')


def is_hex(s):
    return len(s) % 2 == 0 and all(['0' <= x <= '9' or 'a' <= x.lower() <= 'f' for x in s])


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
        # Upgrade wallets: without this initialization only new wallets would work
        if self.STORAGE_KEY not in self.storage.data:
            self.initialize(self.storage)
        storage = self.storage.data[self.STORAGE_KEY]
        assert isinstance(storage, dict)
        assert all([isinstance(x, bytes) for x in storage.keys()])
        assert all([isinstance(x, bytes) for x in storage.values()])

        self._rates = {}
        for script, rate in storage.items():
            self._rates[script.decode('ascii')] = int(rate)

    def save(self, write=True):
        new_data = {}
        self.storage.data[self.STORAGE_KEY] = new_data
        for script, rate in self._rates.items():
            rate = _int_to_bytestr(rate)
            # storage keys must be bytes()
            new_data[script.encode('ascii')] = rate
        if write:
            self.storage.save()

    def reset(self):
        self._rates = {}

    @staticmethod
    def _check_script(script):
        assert isinstance(script, str) and len(script)

    def get_rate(self, script):
        self._check_script(script)

        return self._rates.get(script, 1)

    def has_script(self, script):
        self._check_script(script)

        return script in self._rates

    def remove_script(self, script):
        self._check_script(script)

        return self._rates.pop(script)

    def set_rate(self, script, rate):
        self._check_script(script)
        assert isinstance(rate, numbers.Integral) and rate > 0

        if self.has_script(script):
            rate = min(self.get_rate(script), rate)

        self._rates[script] = rate

    def update(self, ins_scripts, outs, cjscript, changescript, amount):
        assert len(ins_scripts)
        assert all([isinstance(x, str) and len(x) for x in ins_scripts])
        assert all([x['script'] and isinstance(x['script'], str) and is_hex(x['script']) for x in outs])
        assert all([x['value'] > 0 for x in outs])
        assert isinstance(cjscript, str) and len(cjscript) and is_hex(cjscript)
        assert isinstance(changescript, str) and len(changescript) and is_hex(changescript) or changescript is None
        assert isinstance(amount, numbers.Integral) and amount > 0
        assert amount in [x['value'] for x in outs if x['script'] == cjscript]
        assert not changescript or [x['script'] for x in outs].count(changescript)

        input_rate = min(self.get_rate(x) for x in ins_scripts)
        mult = [x['value'] for x in outs].count(amount)

        self.set_rate(cjscript, input_rate * mult)
        if changescript:
            self.set_rate(changescript, input_rate)

    def clean(self, current_scripts):
        scripts = set(current_scripts)
        for key in list(self._rates.keys()):
            if key not in scripts:
                del self._rates[key]
