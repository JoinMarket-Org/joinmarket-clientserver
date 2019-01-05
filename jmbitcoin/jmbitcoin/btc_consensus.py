#!/usr/bin/env python

from __future__ import print_function
import binascii
import ctypes
from ctypes import byref, c_int64, c_uint
from getpass import os

SCRIPT_FLAGS = {
        "VERIFY_NONE": 0,
        "VERIFY_P2SH": 1 << 0,
        "VERIFY_DERSIG": 1 << 2,
        "VERIFY_NULLDUMMY": 1 << 4,
        "VERIFY_CHECKLOCKTIMEVERIFY": 1 << 9,
        "VERIFY_CHECKSEQUENCEVERIFY": 1 << 10,
        "VERIFY_WITNESS": 1 << 11 }
SCRIPT_FLAGS["VERIFY_ALL"] = 0
for i, flag in enumerate(SCRIPT_FLAGS): SCRIPT_FLAGS["VERIFY_ALL"] |= SCRIPT_FLAGS[flag]

ERROR_T = [
        "ERR_OK",
        "ERR_TX_INDEX",
        "ERR_TX_SIZE_MISMATCH",
        "ERR_TX_DESERIALIZE",
        "ERR_AMOUNT_REQUIRED",
        "ERR_INVALID_FLAGS" ]


class BitcoinConsensus(object):
    def __init__(self, path):
        self.l = ctypes.CDLL(path)

    def version(self):
        return self.l.bitcoinconsensus_version()

    def verify_script(self, scriptPubKey, txTo, nIn, amount=None, flags=SCRIPT_FLAGS["VERIFY_ALL"]):
        if not isinstance(scriptPubKey, bytes):
            scriptPubKey = binascii.unhexlify(scriptPubKey)
        if not isinstance(txTo, bytes):
            txTo = binascii.unhexlify(txTo)
        try:
            err = ctypes.c_uint32()
            if not amount:
                self.l.bitcoinconsensus_verify_script(
                        scriptPubKey,
                        c_uint(len(scriptPubKey)),
                        txTo,
                        c_uint(len(txTo)),
                        c_uint(nIn),
                        c_uint(flags),
                        byref(err))
            else:
                self.l.bitcoinconsensus_verify_script_with_amount(
                        scriptPubKey,
                        c_uint(len(scriptPubKey)),
                        c_int64(amount),
                        txTo,
                        c_uint(len(txTo)),
                        c_uint(nIn),
                        c_uint(flags),
                        byref(err))

            if ERROR_T[err.value] != "ERR_OK":
                print("script_verify failed : %s" % ERROR_T[err.value])
                return False

            return True
        except Exception as e:
            print("script_verify exception : %s" % e.repr())
            return False

    def lib(self):
        return self.l

if 'VIRTUAL_ENV' not in os.environ:
    if 'libbitcoinconsensus_so' not in os.environ:
        raise EnvironmentError("set an environment variable :\n\
                export libconsensus_so='/path/to/libbitcoinconsensus[.so|.dylib|-0.dll]'")
    else:
        libcon_so = os.environ['libbitcoinconsensus_so']
else:
    libcon_so = os.path.join(os.environ['VIRTUAL_ENV'], "lib", "_libbitcoinconsensus.so")
    if not os.path.exists(libcon_so):
        raise EnvironmentError("libconsensus not found in :\n%s" % libcon_so)

libcon = BitcoinConsensus(libcon_so)

if __name__ == '__main__':
    print('API version', libcon.version())

