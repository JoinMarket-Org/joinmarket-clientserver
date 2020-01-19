

from binascii import hexlify, unhexlify
from collections import OrderedDict
import struct

import jmbitcoin as btc
from .configure import get_network


TYPE_P2PKH, TYPE_P2SH_P2WPKH, TYPE_P2WPKH, TYPE_P2SH_M_N = range(4)
NET_MAINNET, NET_TESTNET = range(2)
NET_MAP = {'mainnet': NET_MAINNET, 'testnet': NET_TESTNET}
WIF_PREFIX_MAP = {'mainnet': b'\x80', 'testnet': b'\xef'}
BIP44_COIN_MAP = {'mainnet': 2**31, 'testnet': 2**31 + 1}

def detect_script_type(script):
    if script.startswith(btc.P2PKH_PRE) and script.endswith(btc.P2PKH_POST) and\
       len(script) == 0x14 + len(btc.P2PKH_PRE) + len(btc.P2PKH_POST):
        return TYPE_P2PKH
    elif (script.startswith(btc.P2SH_P2WPKH_PRE) and
          script.endswith(btc.P2SH_P2WPKH_POST) and
          len(script) == 0x14 + len(btc.P2SH_P2WPKH_PRE) + len(
              btc.P2SH_P2WPKH_POST)):
        return TYPE_P2SH_P2WPKH
    elif script.startswith(btc.P2WPKH_PRE) and\
            len(script) == 0x14 + len(btc.P2WPKH_PRE):
        return TYPE_P2WPKH
    raise EngineError("Unknown script type for script '{}'"
                      .format(hexlify(script)))

class classproperty(object):
    """
    from https://stackoverflow.com/a/5192374
    """
    def __init__(self, f):
        self.f = f

    def __get__(self, obj, owner):
        return self.f(owner)


class SimpleLruCache(OrderedDict):
    """
    note: python3.2 has a lru cache in functools
    """
    def __init__(self, max_size):
        OrderedDict.__init__(self)
        assert max_size > 0
        self.max_size = max_size

    def __setitem__(self, key, value):
        OrderedDict.__setitem__(self, key, value)
        self._adjust_size()

    def __getitem__(self, item):
        e = OrderedDict.__getitem__(self, item)
        del self[item]
        OrderedDict.__setitem__(self, item, e)
        return e

    def _adjust_size(self):
        while len(self) > self.max_size:
            self.popitem(last=False)


#
# library stuff end
#


class EngineError(Exception):
    pass


class BTCEngine(object):
    # must be set by subclasses
    VBYTE = None
    __LRU_KEY_CACHE = SimpleLruCache(50)

    @classproperty
    def BIP32_priv_vbytes(cls):
        return btc.PRIVATE[NET_MAP[get_network()]]

    @classproperty
    def WIF_PREFIX(cls):
        return WIF_PREFIX_MAP[get_network()]

    @classproperty
    def BIP44_COIN_TYPE(cls):
        return BIP44_COIN_MAP[get_network()]

    @staticmethod
    def privkey_to_pubkey(privkey):
        return btc.privkey_to_pubkey(privkey, False)

    @staticmethod
    def address_to_script(addr):
        return unhexlify(btc.address_to_script(addr))

    @classmethod
    def wif_to_privkey(cls, wif):
        raw = btc.b58check_to_bin(wif)
        vbyte = struct.unpack('B', btc.get_version_byte(wif))[0]

        if (struct.unpack('B', btc.BTC_P2PK_VBYTE[get_network()])[0] + struct.unpack('B', cls.WIF_PREFIX)[0]) & 0xff == vbyte:
            key_type = TYPE_P2PKH
        elif (struct.unpack('B', btc.BTC_P2SH_VBYTE[get_network()])[0] + struct.unpack('B', cls.WIF_PREFIX)[0]) & 0xff == vbyte:
            key_type = TYPE_P2SH_P2WPKH
        else:
            key_type = None

        return raw, key_type

    @classmethod
    def privkey_to_wif(cls, priv):
        return btc.bin_to_b58check(priv, cls.WIF_PREFIX)

    @classmethod
    def derive_bip32_master_key(cls, seed):
        # FIXME: slight encoding mess
        return btc.bip32_deserialize(
            btc.bip32_master_key(seed, vbytes=cls.BIP32_priv_vbytes))

    @classmethod
    def derive_bip32_privkey(cls, master_key, path):
        assert len(path) > 1
        return cls._walk_bip32_path(master_key, path)[-1]

    @classmethod
    def derive_bip32_pub_export(cls, master_key, path):
        priv = cls._walk_bip32_path(master_key, path)
        return btc.bip32_serialize(btc.raw_bip32_privtopub(priv))

    @classmethod
    def derive_bip32_priv_export(cls, master_key, path):
        return btc.bip32_serialize(cls._walk_bip32_path(master_key, path))

    @classmethod
    def _walk_bip32_path(cls, master_key, path):
        key = master_key
        for lvl in path[1:]:
            assert 0 <= lvl < 2**32
            if (key, lvl) in cls.__LRU_KEY_CACHE:
                key = cls.__LRU_KEY_CACHE[(key, lvl)]
            else:
                cls.__LRU_KEY_CACHE[(key, lvl)] = btc.raw_bip32_ckd(key, lvl)
                key = cls.__LRU_KEY_CACHE[(key, lvl)]
        return key

    @classmethod
    def privkey_to_script(cls, privkey):
        pub = cls.privkey_to_pubkey(privkey)
        return cls.pubkey_to_script(pub)

    @classmethod
    def pubkey_to_script(cls, pubkey):
        raise NotImplementedError()

    @classmethod
    def privkey_to_address(cls, privkey):
        script = cls.privkey_to_script(privkey)
        return btc.script_to_address(script, cls.VBYTE)

    @classmethod
    def pubkey_to_address(cls, pubkey):
        script = cls.pubkey_to_script(pubkey)
        return btc.script_to_address(script, cls.VBYTE)

    @classmethod
    def pubkey_has_address(cls, pubkey, addr):
        ascript = cls.address_to_script(addr)
        return cls.pubkey_has_script(pubkey, ascript)

    @classmethod
    def pubkey_has_script(cls, pubkey, script):
        stype = detect_script_type(script)
        assert stype in ENGINES
        engine = ENGINES[stype]
        pscript = engine.pubkey_to_script(pubkey)
        return script == pscript

    @classmethod
    def sign_transaction(cls, tx, index, privkey, amount):
        raise NotImplementedError()

    @staticmethod
    def sign_message(privkey, message):
        """
        args:
            privkey: bytes
            message: bytes
        returns:
            base64-encoded signature
        """
        return btc.ecdsa_sign(message, privkey, True, False)

    @classmethod
    def script_to_address(cls, script):
        return btc.script_to_address(script, vbyte=cls.VBYTE)


class BTC_P2PKH(BTCEngine):
    @classproperty
    def VBYTE(cls):
        return btc.BTC_P2PK_VBYTE[get_network()]

    @classmethod
    def pubkey_to_script(cls, pubkey):
        return btc.pubkey_to_p2pkh_script(pubkey)

    @classmethod
    def pubkey_to_script_code(cls, pubkey):
        raise EngineError("Script code does not apply to legacy wallets")

    @classmethod
    def sign_transaction(cls, tx, index, privkey, *args, **kwargs):
        hashcode = kwargs.get('hashcode') or btc.SIGHASH_ALL
        return btc.sign(btc.serialize(tx), index, privkey,
                        hashcode=hashcode, amount=None, native=False)


class BTC_P2SH_P2WPKH(BTCEngine):
    # FIXME: implement different bip32 key export prefixes like electrum?
    # see http://docs.electrum.org/en/latest/seedphrase.html#list-of-reserved-numbers

    @classproperty
    def VBYTE(cls):
        return btc.BTC_P2SH_VBYTE[get_network()]

    @classmethod
    def pubkey_to_script(cls, pubkey):
        return btc.pubkey_to_p2sh_p2wpkh_script(pubkey)

    @classmethod
    def pubkey_to_script_code(cls, pubkey):
        """ As per BIP143, the scriptCode for the p2wpkh
        case is "76a914+hash160(pub)+"88ac" as per the
        scriptPubKey of the p2pkh case.
        """
        return btc.pubkey_to_p2pkh_script(pubkey, require_compressed=True)

    @classmethod
    def sign_transaction(cls, tx, index, privkey, amount,
                         hashcode=btc.SIGHASH_ALL, **kwargs):
        assert amount is not None
        return btc.sign(btc.serialize(tx), index, privkey,
                        hashcode=hashcode, amount=amount, native=False)

class BTC_P2WPKH(BTCEngine):

    @classproperty
    def VBYTE(cls):
        """Note that vbyte is needed in the native segwit case
        to decide the value of the 'human readable part' of the
        bech32 address. If it's 0 or 5 we use 'bc', else we use
        'tb' for testnet bitcoin; so it doesn't matter if we use
        the P2PK vbyte or the P2SH one.
        However, regtest uses 'bcrt' only (and fails on 'tb'),
        so bitcoin.script_to_address currently uses an artificial
        value 100 to flag that case.
        This means that for testing, this value must be explicitly
        overwritten.
        """
        return btc.BTC_P2PK_VBYTE[get_network()]

    @classmethod
    def pubkey_to_script(cls, pubkey):
        return btc.pubkey_to_p2wpkh_script(pubkey)

    @classmethod
    def pubkey_to_script_code(cls, pubkey):
        """ As per BIP143, the scriptCode for the p2wpkh
        case is "76a914+hash160(pub)+"88ac" as per the
        scriptPubKey of the p2pkh case.
        """
        return btc.pubkey_to_p2pkh_script(pubkey, require_compressed=True)

    @classmethod
    def sign_transaction(cls, tx, index, privkey, amount,
                         hashcode=btc.SIGHASH_ALL, **kwargs):
        assert amount is not None
        return btc.sign(btc.serialize(tx), index, privkey,
                        hashcode=hashcode, amount=amount, native=True)

ENGINES = {
    TYPE_P2PKH: BTC_P2PKH,
    TYPE_P2SH_P2WPKH: BTC_P2SH_P2WPKH,
    TYPE_P2WPKH: BTC_P2WPKH
}