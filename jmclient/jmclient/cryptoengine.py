
from collections import OrderedDict
import struct

import jmbitcoin as btc
from jmbase import bintohex
from .configure import get_network, jm_single


#NOTE: before fidelity bonds and watchonly wallet, each of these types corresponded
# to one wallet type and one engine, not anymore
#with fidelity bond wallets and watchonly fidelity bond wallet, the wallet class
# can have two engines, one for single-sig addresses and the other for timelocked addresses
TYPE_P2PKH, TYPE_P2SH_P2WPKH, TYPE_P2WPKH, TYPE_P2SH_M_N, TYPE_TIMELOCK_P2WSH, \
    TYPE_SEGWIT_WALLET_FIDELITY_BONDS, TYPE_WATCHONLY_FIDELITY_BONDS, \
    TYPE_WATCHONLY_TIMELOCK_P2WSH, TYPE_WATCHONLY_P2WPKH = range(9)
NET_MAINNET, NET_TESTNET, NET_SIGNET = range(3)
NET_MAP = {'mainnet': NET_MAINNET, 'testnet': NET_TESTNET,
    'signet': NET_SIGNET}
WIF_PREFIX_MAP = {'mainnet': b'\x80', 'testnet': b'\xef', 'signet': b'\xef'}
BIP44_COIN_MAP = {'mainnet': 2**31, 'testnet': 2**31 + 1, 'signet': 2**31 + 1}

def detect_script_type(script_str):
    """ Given a scriptPubKey, decide which engine
    to use, one of: p2pkh, p2sh-p2wpkh, p2wpkh.
    Note that for the p2sh case, we are assuming the nature
    of the redeem script (p2wpkh wrapped) because that is what
    we support; but we can't know for sure, from the sPK only.
    Raises EngineError if the type cannot be detected, so
    callers MUST handle this exception to avoid crashes.
    """
    script = btc.CScript(script_str)
    if not script.is_valid():
        raise EngineError("Unknown script type for script '{}'"
                          .format(bintohex(script_str)))
    if script.is_p2pkh():
        return TYPE_P2PKH
    elif script.is_p2sh():
        # see note above.
        # note that is_witness_v0_nested_keyhash does not apply,
        # since that picks up scriptSigs not scriptPubKeys.
        return TYPE_P2SH_P2WPKH
    elif script.is_witness_v0_keyhash():
        return TYPE_P2WPKH
    raise EngineError("Unknown script type for script '{}'"
                      .format(bintohex(script_str)))

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
        return btc.privkey_to_pubkey(privkey)

    @staticmethod
    def address_to_script(addr):
        return btc.CCoinAddress(addr).to_scriptPubKey()

    @classmethod
    def wif_to_privkey(cls, wif):
        """ Note July 2020: the `key_type` construction below is
        custom and is not currently used. Future code should
        not use this returned `key_type` variable.
        """
        raw = btc.b58check_to_bin(wif)[1]
        # see note to `privkey_to_wif`; same applies here.
        # We only handle valid private keys, not any byte string.
        btc.read_privkey(raw)

        vbyte = struct.unpack('B', btc.get_version_byte(wif))[0]

        if (struct.unpack('B', btc.BTC_P2PK_VBYTE[get_network()])[0] + \
            struct.unpack('B', cls.WIF_PREFIX)[0]) & 0xff == vbyte:
            key_type = TYPE_P2PKH
        elif (struct.unpack('B', btc.BTC_P2SH_VBYTE[get_network()])[0] + \
              struct.unpack('B', cls.WIF_PREFIX)[0]) & 0xff == vbyte:
            key_type = TYPE_P2SH_P2WPKH
        else:
            key_type = None
        return raw, key_type

    @classmethod
    def privkey_to_wif(cls, priv):
        # refuse to WIF-ify something that we don't recognize
        # as a private key; ignoring the return value of this
        # function as we only want to raise whatever Exception
        # it does:
        btc.read_privkey(priv)
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
        #in the case of watchonly wallets this priv is actually a pubkey
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
    def key_to_script(cls, privkey):
        pub = cls.privkey_to_pubkey(privkey)
        return cls.pubkey_to_script(pub)

    @classmethod
    def pubkey_to_script(cls, pubkey):
        raise NotImplementedError()

    @classmethod
    def privkey_to_address(cls, privkey):
        script = cls.key_to_script(privkey)
        return str(btc.CCoinAddress.from_scriptPubKey(script))

    @classmethod
    def pubkey_to_address(cls, pubkey):
        script = cls.pubkey_to_script(pubkey)
        return str(btc.CCoinAddress.from_scriptPubKey(script))

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
        Note: only (currently) used for manual
        signing of text messages by keys,
        *not* used in Joinmarket communication protocol.
        args:
            privkey: bytes
            message: bytes
        returns:
            base64-encoded signature
        """
        # note: only supported on mainnet
        assert get_network() == "mainnet"
        k = btc.CBitcoinKey(BTCEngine.privkey_to_wif(privkey))
        return btc.SignMessage(k, btc.BitcoinMessage(message)).decode("ascii")

    @classmethod
    def script_to_address(cls, script):
        """ a script passed in as binary converted to a
        Bitcoin address of the appropriate type.
        """
        s = btc.CScript(script)
        assert s.is_valid()
        return str(btc.CCoinAddress.from_scriptPubKey(s))


class BTC_P2PKH(BTCEngine):
    @classproperty
    def VBYTE(cls):
        return btc.BTC_P2PK_VBYTE[get_network()]

    @classmethod
    def pubkey_to_script(cls, pubkey):
        # this call does not enforce compressed:
        return btc.pubkey_to_p2pkh_script(pubkey)

    @classmethod
    def pubkey_to_script_code(cls, pubkey):
        raise EngineError("Script code does not apply to legacy wallets")

    @classmethod
    def sign_transaction(cls, tx, index, privkey, *args, **kwargs):
        hashcode = kwargs.get('hashcode') or btc.SIGHASH_ALL
        return btc.sign(tx, index, privkey,
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
        a, b = btc.sign(tx, index, privkey,
                        hashcode=hashcode, amount=amount, native=False)
        return a, b

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
        return btc.sign(tx, index, privkey,
                        hashcode=hashcode, amount=amount, native="p2wpkh")

class BTC_Timelocked_P2WSH(BTCEngine):

    """
    In this class many instances of "privkey" or "pubkey" are actually tuples
    of (privkey, timelock) or (pubkey, timelock)
    """

    @classproperty
    def VBYTE(cls):
        #slight hack here, network can be either "mainnet" or "testnet"
        #but we need to distinguish between actual testnet and regtest
        if get_network() == "mainnet":
            return btc.BTC_P2PK_VBYTE["mainnet"]
        else:
            if jm_single().config.get("BLOCKCHAIN", "blockchain_source")\
                    == "regtest":
                return btc.BTC_P2PK_VBYTE["regtest"]
            else:
                assert get_network() == "testnet"
                return btc.BTC_P2PK_VBYTE["testnet"]

    @classmethod
    def key_to_script(cls, privkey_locktime):
        privkey, locktime = privkey_locktime
        pub = cls.privkey_to_pubkey(privkey)
        return cls.pubkey_to_script((pub, locktime))

    @classmethod
    def pubkey_to_script(cls, pubkey_locktime):
        redeem_script = cls.pubkey_to_script_code(pubkey_locktime)
        return btc.redeem_script_to_p2wsh_script(redeem_script)

    @classmethod
    def pubkey_to_script_code(cls, pubkey_locktime):
        pubkey, locktime = pubkey_locktime
        return btc.mk_freeze_script(pubkey, locktime)

    @classmethod
    def privkey_to_wif(cls, privkey_locktime):
        priv, locktime = privkey_locktime
        return btc.bin_to_b58check(priv, cls.WIF_PREFIX)

    @classmethod
    def sign_transaction(cls, tx, index, privkey_locktime, amount,
                         hashcode=btc.SIGHASH_ALL, **kwargs):
        assert amount is not None
        priv, locktime = privkey_locktime
        pub = cls.privkey_to_pubkey(priv)
        redeem_script = cls.pubkey_to_script_code((pub, locktime))
        return btc.sign(tx, index, priv, amount=amount, native=redeem_script)

class BTC_Watchonly_Timelocked_P2WSH(BTC_Timelocked_P2WSH):

    @classmethod
    def get_watchonly_path(cls, path):
        #given path is something like "m/49'/1'/0'/0/0"
        #but watchonly wallet already stores the xpub for "m/49'/1'/0'/"
        #so to make this work we must chop off the first 3 elements
        return path[3:]

    @classmethod
    def derive_bip32_privkey(cls, master_key, path):
        assert len(path) > 1
        return cls._walk_bip32_path(master_key, cls.get_watchonly_path(
            path))[-1]

    @classmethod
    def key_to_script(cls, pubkey_locktime):
        pub, locktime = pubkey_locktime
        return cls.pubkey_to_script((pub, locktime))

    @classmethod
    def privkey_to_wif(cls, privkey_locktime):
        return ""

    @classmethod
    def sign_transaction(cls, tx, index, privkey, amount,
                         hashcode=btc.SIGHASH_ALL, **kwargs):
        raise RuntimeError("Cannot spend from watch-only wallets")

class BTC_Watchonly_P2WPKH(BTC_P2WPKH):

    @classmethod
    def derive_bip32_privkey(cls, master_key, path):
        return BTC_Watchonly_Timelocked_P2WSH.derive_bip32_privkey(master_key, path)

    @classmethod
    def privkey_to_wif(cls, privkey_locktime):
        return BTC_Watchonly_Timelocked_P2WSH.privkey_to_wif(privkey_locktime)

    @staticmethod
    def privkey_to_pubkey(privkey):
        #in watchonly wallets there are no privkeys, so functions
        # like _get_key_from_path() actually return pubkeys and
        # this function is a noop
        return privkey

    @classmethod
    def derive_bip32_pub_export(cls, master_key, path):
        return super(BTC_Watchonly_P2WPKH, cls).derive_bip32_pub_export(
            master_key, BTC_Watchonly_Timelocked_P2WSH.get_watchonly_path(path))

    @classmethod
    def sign_transaction(cls, tx, index, privkey, amount,
                         hashcode=btc.SIGHASH_ALL, **kwargs):
        raise RuntimeError("Cannot spend from watch-only wallets")

ENGINES = {
    TYPE_P2PKH: BTC_P2PKH,
    TYPE_P2SH_P2WPKH: BTC_P2SH_P2WPKH,
    TYPE_P2WPKH: BTC_P2WPKH,
    TYPE_TIMELOCK_P2WSH: BTC_Timelocked_P2WSH,
    TYPE_WATCHONLY_TIMELOCK_P2WSH: BTC_Watchonly_Timelocked_P2WSH,
    TYPE_WATCHONLY_P2WPKH: BTC_Watchonly_P2WPKH
}
