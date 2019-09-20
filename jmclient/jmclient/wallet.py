from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401

from configparser import NoOptionError
import warnings
import random
import functools
import collections
import numbers
from binascii import hexlify, unhexlify
from datetime import datetime
from copy import deepcopy
from mnemonic import Mnemonic as MnemonicParent
from hashlib import sha256
from itertools import chain
from decimal import Decimal
from numbers import Integral


from .configure import jm_single
from .support import select_gradual, select_greedy, select_greediest, \
    select
from .cryptoengine import TYPE_P2PKH, TYPE_P2SH_P2WPKH,\
    TYPE_P2WPKH, ENGINES
from .support import get_random_bytes
from . import mn_encode, mn_decode
import jmbitcoin as btc


"""
transaction dict format:
    {
        'version': int,
        'locktime': int,
        'ins': [
            {
                'outpoint': {
                    'hash': bytes,
                    'index': int
                },
                'script': bytes,
                'sequence': int,
                'txinwitness': [bytes]
            }
        ],
        'outs': [
            {
                'script': bytes,
                'value': int
            }
        ]
    }
"""


def _int_to_bytestr(i):
    return str(i).encode('ascii')


class WalletError(Exception):
    pass


class Mnemonic(MnemonicParent):
    @classmethod
    def detect_language(cls, code):
        return "english"

def make_shuffled_tx(ins, outs, deser=True, version=1, locktime=0):
    """ Simple utility to ensure transaction
    inputs and outputs are randomly ordered.
    Can possibly be replaced by BIP69 in future
    """
    random.shuffle(ins)
    random.shuffle(outs)
    tx = btc.mktx(ins, outs, version=version, locktime=locktime)
    if deser:
        return btc.deserialize(tx)
    else:
        return tx

def estimate_tx_fee(ins, outs, txtype='p2pkh'):
    '''Returns an estimate of the number of satoshis required
    for a transaction with the given number of inputs and outputs,
    based on information from the blockchain interface.
    '''
    fee_per_kb = jm_single().bc_interface.estimate_fee_per_kb(
                jm_single().config.getint("POLICY","tx_fees"))
    absurd_fee = jm_single().config.getint("POLICY", "absurd_fee_per_kb")
    if fee_per_kb > absurd_fee:
        #This error is considered critical; for safety reasons, shut down.
        raise ValueError("Estimated fee per kB greater than absurd value: " + \
                                     str(absurd_fee) + ", quitting.")
    if txtype in ['p2pkh', 'p2shMofN']:
        tx_estimated_bytes = btc.estimate_tx_size(ins, outs, txtype)
        return int((tx_estimated_bytes * fee_per_kb)/Decimal(1000.0))
    elif txtype in ['p2wpkh', 'p2sh-p2wpkh']:
        witness_estimate, non_witness_estimate = btc.estimate_tx_size(
            ins, outs, txtype)
        return int(int((
        non_witness_estimate + 0.25*witness_estimate)*fee_per_kb)/Decimal(1000.0))
    else:
        raise NotImplementedError("Txtype: " + txtype + " not implemented.")


#FIXME: move this to a utilities file?
def deprecated(func):
    @functools.wraps(func)
    def wrapped(*args, **kwargs):
        warnings.warn("Call to deprecated function {}.".format(func.__name__),
                      category=DeprecationWarning, stacklevel=2)
        return func(*args, **kwargs)

    return wrapped


class UTXOManager(object):
    STORAGE_KEY = b'utxo'
    METADATA_KEY = b'meta'
    TXID_LEN = 32

    def __init__(self, storage, merge_func):
        self.storage = storage
        self.selector = merge_func
        # {mixdexpth: {(txid, index): (path, value)}}
        self._utxo = None
        # metadata kept as a separate key in the database
        # for backwards compat; value as dict for forward-compat.
        # format is {(txid, index): value-dict} with "disabled"
        # as the only currently used key in the dict.
        self._utxo_meta = None
        self._load_storage()
        assert self._utxo is not None

    @classmethod
    def initialize(cls, storage):
        storage.data[cls.STORAGE_KEY] = {}

    def _load_storage(self):
        assert isinstance(self.storage.data[self.STORAGE_KEY], dict)

        self._utxo = collections.defaultdict(dict)
        self._utxo_meta = collections.defaultdict(dict)
        for md, data in self.storage.data[self.STORAGE_KEY].items():
            md = int(md)
            md_data = self._utxo[md]
            for utxo, value in data.items():
                txid = utxo[:self.TXID_LEN]
                index = int(utxo[self.TXID_LEN:])
                md_data[(txid, index)] = value

        # Wallets may not have any metadata
        if self.METADATA_KEY in self.storage.data:
            for utxo, value in self.storage.data[self.METADATA_KEY].items():
                txid = utxo[:self.TXID_LEN]
                index = int(utxo[self.TXID_LEN:])
                self._utxo_meta[(txid, index)] = value

    def save(self, write=True):
        new_data = {}
        self.storage.data[self.STORAGE_KEY] = new_data

        for md, data in self._utxo.items():
            md = _int_to_bytestr(md)
            new_data[md] = {}
            # storage keys must be bytes()
            for (txid, index), value in data.items():
                new_data[md][txid + _int_to_bytestr(index)] = value

        new_meta_data = {}
        self.storage.data[self.METADATA_KEY] = new_meta_data
        for (txid, index), value in self._utxo_meta.items():
            new_meta_data[txid + _int_to_bytestr(index)] = value

        if write:
            self.storage.save()

    def reset(self):
        self._utxo = collections.defaultdict(dict)

    def have_utxo(self, txid, index, include_disabled=True):
        if not include_disabled and self.is_disabled(txid, index):
            return False
        for md in self._utxo:
            if (txid, index) in self._utxo[md]:
                return md
        return False

    def remove_utxo(self, txid, index, mixdepth):
        # currently does not remove metadata associated
        # with this utxo
        assert isinstance(txid, bytes)
        assert len(txid) == self.TXID_LEN
        assert isinstance(index, numbers.Integral)
        assert isinstance(mixdepth, numbers.Integral)

        return self._utxo[mixdepth].pop((txid, index))

    def add_utxo(self, txid, index, path, value, mixdepth):
        # Assumed: that we add a utxo only if we want it enabled,
        # so metadata is not currently added.
        assert isinstance(txid, bytes)
        assert len(txid) == self.TXID_LEN
        assert isinstance(index, numbers.Integral)
        assert isinstance(value, numbers.Integral)
        assert isinstance(mixdepth, numbers.Integral)

        self._utxo[mixdepth][(txid, index)] = (path, value)

    def is_disabled(self, txid, index):
        if not self._utxo_meta:
            return False
        if (txid, index) not in self._utxo_meta:
            return False
        if b'disabled' not in self._utxo_meta[(txid, index)]:
            return False
        if not self._utxo_meta[(txid, index)][b'disabled']:
            return False
        return True

    def disable_utxo(self, txid, index, disable=True):
        assert isinstance(txid, bytes)
        assert len(txid) == self.TXID_LEN
        assert isinstance(index, numbers.Integral)

        if b'disabled' not in self._utxo_meta[(txid, index)]:
            self._utxo_meta[(txid, index)] = {}
        self._utxo_meta[(txid, index)][b'disabled'] = disable

    def enable_utxo(self, txid, index):
        self.disable_utxo(txid, index, disable=False)

    def select_utxos(self, mixdepth, amount, utxo_filter=(), select_fn=None):
        assert isinstance(mixdepth, numbers.Integral)
        utxos = self._utxo[mixdepth]
        # do not select anything in the filter
        available = [{'utxo': utxo, 'value': val}
            for utxo, (addr, val) in utxos.items() if utxo not in utxo_filter]
        # do not select anything disabled
        available = [u for u in available if not self.is_disabled(*u['utxo'])]
        selector = select_fn or self.selector
        selected = selector(available, amount)
        return {s['utxo']: {'path': utxos[s['utxo']][0],
                            'value': utxos[s['utxo']][1]}
                for s in selected}

    def get_balance_by_mixdepth(self, max_mixdepth=float('Inf'),
                                include_disabled=True):
        """ By default this returns a dict of aggregated bitcoin
        balance per mixdepth: {0: N sats, 1: M sats, ...} for all
        currently available mixdepths.
        If max_mixdepth is set it will return balances only up
        to that mixdepth.
        To get only enabled balance, set include_disabled=False.
        """
        balance_dict = collections.defaultdict(int)
        for mixdepth, utxomap in self._utxo.items():
            if mixdepth > max_mixdepth:
                continue
            if not include_disabled:
                utxomap = {k: v for k, v in utxomap.items(
                    ) if not self.is_disabled(*k)}
            value = sum(x[1] for x in utxomap.values())
            balance_dict[mixdepth] = value
        return balance_dict

    def get_utxos_by_mixdepth(self):
        return deepcopy(self._utxo)

    def __eq__(self, o):
        return self._utxo == o._utxo and \
            self.selector is o.selector


class BaseWallet(object):
    TYPE = None

    MERGE_ALGORITHMS = {
        'default': select,
        'gradual': select_gradual,
        'greedy': select_greedy,
        'greediest': select_greediest
    }

    _ENGINES = ENGINES

    _ENGINE = None

    def __init__(self, storage, gap_limit=6, merge_algorithm_name=None,
                 mixdepth=None):
        # to be defined by inheriting classes
        assert self.TYPE is not None
        assert self._ENGINE is not None

        self.merge_algorithm = self._get_merge_algorithm(merge_algorithm_name)
        self.gap_limit = gap_limit
        self._storage = storage
        self._utxos = None
        # highest mixdepth ever used in wallet, important for synching
        self.max_mixdepth = None
        # effective maximum mixdepth to be used by joinmarket
        self.mixdepth = None
        self.network = None

        # {script: path}, should always hold mappings for all "known" keys
        self._script_map = {}

        self._load_storage()

        assert self._utxos is not None
        assert self.max_mixdepth is not None
        assert self.max_mixdepth >= 0
        assert self.network in ('mainnet', 'testnet')

        if mixdepth is not None:
            assert mixdepth >= 0
            if self._storage.read_only and mixdepth > self.max_mixdepth:
                raise Exception("Effective max mixdepth must be at most {}!"
                                .format(self.max_mixdepth))
            self.max_mixdepth = max(self.max_mixdepth, mixdepth)
            self.mixdepth = mixdepth
        else:
            self.mixdepth = self.max_mixdepth

        assert self.mixdepth is not None

    @property
    @deprecated
    def max_mix_depth(self):
        return self.mixdepth

    @property
    @deprecated
    def gaplimit(self):
        return self.gap_limit

    def _load_storage(self):
        """
        load data from storage
        """
        if self._storage.data[b'wallet_type'] != self.TYPE:
            raise Exception("Wrong class to initialize wallet of type {}."
                            .format(self.TYPE))
        self.network = self._storage.data[b'network'].decode('ascii')
        self._utxos = UTXOManager(self._storage, self.merge_algorithm)

    def save(self):
        """
        Write data to associated storage object and trigger persistent update.
        """
        self._utxos.save()

    @classmethod
    def initialize(cls, storage, network, max_mixdepth=2, timestamp=None,
                   write=True):
        """
        Initialize wallet in an empty storage. Must be used on a storage object
        before creating a wallet object with it.

        args:
            storage: a Storage object
            network: str, network we are on, 'mainnet' or 'testnet'
            max_mixdepth: int, number of the highest mixdepth
            timestamp: bytes or None, defaults to the current time
            write: execute storage.save()
        """
        assert network in ('mainnet', 'testnet')
        assert max_mixdepth >= 0

        if storage.data != {}:
            # prevent accidentally overwriting existing wallet
            raise WalletError("Refusing to initialize wallet in non-empty "
                              "storage.")

        if not timestamp:
            timestamp = datetime.now().strftime('%Y/%m/%d %H:%M:%S')

        storage.data[b'network'] = network.encode('ascii')
        storage.data[b'created'] = timestamp.encode('ascii')
        storage.data[b'wallet_type'] = cls.TYPE

        UTXOManager.initialize(storage)

        if write:
            storage.save()

    def get_txtype(self):
        """
        use TYPE constant instead if possible
        """
        if self.TYPE == TYPE_P2PKH:
            return 'p2pkh'
        elif self.TYPE == TYPE_P2SH_P2WPKH:
            return 'p2sh-p2wpkh'
        elif self.TYPE == TYPE_P2WPKH:
            return 'p2wpkh'
        assert False

    def sign_tx(self, tx, scripts, **kwargs):
        """
        Add signatures to transaction for inputs referenced by scripts.

        args:
            tx: transaction dict
            scripts: {input_index: (output_script, amount)}
            kwargs: additional arguments for engine.sign_transaction
        returns:
            input transaction dict with added signatures, hex-encoded.
        """
        for index, (script, amount) in scripts.items():
            assert amount > 0
            path = self.script_to_path(script)
            privkey, engine = self._get_priv_from_path(path)
            tx = btc.deserialize(engine.sign_transaction(tx, index, privkey,
                                                         amount, **kwargs))
        return tx

    @deprecated
    def get_key_from_addr(self, addr):
        """
        There should be no reason for code outside the wallet to need a privkey.
        """
        script = self._ENGINE.address_to_script(addr)
        path = self.script_to_path(script)
        privkey = self._get_priv_from_path(path)[0]
        return hexlify(privkey).decode('ascii')

    def _get_addr_int_ext(self, get_script_func, mixdepth, bci=None):
        script = get_script_func(mixdepth)
        addr = self.script_to_addr(script)
        if bci is not None and hasattr(bci, 'import_addresses'):
            assert hasattr(bci, 'get_wallet_name')
            bci.import_addresses([addr], bci.get_wallet_name(self))
        return addr

    def get_external_addr(self, mixdepth, bci=None):
        """
        Return an address suitable for external distribution, including funding
        the wallet from other sources, or receiving payments or donations.
        JoinMarket will never generate these addresses for internal use.
        If the argument bci is non-null, we attempt to import the new
        address into this blockchaininterface instance
        (based on Bitcoin Core's model).
        """
        return self._get_addr_int_ext(self.get_external_script, mixdepth,
                                      bci=bci)

    def get_internal_addr(self, mixdepth, bci=None):
        """
        Return an address for internal usage, as change addresses and when
        participating in transactions initiated by other parties.
        If the argument bci is non-null, we attempt to import the new
        address into this blockchaininterface instance
        (based on Bitcoin Core's model).
        """
        return self._get_addr_int_ext(self.get_internal_script, mixdepth,
                                      bci=bci)

    def get_external_script(self, mixdepth):
        return self.get_new_script(mixdepth, False)

    def get_internal_script(self, mixdepth):
        return self.get_new_script(mixdepth, True)

    @classmethod
    def addr_to_script(cls, addr):
        return cls._ENGINE.address_to_script(addr)

    @classmethod
    def pubkey_to_script(cls, pubkey):
        return cls._ENGINE.pubkey_to_script(pubkey)

    @classmethod
    def pubkey_to_addr(cls, pubkey):
        return cls._ENGINE.pubkey_to_address(pubkey)

    def script_to_addr(self, script):
        assert self.is_known_script(script)
        path = self.script_to_path(script)
        engine = self._get_priv_from_path(path)[1]
        return engine.script_to_address(script)

    def get_script_code(self, script):
        """
        For segwit wallets, gets the value of the scriptCode
        parameter required (see BIP143) for sighashing; this is
        required for protocols (like Joinmarket) where signature
        verification materials must be communicated between wallets.
        For non-segwit wallets, raises EngineError.
        """
        path = self.script_to_path(script)
        priv, engine = self._get_priv_from_path(path)
        pub = engine.privkey_to_pubkey(priv)
        return engine.pubkey_to_script_code(pub)

    @classmethod
    def pubkey_has_address(cls, pubkey, addr):
        return cls._ENGINE.pubkey_has_address(pubkey, addr)

    @classmethod
    def pubkey_has_script(cls, pubkey, script):
        return cls._ENGINE.pubkey_has_script(pubkey, script)

    @deprecated
    def get_key(self, mixdepth, internal, index):
        raise NotImplementedError()

    def get_addr(self, mixdepth, internal, index):
        script = self.get_script(mixdepth, internal, index)
        return self.script_to_addr(script)

    def get_addr_path(self, path):
        script = self.get_script_path(path)
        return self.script_to_addr(script)

    def get_new_addr(self, mixdepth, internal):
        """
        use get_external_addr/get_internal_addr
        """
        script = self.get_new_script(mixdepth, internal)
        return self.script_to_addr(script)

    def get_new_script(self, mixdepth, internal):
        raise NotImplementedError()

    def get_wif(self, mixdepth, internal, index):
        return self.get_wif_path(self.get_path(mixdepth, internal, index))

    def get_wif_path(self, path):
        priv, engine = self._get_priv_from_path(path)
        return engine.privkey_to_wif(priv)

    def get_path(self, mixdepth=None, internal=None, index=None):
        raise NotImplementedError()

    def get_details(self, path):
        """
        Return mixdepth, internal, index for a given path

        args:
            path: wallet path
        returns:
            tuple (mixdepth, type, index)

            type is one of 0, 1, 'imported'
        """
        raise NotImplementedError()

    @deprecated
    def update_cache_index(self):
        """
        Deprecated alias for save()
        """
        self.save()

    @deprecated
    def remove_old_utxos(self, tx):
        tx = deepcopy(tx)
        for inp in tx['ins']:
            inp['outpoint']['hash'] = unhexlify(inp['outpoint']['hash'])

        ret = self.remove_old_utxos_(tx)

        removed_utxos = {}
        for (txid, index), val in ret.items():
            val['address'] = self.get_addr_path(val['path'])
            removed_utxos[hexlify(txid).decode('ascii') + ':' + str(index)] = val
        return removed_utxos

    def remove_old_utxos_(self, tx):
        """
        Remove all own inputs of tx from internal utxo list.

        args:
            tx: transaction dict
        returns:
            {(txid, index): {'script': bytes, 'value': int} for all removed utxos
        """
        removed_utxos = {}
        for inp in tx['ins']:
            txid, index = inp['outpoint']['hash'], inp['outpoint']['index']
            md = self._utxos.have_utxo(txid, index)
            if md is False:
                continue
            path, value = self._utxos.remove_utxo(txid, index, md)
            script = self.get_script_path(path)
            removed_utxos[(txid, index)] = {'script': script,
                                            'path': path,
                                            'value': value}
        return removed_utxos

    @deprecated
    def add_new_utxos(self, tx, txid):
        tx = deepcopy(tx)
        for out in tx['outs']:
            out['script'] = unhexlify(out['script'])

        ret = self.add_new_utxos_(tx, unhexlify(txid))

        added_utxos = {}
        for (txid_bin, index), val in ret.items():
            addr = self.get_addr_path(val['path'])
            val['address'] = addr
            added_utxos[txid + ':' + str(index)] = val
        return added_utxos

    def add_new_utxos_(self, tx, txid):
        """
        Add all outputs of tx for this wallet to internal utxo list.

        args:
            tx: transaction dict
        returns:
            {(txid, index): {'script': bytes, 'path': tuple, 'value': int}
                for all added utxos
        """
        assert isinstance(txid, bytes) and len(txid) == self._utxos.TXID_LEN
        added_utxos = {}
        for index, outs in enumerate(tx['outs']):
            try:
                self.add_utxo(txid, index, outs['script'], outs['value'])
            except WalletError:
                continue

            path = self.script_to_path(outs['script'])
            added_utxos[(txid, index)] = {'script': outs['script'],
                                          'path': path,
                                          'value': outs['value']}
        return added_utxos

    def add_utxo(self, txid, index, script, value):
        assert isinstance(txid, bytes)
        assert isinstance(index, Integral)
        assert isinstance(script, bytes)
        assert isinstance(value, Integral)

        if script not in self._script_map:
            raise WalletError("Tried to add UTXO for unknown key to wallet.")

        path = self.script_to_path(script)
        mixdepth = self._get_mixdepth_from_path(path)
        self._utxos.add_utxo(txid, index, path, value, mixdepth)

    @deprecated
    def select_utxos(self, mixdepth, amount, utxo_filter=None, select_fn=None):
        utxo_filter_new = None
        if utxo_filter:
            utxo_filter_new = [(unhexlify(utxo[:64]), int(utxo[65:]))
                               for utxo in utxo_filter]
        ret = self.select_utxos_(mixdepth, amount, utxo_filter_new, select_fn)
        ret_conv = {}
        for utxo, data in ret.items():
            addr = self.get_addr_path(data['path'])
            utxo_txt = hexlify(utxo[0]).decode('ascii') + ':' + str(utxo[1])
            ret_conv[utxo_txt] = {'address': addr, 'value': data['value']}
        return ret_conv

    def select_utxos_(self, mixdepth, amount, utxo_filter=None,
                      select_fn=None):
        """
        Select a subset of available UTXOS for a given mixdepth whose value is
        greater or equal to amount.

        args:
            mixdepth: int, mixdepth to select utxos from, must be smaller or
                equal to wallet.max_mixdepth
            amount: int, total minimum amount of all selected utxos
            utxo_filter: list of (txid, index), utxos not to select

        returns:
            {(txid, index): {'script': bytes, 'path': tuple, 'value': int}}
        """
        assert isinstance(mixdepth, numbers.Integral)
        assert isinstance(amount, numbers.Integral)

        if not utxo_filter:
            utxo_filter = ()
        for i in utxo_filter:
            assert len(i) == 2
            assert isinstance(i[0], bytes)
            assert isinstance(i[1], numbers.Integral)
        ret = self._utxos.select_utxos(
            mixdepth, amount, utxo_filter, select_fn)

        for data in ret.values():
            data['script'] = self.get_script_path(data['path'])

        return ret

    def disable_utxo(self, txid, index, disable=True):
        self._utxos.disable_utxo(txid, index, disable)
        # make sure the utxo database is persisted
        self.save()

    def toggle_disable_utxo(self, txid, index):
        is_disabled = self._utxos.is_disabled(txid, index)
        self.disable_utxo(txid, index, disable= not is_disabled)

    def reset_utxos(self):
        self._utxos.reset()

    def get_balance_by_mixdepth(self, verbose=True,
                                include_disabled=False):
        """
        Get available funds in each active mixdepth.
        By default ignores disabled utxos in calculation.
        returns: {mixdepth: value}
        """
        # TODO: verbose
        return self._utxos.get_balance_by_mixdepth(max_mixdepth=self.mixdepth,
                                            include_disabled=include_disabled)

    @deprecated
    def get_utxos_by_mixdepth(self, verbose=True):
        # TODO: verbose
        ret = self.get_utxos_by_mixdepth_()

        utxos_conv = collections.defaultdict(dict)
        for md, utxos in ret.items():
            for utxo, data in utxos.items():
                utxo_str = hexlify(utxo[0]).decode('ascii') + ':' + str(utxo[1])
                addr = self.get_addr_path(data['path'])
                data['address'] = addr
                utxos_conv[md][utxo_str] = data
        return utxos_conv

    def get_utxos_by_mixdepth_(self, include_disabled=False):
        """
        Get all UTXOs for active mixdepths.

        returns:
            {mixdepth: {(txid, index):
                {'script': bytes, 'path': tuple, 'value': int}}}
        """
        mix_utxos = self._utxos.get_utxos_by_mixdepth()

        script_utxos = collections.defaultdict(dict)
        for md, data in mix_utxos.items():
            if md > self.mixdepth:
                continue
            for utxo, (path, value) in data.items():
                if not include_disabled and self._utxos.is_disabled(*utxo):
                    continue
                script = self.get_script_path(path)
                script_utxos[md][utxo] = {'script': script,
                                          'path': path,
                                          'value': value}
        return script_utxos

    @classmethod
    def _get_merge_algorithm(cls, algorithm_name=None):
        if not algorithm_name:
            try:
                algorithm_name = jm_single().config.get('POLICY',
                                                        'merge_algorithm')
            except NoOptionError:
                algorithm_name = 'default'

        alg = cls.MERGE_ALGORITHMS.get(algorithm_name)
        if alg is None:
            raise Exception("Unknown merge algorithm: '{}'."
                            "".format(algorithm_name))
        return alg

    def _get_mixdepth_from_path(self, path):
        raise NotImplementedError()

    def get_script_path(self, path):
        """
        internal note: This is the final sink for all operations that somehow
            need to derive a script. If anything goes wrong when deriving a
            script this is the place to look at.

        args:
            path: wallet path
        returns:
            script
        """
        raise NotImplementedError()

    def get_script(self, mixdepth, internal, index):
        path = self.get_path(mixdepth, internal, index)
        return self.get_script_path(path)

    def _get_priv_from_path(self, path):
        raise NotImplementedError()

    def get_path_repr(self, path):
        """
        Get a human-readable representation of the wallet path.

        args:
            path: path tuple
        returns:
            str
        """
        raise NotImplementedError()

    def path_repr_to_path(self, pathstr):
        """
        Convert a human-readable path representation to internal representation.

        args:
            pathstr: str
        returns:
            path tuple
        """
        raise NotImplementedError()

    def get_next_unused_index(self, mixdepth, internal):
        """
        Get the next index for public scripts/addresses not yet handed out.

        returns:
            int >= 0
        """
        raise NotImplementedError()

    def get_mnemonic_words(self):
        """
        Get mnemonic seed words for master key.

        returns:
            mnemonic_seed, seed_extension
                mnemonic_seed is a space-separated str of words
                seed_extension is a str or None
        """
        raise NotImplementedError()

    def sign_message(self, message, path):
        """
        Sign the message using the key referenced by path.

        args:
            message: bytes
            path: path tuple
        returns:
            signature as base64-encoded string
        """
        priv, engine = self._get_priv_from_path(path)
        return engine.sign_message(priv, message)

    def get_wallet_id(self):
        """
        Get a human-readable identifier for the wallet.

        returns:
            str
        """
        raise NotImplementedError()

    def yield_imported_paths(self, mixdepth):
        """
        Get an iterator for all imported keys in given mixdepth.

        params:
            mixdepth: int
        returns:
            iterator of wallet paths
        """
        return iter([])

    def is_known_addr(self, addr):
        """
        Check if address is known to belong to this wallet.

        params:
            addr: str
        returns:
            bool
        """
        script = self.addr_to_script(addr)
        return script in self._script_map

    def is_known_script(self, script):
        """
        Check if script is known to belong to this wallet.

        params:
            script: bytes
        returns:
            bool
        """
        assert isinstance(script, bytes)
        return script in self._script_map

    def get_addr_mixdepth(self, addr):
        script = self.addr_to_script(addr)
        return self.get_script_mixdepth(script)

    def get_script_mixdepth(self, script):
        path = self.script_to_path(script)
        return self._get_mixdepth_from_path(path)

    def yield_known_paths(self):
        """
        Generator for all paths currently known to the wallet

        returns:
            path generator
        """
        for s in self._script_map.values():
            yield s

    def addr_to_path(self, addr):
        script = self.addr_to_script(addr)
        return self.script_to_path(script)

    def script_to_path(self, script):
        assert script in self._script_map
        return self._script_map[script]

    def set_next_index(self, mixdepth, internal, index, force=False):
        """
        Set the next index to use when generating a new key pair.

        params:
            mixdepth: int
            internal: 0/False or 1/True
            index: int
            force: True if you know the wallet already knows all scripts
                   up to (excluding) the given index

        Warning: improper use of 'force' will cause undefined behavior!
        """
        raise NotImplementedError()

    def close(self):
        self._storage.close()

    def __del__(self):
        self.close()


class ImportWalletMixin(object):
    """
    Mixin for BaseWallet to support importing keys.
    """
    _IMPORTED_STORAGE_KEY = b'imported_keys'
    _IMPORTED_ROOT_PATH = b'imported'

    def __init__(self, storage, **kwargs):
        # {mixdepth: [(privkey, type)]}
        self._imported = None
        # path is (_IMPORTED_ROOT_PATH, mixdepth, key_index)
        super(ImportWalletMixin, self).__init__(storage, **kwargs)

    def _load_storage(self):
        super(ImportWalletMixin, self)._load_storage()
        self._imported = collections.defaultdict(list)
        for md, keys in self._storage.data[self._IMPORTED_STORAGE_KEY].items():
            md = int(md)
            self._imported[md] = keys
            for index, (key, key_type) in enumerate(keys):
                if not key:
                    # imported key was removed
                    continue
                assert key_type in self._ENGINES
                self._cache_imported_key(md, key, key_type, index)

    def save(self):
        import_data = {}
        for md in self._imported:
            import_data[_int_to_bytestr(md)] = self._imported[md]
        self._storage.data[self._IMPORTED_STORAGE_KEY] = import_data
        super(ImportWalletMixin, self).save()

    @classmethod
    def initialize(cls, storage, network, max_mixdepth=2, timestamp=None,
                   write=True, **kwargs):
        super(ImportWalletMixin, cls).initialize(
            storage, network, max_mixdepth, timestamp, write=False, **kwargs)
        storage.data[cls._IMPORTED_STORAGE_KEY] = {}

        if write:
            storage.save()

    def import_private_key(self, mixdepth, wif, key_type=None):
        """
        Import a private key in WIF format.

        args:
            mixdepth: int, mixdepth to import key into
            wif: str, private key in WIF format
            key_type: int, must match a TYPE_* constant of this module,
                used to verify against the key type extracted from WIF

        raises:
            WalletError: if key's network does not match wallet network
            WalletError: if key is not compressed and type is not P2PKH
            WalletError: if key_type does not match data from WIF

        returns:
            path of imported key
        """
        if not 0 <= mixdepth <= self.max_mixdepth:
            raise WalletError("Mixdepth must be positive and at most {}."
                              "".format(self.max_mixdepth))
        if key_type is not None and key_type not in self._ENGINES:
            raise WalletError("Unsupported key type for imported keys.")

        privkey, key_type_wif = self._ENGINE.wif_to_privkey(wif)

        # FIXME: there is no established standard for encoding key type in wif
        #if key_type is not None and key_type_wif is not None and \
        #        key_type != key_type_wif:
        #    raise WalletError("Expected key type does not match WIF type.")

        # default to wallet key type if not told otherwise
        if key_type is None:
            key_type = self.TYPE
            #key_type = key_type_wif if key_type_wif is not None else self.TYPE
        engine = self._ENGINES[key_type]

        if engine.privkey_to_script(privkey) in self._script_map:
            raise WalletError("Cannot import key, already in wallet: {}"
                              "".format(wif))

        self._imported[mixdepth].append((privkey, key_type))
        return self._cache_imported_key(mixdepth, privkey, key_type,
                                        len(self._imported[mixdepth]) - 1)

    def remove_imported_key(self, script=None, address=None, path=None):
        """
        Remove an imported key. Arguments are exclusive.

        args:
            script: bytes
            address: str
            path: path
        """
        if sum((bool(script), bool(address), bool(path))) != 1:
            raise Exception("Only one of script|address|path may be given.")

        if address:
            script = self.addr_to_script(address)
        if script:
            path = self.script_to_path(script)

        if not path:
            raise WalletError("Cannot find key in wallet.")

        if not self._is_imported_path(path):
            raise WalletError("Cannot remove non-imported key.")

        assert len(path) == 3

        if not script:
            script = self.get_script_path(path)

        # we need to retain indices
        self._imported[path[1]][path[2]] = (b'', -1)

        del self._script_map[script]

    def _cache_imported_key(self, mixdepth, privkey, key_type, index):
        engine = self._ENGINES[key_type]
        path = (self._IMPORTED_ROOT_PATH, mixdepth, index)

        self._script_map[engine.privkey_to_script(privkey)] = path

        return path

    def _get_mixdepth_from_path(self, path):
        if not self._is_imported_path(path):
            return super(ImportWalletMixin, self)._get_mixdepth_from_path(path)

        assert len(path) == 3
        return path[1]

    def _get_priv_from_path(self, path):
        if not self._is_imported_path(path):
            return super(ImportWalletMixin, self)._get_priv_from_path(path)

        assert len(path) == 3
        md, i = path[1], path[2]
        assert 0 <= md <= self.max_mixdepth

        if len(self._imported[md]) <= i:
            raise WalletError("unknown imported key at {}"
                              "".format(self.get_path_repr(path)))

        key, key_type = self._imported[md][i]

        if key_type == -1:
            raise WalletError("imported key was removed")

        return key, self._ENGINES[key_type]

    @classmethod
    def _is_imported_path(cls, path):
        return len(path) == 3 and path[0] == cls._IMPORTED_ROOT_PATH

    def path_repr_to_path(self, pathstr):
        spath = pathstr.encode('ascii').split(b'/')
        if not self._is_imported_path(spath):
            return super(ImportWalletMixin, self).path_repr_to_path(pathstr)

        return self._IMPORTED_ROOT_PATH, int(spath[1]), int(spath[2])

    def get_path_repr(self, path):
        if not self._is_imported_path(path):
            return super(ImportWalletMixin, self).get_path_repr(path)

        assert len(path) == 3
        return 'imported/{}/{}'.format(*path[1:])

    def yield_imported_paths(self, mixdepth):
        assert 0 <= mixdepth <= self.max_mixdepth

        for index in range(len(self._imported[mixdepth])):
            if self._imported[mixdepth][index][1] == -1:
                continue
            yield (self._IMPORTED_ROOT_PATH, mixdepth, index)

    def get_details(self, path):
        if not self._is_imported_path(path):
            return super(ImportWalletMixin, self).get_details(path)
        return path[1], 'imported', path[2]

    def get_script_path(self, path):
        if not self._is_imported_path(path):
            return super(ImportWalletMixin, self).get_script_path(path)

        priv, engine = self._get_priv_from_path(path)
        return engine.privkey_to_script(priv)


class BIP39WalletMixin(object):
    """
    Mixin to use BIP-39 mnemonic seed with BIP32Wallet
    """
    _BIP39_EXTENSION_KEY = b'seed_extension'
    MNEMONIC_LANG = 'english'

    def _load_storage(self):
        super(BIP39WalletMixin, self)._load_storage()
        self._entropy_extension = self._storage.data.get(self._BIP39_EXTENSION_KEY)

    @classmethod
    def initialize(cls, storage, network, max_mixdepth=2, timestamp=None,
                   entropy=None, entropy_extension=None, write=True, **kwargs):
        super(BIP39WalletMixin, cls).initialize(
            storage, network, max_mixdepth, timestamp, entropy,
            write=False, **kwargs)
        if entropy_extension:
            storage.data[cls._BIP39_EXTENSION_KEY] = entropy_extension

        if write:
            storage.save()

    def _create_master_key(self):
        ent, ext = self.get_mnemonic_words()
        m = Mnemonic(self.MNEMONIC_LANG)
        return m.to_seed(ent, ext or b'')

    @classmethod
    def _verify_entropy(cls, ent):
        # every 4-bytestream is a valid entropy for BIP-39
        return ent and len(ent) % 4 == 0

    def get_mnemonic_words(self):
        entropy = super(BIP39WalletMixin, self)._create_master_key()
        m = Mnemonic(self.MNEMONIC_LANG)
        return m.to_mnemonic(entropy), self._entropy_extension

    @classmethod
    def entropy_from_mnemonic(cls, seed):
        m = Mnemonic(cls.MNEMONIC_LANG)
        seed = seed.lower()
        if not m.check(seed):
            raise WalletError("Invalid mnemonic seed.")

        ent = m.to_entropy(seed)

        if not cls._verify_entropy(ent):
            raise WalletError("Seed entropy is too low.")

        return bytes(ent)


class BIP32Wallet(BaseWallet):
    _STORAGE_ENTROPY_KEY = b'entropy'
    _STORAGE_INDEX_CACHE = b'index_cache'
    BIP32_MAX_PATH_LEVEL = 2**31
    BIP32_EXT_ID = 0
    BIP32_INT_ID = 1
    ENTROPY_BYTES = 16

    def __init__(self, storage, **kwargs):
        self._entropy = None
        # {mixdepth: {type: index}} with type being 0/1 for [non]-internal
        self._index_cache = None
        # path is a tuple of BIP32 levels,
        # m is the master key's fingerprint
        # other levels are ints
        super(BIP32Wallet, self).__init__(storage, **kwargs)
        assert self._index_cache is not None
        assert self._verify_entropy(self._entropy)

        _master_entropy = self._create_master_key()
        assert _master_entropy
        assert isinstance(_master_entropy, bytes)
        self._master_key = self._derive_bip32_master_key(_master_entropy)

        # used to verify paths for sanity checking and for wallet id creation
        self._key_ident = b''  # otherwise get_bip32_* won't work
        self._key_ident = sha256(sha256(
            self.get_bip32_priv_export(0, 0).encode('ascii')).digest())\
            .digest()[:3]
        self._populate_script_map()

    @classmethod
    def initialize(cls, storage, network, max_mixdepth=2, timestamp=None,
                   entropy=None, write=True):
        """
        args:
            entropy: ENTROPY_BYTES bytes or None to have wallet generate some
        """
        if entropy and not cls._verify_entropy(entropy):
            raise WalletError("Invalid entropy.")

        super(BIP32Wallet, cls).initialize(storage, network, max_mixdepth,
                                           timestamp, write=False)

        if not entropy:
            entropy = get_random_bytes(cls.ENTROPY_BYTES, True)

        storage.data[cls._STORAGE_ENTROPY_KEY] = entropy
        storage.data[cls._STORAGE_INDEX_CACHE] = {
            _int_to_bytestr(i): {} for i in range(max_mixdepth + 1)}

        if write:
            storage.save()

    def _load_storage(self):
        super(BIP32Wallet, self)._load_storage()
        self._entropy = self._storage.data[self._STORAGE_ENTROPY_KEY]

        self._index_cache = collections.defaultdict(
            lambda: collections.defaultdict(int))

        for md, data in self._storage.data[self._STORAGE_INDEX_CACHE].items():
            md = int(md)
            md_map = self._index_cache[md]
            for t, k in data.items():
                md_map[int(t)] = k

        self.max_mixdepth = max(0, 0, *self._index_cache.keys())

    def _populate_script_map(self):
        for md in self._index_cache:
            for int_type in (self.BIP32_EXT_ID, self.BIP32_INT_ID):
                for i in range(self._index_cache[md][int_type]):
                    path = self.get_path(md, int_type, i)
                    script = self.get_script_path(path)
                    self._script_map[script] = path

    def save(self):
        for md, data in self._index_cache.items():
            str_data = {}
            str_md = _int_to_bytestr(md)

            for t, k in data.items():
                str_data[_int_to_bytestr(t)] = k

            self._storage.data[self._STORAGE_INDEX_CACHE][str_md] = str_data

        super(BIP32Wallet, self).save()

    def _create_master_key(self):
        """
        for base/legacy wallet type, this is a passthrough.
        for bip39 style wallets, this will convert from one to the other
        """
        return self._entropy

    @classmethod
    def _verify_entropy(cls, ent):
        # This is not very useful but true for BIP32. Subclasses may have
        # stricter requirements.
        return bool(ent)

    @classmethod
    def _derive_bip32_master_key(cls, seed):
        return cls._ENGINE.derive_bip32_master_key(seed)

    def get_script_path(self, path):
        if not self._is_my_bip32_path(path):
            raise WalletError("unable to get script for unknown key path")

        md, int_type, index = self.get_details(path)

        if not 0 <= md <= self.max_mixdepth:
            raise WalletError("Mixdepth outside of wallet's range.")
        assert int_type in (self.BIP32_EXT_ID, self.BIP32_INT_ID)

        current_index = self._index_cache[md][int_type]

        if index == current_index:
            return self.get_new_script(md, int_type)

        priv, engine = self._get_priv_from_path(path)
        script = engine.privkey_to_script(priv)

        return script

    def get_path(self, mixdepth=None, internal=None, index=None):
        if mixdepth is not None:
            assert isinstance(mixdepth, Integral)
            if not 0 <= mixdepth <= self.max_mixdepth:
                raise WalletError("Mixdepth outside of wallet's range.")

        if internal is not None:
            if mixdepth is None:
                raise Exception("mixdepth must be set if internal is set")
            int_type = self._get_internal_type(internal)

        if index is not None:
            assert isinstance(index, Integral)
            if internal is None:
                raise Exception("internal must be set if index is set")
            assert index <= self._index_cache[mixdepth][int_type]
            assert index < self.BIP32_MAX_PATH_LEVEL
            return tuple(chain(self._get_bip32_export_path(mixdepth, internal),
                               (index,)))

        return tuple(self._get_bip32_export_path(mixdepth, internal))

    def get_path_repr(self, path):
        path = list(path)
        assert self._is_my_bip32_path(path)
        path.pop(0)
        return 'm' + '/' + '/'.join(map(self._path_level_to_repr, path))

    @classmethod
    def _harden_path_level(cls, lvl):
        assert isinstance(lvl, Integral)
        if not 0 <= lvl < cls.BIP32_MAX_PATH_LEVEL:
            raise WalletError("Unable to derive hardened path level from {}."
                              "".format(lvl))
        return lvl + cls.BIP32_MAX_PATH_LEVEL

    @classmethod
    def _path_level_to_repr(cls, lvl):
        assert isinstance(lvl, Integral)
        if not 0 <= lvl < cls.BIP32_MAX_PATH_LEVEL * 2:
            raise WalletError("Invalid path level {}.".format(lvl))
        if lvl < cls.BIP32_MAX_PATH_LEVEL:
            return str(lvl)
        return str(lvl - cls.BIP32_MAX_PATH_LEVEL) + "'"

    def path_repr_to_path(self, pathstr):
        spath = pathstr.split('/')
        assert len(spath) > 0
        if spath[0] != 'm':
            raise WalletError("Not a valid wallet path: {}".format(pathstr))

        def conv_level(lvl):
            if lvl[-1] == "'":
                return self._harden_path_level(int(lvl[:-1]))
            return int(lvl)

        return tuple(chain((self._key_ident,), map(conv_level, spath[1:])))

    def _get_mixdepth_from_path(self, path):
        if not self._is_my_bip32_path(path):
            raise WalletError("Invalid path, unknown root: {}".format(path))

        return path[len(self._get_bip32_base_path())]

    def _get_priv_from_path(self, path):
        if not self._is_my_bip32_path(path):
            raise WalletError("Invalid path, unknown root: {}".format(path))

        return self._ENGINE.derive_bip32_privkey(self._master_key, path), \
            self._ENGINE

    def _is_my_bip32_path(self, path):
        return path[0] == self._key_ident

    def get_new_script(self, mixdepth, internal):
        # This is called by get_script_path and calls back there. We need to
        # ensure all conditions match to avoid endless recursion.
        int_type = self._get_internal_type(internal)
        index = self._index_cache[mixdepth][int_type]
        self._index_cache[mixdepth][int_type] += 1
        path = self.get_path(mixdepth, int_type, index)
        script = self.get_script_path(path)
        self._script_map[script] = path
        return script

    def get_script(self, mixdepth, internal, index):
        path = self.get_path(mixdepth, internal, index)
        return self.get_script_path(path)

    @deprecated
    def get_key(self, mixdepth, internal, index):
        int_type = self._get_internal_type(internal)
        path = self.get_path(mixdepth, int_type, index)
        priv = self._ENGINE.derive_bip32_privkey(self._master_key, path)
        return hexlify(priv).decode('ascii')

    def get_bip32_priv_export(self, mixdepth=None, internal=None):
        path = self._get_bip32_export_path(mixdepth, internal)
        return self._ENGINE.derive_bip32_priv_export(self._master_key, path)

    def get_bip32_pub_export(self, mixdepth=None, internal=None):
        path = self._get_bip32_export_path(mixdepth, internal)
        return self._ENGINE.derive_bip32_pub_export(self._master_key, path)

    def _get_bip32_export_path(self, mixdepth=None, internal=None):
        if mixdepth is None:
            assert internal is None
            path = tuple()
        else:
            assert 0 <= mixdepth <= self.max_mixdepth
            if internal is None:
                path = (self._get_bip32_mixdepth_path_level(mixdepth),)
            else:
                int_type = self._get_internal_type(internal)
                path = (self._get_bip32_mixdepth_path_level(mixdepth), int_type)

        return tuple(chain(self._get_bip32_base_path(), path))

    def _get_bip32_base_path(self):
        return self._key_ident,

    @classmethod
    def _get_bip32_mixdepth_path_level(cls, mixdepth):
        return mixdepth

    def _get_internal_type(self, is_internal):
        return self.BIP32_INT_ID if is_internal else self.BIP32_EXT_ID

    def get_next_unused_index(self, mixdepth, internal):
        assert 0 <= mixdepth <= self.max_mixdepth
        int_type = self._get_internal_type(internal)

        if self._index_cache[mixdepth][int_type] >= self.BIP32_MAX_PATH_LEVEL:
            # FIXME: theoretically this should work for up to
            # self.BIP32_MAX_PATH_LEVEL * 2, no?
            raise WalletError("All addresses used up, cannot generate new ones.")

        return self._index_cache[mixdepth][int_type]

    def get_mnemonic_words(self):
        return ' '.join(mn_encode(hexlify(self._entropy).decode('ascii'))), None

    @classmethod
    def entropy_from_mnemonic(cls, seed):
        words = seed.split()
        if len(words) != 12:
            raise WalletError("Seed phrase must consist of exactly 12 words.")

        return unhexlify(mn_decode(words))

    def get_wallet_id(self):
        return hexlify(self._key_ident).decode('ascii')

    def set_next_index(self, mixdepth, internal, index, force=False):
        int_type = self._get_internal_type(internal)
        if not (force or index <= self._index_cache[mixdepth][int_type]):
            raise Exception("cannot advance index without force=True")
        self._index_cache[mixdepth][int_type] = index

    def get_details(self, path):
        if not self._is_my_bip32_path(path):
            raise Exception("path does not belong to wallet")
        return self._get_mixdepth_from_path(path), path[-2], path[-1]


class LegacyWallet(ImportWalletMixin, BIP32Wallet):
    TYPE = TYPE_P2PKH
    _ENGINE = ENGINES[TYPE_P2PKH]

    def _create_master_key(self):
        return hexlify(self._entropy)

    def _get_bip32_base_path(self):
        return self._key_ident, 0



class BIP32PurposedWallet(BIP32Wallet):
    """ A class to encapsulate cases like
    BIP44, 49 and 84, all of which are derivatives
    of BIP32, and use specific purpose
    fields to flag different wallet types.
    """

    def _get_bip32_base_path(self):
        return self._key_ident, self._PURPOSE,\
               self._ENGINE.BIP44_COIN_TYPE

    @classmethod
    def _get_bip32_mixdepth_path_level(cls, mixdepth):
        assert 0 <= mixdepth < 2**31
        return cls._harden_path_level(mixdepth)

    def _get_mixdepth_from_path(self, path):
        if not self._is_my_bip32_path(path):
            raise WalletError("Invalid path, unknown root: {}".format(path))

        return path[len(self._get_bip32_base_path())] - 2**31

class BIP49Wallet(BIP32PurposedWallet):
    _PURPOSE = 2**31 + 49
    _ENGINE = ENGINES[TYPE_P2SH_P2WPKH]

class BIP84Wallet(BIP32PurposedWallet):
    _PURPOSE = 2**31 + 84
    _ENGINE = ENGINES[TYPE_P2WPKH]

class SegwitLegacyWallet(ImportWalletMixin, BIP39WalletMixin, BIP49Wallet):
    TYPE = TYPE_P2SH_P2WPKH

class SegwitWallet(ImportWalletMixin, BIP39WalletMixin, BIP84Wallet):
    TYPE = TYPE_P2WPKH

WALLET_IMPLEMENTATIONS = {
    LegacyWallet.TYPE: LegacyWallet,
    SegwitLegacyWallet.TYPE: SegwitLegacyWallet,
    SegwitWallet.TYPE: SegwitWallet
}
