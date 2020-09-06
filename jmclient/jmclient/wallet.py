
from configparser import NoOptionError
import warnings
import functools
import collections
import numbers
import random
import base64
import json
from binascii import hexlify, unhexlify
from datetime import datetime
from calendar import timegm
from copy import deepcopy
from mnemonic import Mnemonic as MnemonicParent
from hashlib import sha256
from itertools import chain
from decimal import Decimal
from numbers import Integral


from .configure import jm_single
from .blockchaininterface import INF_HEIGHT
from .support import select_gradual, select_greedy, select_greediest, \
    select
from .cryptoengine import TYPE_P2PKH, TYPE_P2SH_P2WPKH,\
    TYPE_P2WPKH, TYPE_TIMELOCK_P2WSH, TYPE_SEGWIT_LEGACY_WALLET_FIDELITY_BONDS,\
    TYPE_WATCHONLY_FIDELITY_BONDS, TYPE_WATCHONLY_TIMELOCK_P2WSH, TYPE_WATCHONLY_P2SH_P2WPKH,\
    ENGINES
from .support import get_random_bytes
from . import mn_encode, mn_decode
import jmbitcoin as btc
from jmbase import JM_WALLET_NAME_PREFIX, bintohex


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

def estimate_tx_fee(ins, outs, txtype='p2pkh', extra_bytes=0):
    '''Returns an estimate of the number of satoshis required
    for a transaction with the given number of inputs and outputs,
    based on information from the blockchain interface.
    '''
    if jm_single().bc_interface is None:
        raise RuntimeError("Cannot estimate transaction fee " +
            "without blockchain source.")
    fee_per_kb = jm_single().bc_interface.estimate_fee_per_kb(
                jm_single().config.getint("POLICY","tx_fees"))
    absurd_fee = jm_single().config.getint("POLICY", "absurd_fee_per_kb")
    if fee_per_kb > absurd_fee:
        #This error is considered critical; for safety reasons, shut down.
        raise ValueError("Estimated fee per kB greater than absurd value: " + \
                                     str(absurd_fee) + ", quitting.")
    if txtype in ['p2pkh', 'p2shMofN']:
        tx_estimated_bytes = btc.estimate_tx_size(ins, outs, txtype) + extra_bytes
        return int((tx_estimated_bytes * fee_per_kb)/Decimal(1000.0))
    elif txtype in ['p2wpkh', 'p2sh-p2wpkh']:
        witness_estimate, non_witness_estimate = btc.estimate_tx_size(
            ins, outs, txtype)
        non_witness_estimate += extra_bytes
        return int(int((
            non_witness_estimate + 0.25*witness_estimate)*fee_per_kb)/Decimal(1000.0))
    else:
        raise NotImplementedError("Txtype: " + txtype + " not implemented.")


def compute_tx_locktime():
    # set locktime for best anonset (Core, Electrum)
    # most recent block or some time back in random cases
    locktime = jm_single().bc_interface.get_current_block_height()
    if random.randint(0, 9) == 0:
        # P2EP requires locktime > 0
        locktime = max(1, locktime - random.randint(0, 99))
    return locktime


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
        # {mixdexpth: {(txid, index): (path, value, height)}}
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

        x = self._utxo[mixdepth].pop((txid, index))
        return x

    def add_utxo(self, txid, index, path, value, mixdepth, height=None):
        # Assumed: that we add a utxo only if we want it enabled,
        # so metadata is not currently added.
        # The height (blockheight) field will be "infinity" for unconfirmed.
        assert isinstance(txid, bytes)
        assert len(txid) == self.TXID_LEN
        assert isinstance(index, numbers.Integral)
        assert isinstance(value, numbers.Integral)
        assert isinstance(mixdepth, numbers.Integral)
        if height is None:
            height = INF_HEIGHT
        assert isinstance(height, numbers.Integral)

        self._utxo[mixdepth][(txid, index)] = (path, value, height)

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

    def select_utxos(self, mixdepth, amount, utxo_filter=(), select_fn=None,
                     maxheight=None):
        assert isinstance(mixdepth, numbers.Integral)
        utxos = self._utxo[mixdepth]
        # do not select anything in the filter
        available = [{'utxo': utxo, 'value': val}
            for utxo, (addr, val, height) in utxos.items() if utxo not in utxo_filter]
        # do not select anything with insufficient confirmations:
        if maxheight is not None:
            available = [{'utxo': utxo, 'value': val}
                         for utxo, (addr, val, height) in utxos.items(
                             ) if height <= maxheight]
        # do not select anything disabled
        available = [u for u in available if not self.is_disabled(*u['utxo'])]
        selector = select_fn or self.selector
        selected = selector(available, amount)
        # note that we do not return height; for selection, we expect
        # the caller will not want this (after applying the height filter)
        return {s['utxo']: {'path': utxos[s['utxo']][0],
                            'value': utxos[s['utxo']][1]}
                for s in selected}

    def get_balance_by_mixdepth(self, max_mixdepth=float('Inf'),
                                include_disabled=True, maxheight=None):
        """ By default this returns a dict of aggregated bitcoin
        balance per mixdepth: {0: N sats, 1: M sats, ...} for all
        currently available mixdepths.
        If max_mixdepth is set it will return balances only up
        to that mixdepth.
        To get only enabled balance, set include_disabled=False.
        To get balances only with a certain number of confs, use maxheight.
        """
        balance_dict = collections.defaultdict(int)
        for mixdepth, utxomap in self._utxo.items():
            if mixdepth > max_mixdepth:
                continue
            if not include_disabled:
                utxomap = {k: v for k, v in utxomap.items(
                    ) if not self.is_disabled(*k)}
                if maxheight is not None:
                    utxomap = {k: v for k, v in utxomap.items(
                        ) if v[2] <= maxheight}
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

    ADDRESS_TYPE_EXTERNAL = 0
    ADDRESS_TYPE_INTERNAL = 1

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

    def get_storage_location(self):
        """ Return the location of the
        persistent storage, if it exists, or None.
        """
        if not self._storage:
            return None
        return self._storage.get_location()

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
        elif self.TYPE in (TYPE_P2SH_P2WPKH,
                TYPE_SEGWIT_LEGACY_WALLET_FIDELITY_BONDS):
            return 'p2sh-p2wpkh'
        elif self.TYPE == TYPE_P2WPKH:
            return 'p2wpkh'
        assert False

    def sign_tx(self, tx, scripts, **kwargs):
        """
        Add signatures to transaction for inputs referenced by scripts.

        args:
            tx: CMutableTransaction object
            scripts: {input_index: (output_script, amount)}
            kwargs: additional arguments for engine.sign_transaction
        returns:
            True, None if success.
            False, msg if signing failed, with error msg.
        """
        for index, (script, amount) in scripts.items():
            assert amount > 0
            path = self.script_to_path(script)
            privkey, engine = self._get_key_from_path(path)
            sig, msg = engine.sign_transaction(tx, index, privkey,
                                                         amount, **kwargs)
            if not sig:
                return False, msg
        return True, None

    @deprecated
    def get_key_from_addr(self, addr):
        """
        There should be no reason for code outside the wallet to need a privkey.
        """
        script = self._ENGINE.address_to_script(addr)
        path = self.script_to_path(script)
        privkey = self._get_key_from_path(path)[0]
        return privkey

    def _get_addr_int_ext(self, address_type, mixdepth):
        if address_type == self.ADDRESS_TYPE_EXTERNAL:
            script = self.get_external_script(mixdepth)
        elif address_type == self.ADDRESS_TYPE_INTERNAL:
            script = self.get_internal_script(mixdepth)
        else:
            assert 0
        return self.script_to_addr(script)

    def get_external_addr(self, mixdepth):
        """
        Return an address suitable for external distribution, including funding
        the wallet from other sources, or receiving payments or donations.
        JoinMarket will never generate these addresses for internal use.
        """
        return self._get_addr_int_ext(self.ADDRESS_TYPE_EXTERNAL, mixdepth)

    def get_internal_addr(self, mixdepth):
        """
        Return an address for internal usage, as change addresses and when
        participating in transactions initiated by other parties.
        """
        return self._get_addr_int_ext(self.ADDRESS_TYPE_INTERNAL, mixdepth)

    def get_external_script(self, mixdepth):
        return self.get_new_script(mixdepth, self.ADDRESS_TYPE_EXTERNAL)

    def get_internal_script(self, mixdepth):
        return self.get_new_script(mixdepth, self.ADDRESS_TYPE_INTERNAL)

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
        engine = self._get_key_from_path(path)[1]
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
        priv, engine = self._get_key_from_path(path)
        pub = engine.privkey_to_pubkey(priv)
        return engine.pubkey_to_script_code(pub)

    @classmethod
    def pubkey_has_address(cls, pubkey, addr):
        return cls._ENGINE.pubkey_has_address(pubkey, addr)

    @classmethod
    def pubkey_has_script(cls, pubkey, script):
        return cls._ENGINE.pubkey_has_script(pubkey, script)

    @deprecated
    def get_key(self, mixdepth, address_type, index):
        raise NotImplementedError()

    def get_addr(self, mixdepth, address_type, index):
        script = self.get_script(mixdepth, address_type, index)
        return self.script_to_addr(script)

    def get_address_from_path(self, path):
        script = self.get_script_from_path(path)
        return self.script_to_addr(script)

    def get_new_addr(self, mixdepth, address_type):
        """
        use get_external_addr/get_internal_addr
        """
        script = self.get_new_script(mixdepth, address_type)
        return self.script_to_addr(script)

    def get_new_script(self, mixdepth, address_type):
        raise NotImplementedError()

    def get_wif(self, mixdepth, address_type, index):
        return self.get_wif_path(self.get_path(mixdepth, address_type, index))

    def get_wif_path(self, path):
        priv, engine = self._get_key_from_path(path)
        return engine.privkey_to_wif(priv)

    def get_path(self, mixdepth=None, address_type=None, index=None):
        raise NotImplementedError()

    def get_details(self, path):
        """
        Return mixdepth, address_type, index for a given path

        args:
            path: wallet path
        returns:
            tuple (mixdepth, type, index)

            type is one of 0, 1, 'imported', 2, 3
        """
        raise NotImplementedError()

    @deprecated
    def update_cache_index(self):
        """
        Deprecated alias for save()
        """
        self.save()

    def remove_old_utxos(self, tx):
        """
        Remove all own inputs of tx from internal utxo list.

        args:
            tx: CMutableTransaction
        returns:
            {(txid, index): {'script': bytes, 'path': str, 'value': int} for all removed utxos
        """
        removed_utxos = {}
        for inp in tx.vin:
            txid = inp.prevout.hash[::-1]
            index = inp.prevout.n
            md = self._utxos.have_utxo(txid, index)
            if md is False:
                continue
            path, value, height = self._utxos.remove_utxo(txid, index, md)
            script = self.get_script_from_path(path)
            removed_utxos[(txid, index)] = {'script': script,
                                            'path': path,
                                            'value': value}
        return removed_utxos

    def add_new_utxos(self, tx, height=None):
        """
        Add all outputs of tx for this wallet to internal utxo list.
        They are also returned in standard dict form.
        args:
            tx: CMutableTransaction
            height: blockheight in which tx was included, or None
                    if unconfirmed.
        returns:
            {(txid, index): {'script': bytes, 'path': tuple, 'value': int,
            'address': str}
                for all added utxos
        """
        added_utxos = {}
        txid = tx.GetTxid()[::-1]
        for index, outs in enumerate(tx.vout):
            spk = outs.scriptPubKey
            val = outs.nValue
            try:
                self.add_utxo(txid, index, spk, val, height=height)
            except WalletError:
                continue

            path = self.script_to_path(spk)
            added_utxos[(txid, index)] = {'script': spk, 'path': path, 'value': val,
                'address': self._ENGINE.script_to_address(spk)}
        return added_utxos

    def add_utxo(self, txid, index, script, value, height=None):
        assert isinstance(txid, bytes)
        assert isinstance(index, Integral)
        assert isinstance(script, bytes)
        assert isinstance(value, Integral)

        if script not in self._script_map:
            raise WalletError("Tried to add UTXO for unknown key to wallet.")

        path = self.script_to_path(script)
        mixdepth = self._get_mixdepth_from_path(path)
        self._utxos.add_utxo(txid, index, path, value, mixdepth, height=height)

    def process_new_tx(self, txd, height=None):
        """ Given a newly seen transaction, deserialized as
        CMutableTransaction txd,
        process its inputs and outputs and update
        the utxo contents of this wallet accordingly.
        NOTE: this should correctly handle transactions that are not
        actually related to the wallet; it will not add (or remove,
        obviously) utxos that were not related since the underlying
        functions check this condition.
        """
        removed_utxos = self.remove_old_utxos(txd)
        added_utxos = self.add_new_utxos(txd, height=height)
        return (removed_utxos, added_utxos)

    def select_utxos(self, mixdepth, amount, utxo_filter=None,
                      select_fn=None, maxheight=None, includeaddr=False):
        """
        Select a subset of available UTXOS for a given mixdepth whose value is
        greater or equal to amount. If `includeaddr` is True, adds an `address`
        key to the returned dict.

        args:
            mixdepth: int, mixdepth to select utxos from, must be smaller or
                equal to wallet.max_mixdepth
            amount: int, total minimum amount of all selected utxos
            utxo_filter: list of (txid, index), utxos not to select
            maxheight: only select utxos with blockheight <= this.

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
            mixdepth, amount, utxo_filter, select_fn, maxheight=maxheight)

        for data in ret.values():
            data['script'] = self.get_script_from_path(data['path'])
            if includeaddr:
                data["address"] = self.get_address_from_path(data["path"])
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
                                include_disabled=False,
                                maxheight=None):
        """
        Get available funds in each active mixdepth.
        By default ignores disabled utxos in calculation.
        By default returns unconfirmed transactions, to filter
        confirmations, set maxheight to max acceptable blockheight.
        returns: {mixdepth: value}
        """
        # TODO: verbose
        return self._utxos.get_balance_by_mixdepth(max_mixdepth=self.mixdepth,
                                            include_disabled=include_disabled,
                                            maxheight=maxheight)

    def get_utxos_by_mixdepth(self, include_disabled=False, includeheight=False):
        """
        Get all UTXOs for active mixdepths.

        returns:
            {mixdepth: {(txid, index):
                {'script': bytes, 'path': tuple, 'value': int}}}
        (if `includeheight` is True, adds key 'height': int)
        """
        mix_utxos = self._utxos.get_utxos_by_mixdepth()

        script_utxos = collections.defaultdict(dict)
        for md, data in mix_utxos.items():
            if md > self.mixdepth:
                continue
            for utxo, (path, value, height) in data.items():
                if not include_disabled and self._utxos.is_disabled(*utxo):
                    continue
                script = self.get_script_from_path(path)
                addr = self.get_address_from_path(path)
                script_utxos[md][utxo] = {'script': script,
                                          'path': path,
                                          'value': value,
                                          'address': addr}
                if includeheight:
                    script_utxos[md][utxo]['height'] = height
        return script_utxos


    def get_all_utxos(self, include_disabled=False):
        """ Get all utxos in the wallet, format of return
        is as for get_utxos_by_mixdepth for each mixdepth.
        """
        mix_utxos = self.get_utxos_by_mixdepth(
            include_disabled=include_disabled)
        all_utxos = {}
        for d in mix_utxos.values():
            all_utxos.update(d)
        return all_utxos

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

    def get_script_from_path(self, path):
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

    def get_script(self, mixdepth, address_type, index):
        path = self.get_path(mixdepth, address_type, index)
        return self.get_script_from_path(path)

    def _get_key_from_path(self, path):
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

    def get_next_unused_index(self, mixdepth, address_type):
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
        priv, engine = self._get_key_from_path(path)
        return engine.sign_message(priv, message)

    def get_wallet_name(self):
        """ Returns the name used as a label for this
        specific Joinmarket wallet in Bitcoin Core.
        """
        return JM_WALLET_NAME_PREFIX + self.get_wallet_id()

    def get_wallet_id(self):
        """
        Get a human-readable identifier for the wallet.

        returns:
            str
        """
        raise NotImplementedError()

    def check_wallet_passphrase(self, passphrase):
        return self._storage.check_password(passphrase)

    def change_wallet_passphrase(self, passphrase):
        self._storage.change_password(passphrase)

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

    def set_next_index(self, mixdepth, address_type, index, force=False):
        """
        Set the next index to use when generating a new key pair.

        params:
            mixdepth: int
            address_type: 0 (external) or 1 (internal)
            index: int
            force: True if you know the wallet already knows all scripts
                   up to (excluding) the given index

        Warning: improper use of 'force' will cause undefined behavior!
        """
        raise NotImplementedError()

    def rewind_wallet_indices(self, used_indices, saved_indices):
        for md in used_indices:
            for address_type in range(min(len(used_indices[md]), len(saved_indices[md]))):
                index = max(used_indices[md][address_type],
                            saved_indices[md][address_type])
                self.set_next_index(md, address_type, index, force=True)

    def _get_default_used_indices(self):
        return {x: [0, 0] for x in range(self.max_mixdepth + 1)}

    def get_used_indices(self, addr_gen):
        """ Returns a dict of max used indices for each branch in
        the wallet, from the given addresses addr_gen, assuming
        that they are known to the wallet.
        """
        indices = self._get_default_used_indices()

        for addr in addr_gen:
            if not self.is_known_addr(addr):
                continue
            md, address_type, index = self.get_details(
                self.addr_to_path(addr))
            if address_type not in (self.BIP32_EXT_ID, self.BIP32_INT_ID,
                    FidelityBondMixin.BIP32_TIMELOCK_ID, FidelityBondMixin.BIP32_BURN_ID):
                assert address_type == 'imported'
                continue
            indices[md][address_type] = max(indices[md][address_type], index + 1)

        return indices

    def check_gap_indices(self, used_indices):
        """ Return False if any of the provided indices (which should be
        those seen from listtransactions as having been used, for
        this wallet/label) are higher than the ones recorded in the index
        cache."""

        for md in used_indices:
            for address_type in (self.ADDRESS_TYPE_EXTERNAL,
                    self.ADDRESS_TYPE_INTERNAL):
                if used_indices[md][address_type] >\
                   max(self.get_next_unused_index(md, address_type), 0):
                    return False
        return True

    def close(self):
        self._storage.close()

    def __del__(self):
        self.close()

class PSBTWalletMixin(object):
    """
    Mixin for BaseWallet to provide BIP174
    functions.
    """
    def __init__(self, storage, **kwargs):
        super().__init__(storage, **kwargs)

    def is_input_finalized(self, psbt_input):
        """ This should be a convenience method in python-bitcointx.
        However note: this is not a static method and tacitly
        assumes that the input under examination is of the wallet's
        type.
        """
        assert isinstance(psbt_input, btc.PSBT_Input)
        if not psbt_input.utxo:
            return False
        if isinstance(self, (LegacyWallet, SegwitLegacyWallet)):
            if not psbt_input.final_script_sig:
                return False
        if isinstance(self, (SegwitLegacyWallet, SegwitWallet)):
            if not psbt_input.final_script_witness:
                return False
        return True

    @staticmethod
    def human_readable_psbt(in_psbt):
        """ Returns a jsonified indented string with all relevant
        information, in human readable form, contained in a PSBT.
        Warning: the output can be very verbose in certain cases.
        """
        assert isinstance(in_psbt, btc.PartiallySignedTransaction)
        outdict = {}
        outdict["psbt-version"] = in_psbt.version

        # human readable serialization of these three global fields is for
        # now on a "best-effort" basis, i.e. just takes the representation
        # provided by the underlying classes in bitcointx, though this may
        # not be very readable.
        # TODO: Improve proprietary/unknown as needed.
        if in_psbt.xpubs:
            outdict["xpubs"] = {str(k): bintohex(
                v.serialize()) for k, v in in_psbt.xpubs.items()}
        if in_psbt.proprietary_fields:
            outdict["proprietary-fields"] = str(in_psbt.proprietary_fields)
        if in_psbt.unknown_fields:
            outdict["unknown-fields"] = str(in_psbt.unknown_fields)

        outdict["unsigned-tx"] = btc.human_readable_transaction(
            in_psbt.unsigned_tx, jsonified=False)
        outdict["psbt-inputs"] = []
        for inp in in_psbt.inputs:
            outdict["psbt-inputs"].append(
                PSBTWalletMixin.human_readable_psbt_in(inp))
        outdict["psbt-outputs"] = []
        for out in in_psbt.outputs:
            outdict["psbt-outputs"].append(
                PSBTWalletMixin.human_readable_psbt_out(out))
        return json.dumps(outdict, indent=4)

    @staticmethod
    def human_readable_psbt_in(psbt_input):
        """ Returns a dict containing human readable information
        about a bitcointx.core.psbt.PSBT_Input object.
        """
        assert isinstance(psbt_input, btc.PSBT_Input)
        outdict = {}
        if psbt_input.index is not None:
            outdict["input-index"] = psbt_input.index
        if psbt_input.utxo:
            if isinstance(psbt_input.utxo, btc.CTxOut):
                outdict["utxo"] = btc.human_readable_output(psbt_input.utxo)
            elif isinstance(psbt_input.utxo, btc.CTransaction):
                # human readable full transaction is *too* verbose:
                outdict["utxo"] = bintohex(psbt_input.utxo.serialize())
            else:
                assert False, "invalid PSBT Input utxo field."
        if psbt_input.sighash_type:
            outdict["sighash-type"] = psbt_input.sighash_type
        if psbt_input.redeem_script:
            outdict["redeem-script"] = bintohex(psbt_input.redeem_script)
        if psbt_input.witness_script:
            outdict["witness-script"] = bintohex(psbt_input.witness_script)
        if psbt_input.partial_sigs:
            # convert the dict entries to hex:
            outdict["partial-sigs"] = {bintohex(k): bintohex(v) for k,v in \
                                       psbt_input.partial_sigs.items()}
        # Note we do not currently add derivation info to our own inputs,
        # but probably will in future ( TODO ), still this is shown for
        # externally generated PSBTs:
        if psbt_input.derivation_map:
            # TODO it would be more useful to print the indexes of the
            # derivation path as integers, than 4 byte hex:
            outdict["derivation-map"] = {bintohex(k): bintohex(v.serialize(
                )) for k, v in psbt_input.derivation_map.items()}

        # we show these fields on a best-effort basis; same comment as for
        # globals section as mentioned in hr_psbt()
        if psbt_input.proprietary_fields:
            outdict["proprietary-fields"] = str(psbt_input.proprietary_fields)
        if psbt_input.unknown_fields:
            outdict["unknown-fields"] = str(psbt_input.unknown_fields)
        if psbt_input.proof_of_reserves_commitment:
            outdict["proof-of-reserves-commitment"] = \
                str(psbt_input.proof_of_reserves_commitment)

        outdict["final-scriptSig"] = bintohex(psbt_input.final_script_sig)
        outdict["final-scriptWitness"] = bintohex(
            psbt_input.final_script_witness.serialize())

        return outdict

    @staticmethod
    def human_readable_psbt_out(psbt_output):
        """ Returns a dict containing human readable information
        about a PSBT_Output object.
        """
        assert isinstance(psbt_output, btc.PSBT_Output)
        outdict = {}
        if psbt_output.index is not None:
            outdict["output-index"] = psbt_output.index

        if psbt_output.derivation_map:
            # See note to derivation map in hr_psbt_in()
            outdict["derivation-map"] = {bintohex(k): bintohex(v.serialize(
                )) for k, v in psbt_output.derivation_map.items()}

        if psbt_output.redeem_script:
            outdict["redeem-script"] = bintohex(psbt_output.redeem_script)
        if psbt_output.witness_script:
            outdict["witness-script"] = bintohex(psbt_output.witness_script)

        if psbt_output.proprietary_fields:
            outdict["proprietary-fields"] = str(psbt_output.proprietary_fields)
        if psbt_output.unknown_fields:
            outdict["unknown-fields"] = str(psbt_output.unknown_fields)

        return outdict

    @staticmethod
    def witness_utxos_to_psbt_utxos(utxos):
        """ Given a dict of utxos as returned from select_utxos,
        convert them to the format required to populate PSBT inputs,
        namely CTxOut. Note that the non-segwit case is different, there
        you should provide an entire CMutableTransaction object instead.
        """
        return [btc.CMutableTxOut(v["value"],
                                  v["script"]) for _, v in utxos.items()]

    @staticmethod
    def check_finalized_input_type(psbt_input):
        """ Given an input of a PSBT which is already finalized,
        return its type as either "sw-legacy" or "sw" or False
        if not one of these two types.
        TODO: can be extented to other types.
        """
        assert isinstance(psbt_input, btc.PSBT_Input)
        # TODO: cleanly check that this PSBT Input is finalized.
        if psbt_input.utxo.scriptPubKey.is_p2sh():
            # Note: p2sh does not prove the redeemscript;
            # we check the finalscriptSig is p2wpkh:
            fss = btc.CScript(next(btc.CScript(
                psbt_input.final_script_sig).raw_iter())[1])
            if fss.is_witness_v0_keyhash():
                return "sw-legacy"
        elif psbt_input.utxo.scriptPubKey.is_witness_v0_keyhash():
            return "sw"
        else:
            return False

    def create_psbt_from_tx(self, tx, spent_outs=None):
        """ Given a CMutableTransaction object, which should not currently
        contain signatures, we create and return a new PSBT object of type
        btc.PartiallySignedTransaction.
        Optionally the information about the spent outputs that is stored
        in PSBT_IN_NONWITNESS_UTXO, PSBT_IN_WITNESS_UTXO and PSBT_IN_REDEEM_SCRIPT
        can also be provided, one item per input, in the tuple (spent_outs).
        These objects should be either CMutableTransaction, CTxOut or None,
        Note that redeem script information cannot be provided for inputs which
        we don't own.
        """
        # TODO: verify tx contains no signatures as a sanity check?
        new_psbt = btc.PartiallySignedTransaction(unsigned_tx=tx)
        if spent_outs is None:
            # user has not provided input script information; psbt
            # will not yet be usable for signing.
            return new_psbt
        for i, txinput in enumerate(new_psbt.inputs):
            if spent_outs[i] is None:
                # as above, will not be signable in this case
                continue
            if isinstance(spent_outs[i], (btc.CTransaction, btc.CTxOut)):
                # note that we trust the caller to choose Tx vs TxOut as according
                # to non-witness/witness. Note also that for now this mixin does
                # not attempt to provide unsigned-tx(second argument) for witness
                # case.
                txinput.set_utxo(spent_outs[i], None)
            else:
                assert False, "invalid spent output type passed into PSBT creator"
        # we now insert redeemscripts where that is possible and necessary:
        for i, txinput in enumerate(new_psbt.inputs):
            if isinstance(txinput.witness_utxo, btc.CTxOut):
                # witness
                if txinput.utxo.scriptPubKey.is_witness_scriptpubkey():
                    # nothing needs inserting; the scriptSig is empty.
                    continue
                elif txinput.utxo.scriptPubKey.is_p2sh():
                    try:
                        path = self.script_to_path(txinput.utxo.scriptPubKey)
                    except AssertionError:
                        # this happens when an input is provided but it's not in
                        # this wallet; in this case, we cannot set the redeem script.
                        continue
                    privkey, _ = self._get_key_from_path(path)
                    txinput.redeem_script = btc.pubkey_to_p2wpkh_script(
                        btc.privkey_to_pubkey(privkey))
        return new_psbt

    def sign_psbt(self, in_psbt, with_sign_result=False):
        """ Given a serialized PSBT in raw binary format,
        iterate over the inputs and sign all that we can sign with this wallet.
        NB IT IS UP TO CALLERS TO ENSURE THAT THEY ACTUALLY WANT TO SIGN
        THIS TRANSACTION!
        The above is important especially in coinjoin scenarios.
        Return: (psbt, msg)
        msg: error message or None
        if not `with_sign_result`:
        psbt: signed psbt in binary serialization, or None if error.
        if `with_sign_result` True:
        psbt: (PSBT_SignResult object, psbt (deserialized) object)
        """
        try:
            new_psbt = btc.PartiallySignedTransaction.from_binary(in_psbt)
        except Exception as e:
            return None, "Unable to deserialize binary PSBT, error: " + repr(e)
        privkeys = []
        for k, v in self._utxos._utxo.items():
            for k2, v2 in v.items():
                privkeys.append(self._get_key_from_path(v2[0]))
        jmckeys = list(btc.JMCKey(x[0][:-1]) for x in privkeys)
        new_keystore = btc.KeyStore.from_iterable(jmckeys)

        # for p2sh inputs that we want to sign, the redeem_script
        # field must be populated by us, as the counterparty did not
        # know it. If this was set in an earlier create-psbt role,
        # then overwriting it is harmless (preimage resistance).
        if isinstance(self, SegwitLegacyWallet):
            for i, txinput in enumerate(new_psbt.inputs):
                tu = txinput.witness_utxo
                if isinstance(tu, btc.CTxOut):
                    # witness
                    if tu.scriptPubKey.is_witness_scriptpubkey():
                        # native segwit; no insertion needed.
                        continue
                    elif tu.scriptPubKey.is_p2sh():
                        try:
                            path = self.script_to_path(tu.scriptPubKey)
                        except AssertionError:
                            # this happens when an input is provided but it's not in
                            # this wallet; in this case, we cannot set the redeem script.
                            continue
                        privkey, _ = self._get_key_from_path(path)
                        txinput.redeem_script = btc.pubkey_to_p2wpkh_script(
                            btc.privkey_to_pubkey(privkey))
                    # no else branch; any other form of scriptPubKey will just be
                    # ignored.
        try:
            signresult = new_psbt.sign(new_keystore)
        except Exception as e:
            return None, repr(e)
        if not with_sign_result:
            return new_psbt.serialize(), None
        else:
            return (signresult, new_psbt), None

class SNICKERWalletMixin(object):

    SUPPORTED_SNICKER_VERSIONS = bytes([0, 1])

    def __init__(self, storage, **kwargs):
        super().__init__(storage, **kwargs)

    def create_snicker_proposal(self, our_input, their_input, our_input_utxo,
                                their_input_utxo, net_transfer, network_fee,
                                our_priv, their_pub, our_spk, change_spk,
                                encrypted=True, version_byte=1):
        """ Creates a SNICKER proposal from the given transaction data.
        This only applies to existing specification, i.e. SNICKER v 00 or 01.
        This is only to be used for Joinmarket and only segwit wallets.
        `our_input`, `their_input` - utxo format used in JM wallets,
        keyed by (tixd, n), as dicts (currently of single entry).
        `our_input_utxo`, `their..` - type CTxOut (contains value, scriptPubKey)
        net_transfer - amount, after bitcoin transaction fee, transferred from
        Proposer (our) to Receiver (their). May be negative.
        network_fee - total bitcoin network transaction fee to be paid (so estimates
        must occur before this function).
        `our_priv`, `their_pub` - these are the keys to be used in ECDH to derive
        the tweak as per the BIP. Note `their_pub` may or may not be associated with
        the input of the receiver, so is specified here separately. Note also that
        according to the BIP the privkey we use *must* be the one corresponding to
        the input we provided, else (properly coded) Receivers will reject our
        proposal.
        `our_spk` - a scriptPubKey for the Proposer coinjoin output
        `change_spk` - a change scriptPubkey for the proposer as per BIP
        `encrypted` - whether or not to return the ECIES encrypted version of the
        proposal.
        `version_byte` - which of currently specified Snicker versions is being
        used, (0 for reused address, 1 for inferred key).
        returns:
        if encrypted is True:
          base 64 encoded encrypted transaction proposal as a string
        else:
          binary serialized plaintext SNICKER message.
        """
        assert isinstance(self, PSBTWalletMixin)
        # before constructing the bitcoin transaction we must calculate the output
        # amounts
        # TODO investigate arithmetic for negative transfer
        if our_input_utxo.nValue - their_input_utxo.nValue - network_fee <= 0:
            raise Exception(
                "Cannot create SNICKER proposal, Proposer input too small")
        total_input_amount = our_input_utxo.nValue + their_input_utxo.nValue
        total_output_amount = total_input_amount - network_fee
        receiver_output_amount = their_input_utxo.nValue + net_transfer
        proposer_output_amount = total_output_amount - receiver_output_amount

        # we must also use ecdh to calculate the output scriptpubkey for the
        # receiver
        # First, check that `our_priv` corresponds to scriptPubKey in
        # `our_input_utxo` to prevent callers from making useless proposals.
        expected_pub = btc.privkey_to_pubkey(our_priv)
        expected_spk = self.pubkey_to_script(expected_pub)
        assert our_input_utxo.scriptPubKey == expected_spk
        # now we create the ecdh based tweak:
        tweak_bytes = btc.ecdh(our_priv[:-1], their_pub)
        tweaked_pub = btc.snicker_pubkey_tweak(their_pub, tweak_bytes)
        # TODO: remove restriction to one scriptpubkey type
        tweaked_spk = btc.pubkey_to_p2sh_p2wpkh_script(tweaked_pub)
        tweaked_addr, our_addr, change_addr = [str(
            btc.CCoinAddress.from_scriptPubKey(x)) for x in (
                tweaked_spk, expected_spk, change_spk)]
        # now we must construct the three outputs with correct output amounts.
        outputs = [{"address": tweaked_addr, "value": receiver_output_amount}]
        outputs.append({"address": our_addr, "value": receiver_output_amount})
        outputs.append({"address": change_addr,
                "value": total_output_amount - 2 * receiver_output_amount})
        assert all([x["value"] > 0 for x in outputs])

        # version and locktime as currently specified in the BIP
        # for 0/1 version SNICKER.
        tx = btc.make_shuffled_tx([our_input, their_input], outputs,
                              version=2, locktime=0)
        # we need to know which randomized input is ours:
        our_index = -1
        for i, inp in enumerate(tx.vin):
            if our_input == (inp.prevout.hash[::-1], inp.prevout.n):
                our_index = i
        assert our_index in [0, 1], "code error: our input not in tx"
        spent_outs = [our_input_utxo, their_input_utxo]
        if our_index == 1:
            spent_outs = spent_outs[::-1]
        # create the psbt and then sign our input.
        snicker_psbt = self.create_psbt_from_tx(tx, spent_outs=spent_outs)

        # having created the PSBT, sign our input
        # TODO this requires bitcointx updated minor version else fails
        signed_psbt_and_signresult, err = self.sign_psbt(
        snicker_psbt.serialize(), with_sign_result=True)
        assert err is None
        signresult, partially_signed_psbt = signed_psbt_and_signresult
        assert signresult.num_inputs_signed == 1
        assert signresult.num_inputs_final == 1
        assert not signresult.is_final
        snicker_serialized_message = btc.SNICKER_MAGIC_BYTES + bytes(
            [version_byte]) + btc.SNICKER_FLAG_NONE + tweak_bytes + \
            partially_signed_psbt.serialize()

        if not encrypted:
            return snicker_serialized_message

        # encryption has been requested;
        # we apply ECIES in the form given by the BIP.
        return btc.ecies_encrypt(snicker_serialized_message, their_pub)

    def parse_proposal_to_signed_tx(self, privkey, proposal,
                                    acceptance_callback):
        """ Given a candidate privkey (binary and compressed format),
        and a candidate encrypted SNICKER proposal, attempt to decrypt
        and validate it in all aspects. If validation fails the first
        return value is None and the second is the reason as a string.

        If all validation checks pass, the next step is checking
        acceptance according to financial rules: the acceptance
        callback must be a function that accepts four arguments:
        (our_ins, their_ins, our_outs, their_outs), where *ins values
        are lists of CTxIns and *outs are lists of CTxOuts,
        and must return only True/False where True means that the
        transaction should be signed.

        If True is returned from the callback, the following are returned
        from this function:
        (raw transaction for broadcasting (serialized),
        tweak value as bytes,  derived output spk belonging to receiver)

        Note: flags is currently always None as version is only 0 or 1.
        """
        assert isinstance(self, PSBTWalletMixin)

        our_pub = btc.privkey_to_pubkey(privkey)

        if len(proposal) < 5:
            return None, "Invalid proposal, too short."

        if base64.b64decode(proposal)[:4] == btc.ECIES_MAGIC_BYTES:
            # attempt decryption and reject if fails:
            try:
                snicker_message = btc.ecies_decrypt(privkey, proposal)
            except Exception as e:
                return None, "Failed to decrypt." + repr(e)
        else:
            snicker_message = proposal

        # magic + version,flag + tweak + psbt:
        # TODO replace '20' with the minimum feasible PSBT.
        if len(snicker_message) < 7 + 2 + 32 + 20:
            return None, "Invalid proposal, too short."

        if snicker_message[:7] != btc.SNICKER_MAGIC_BYTES:
            return None, "Invalid SNICKER magic bytes."

        version_byte = bytes([snicker_message[7]])
        flag_byte = bytes([snicker_message[8]])
        if version_byte not in self.SUPPORTED_SNICKER_VERSIONS:
            return None, "Unrecognized SNICKER version: " + version_byte
        if flag_byte != btc.SNICKER_FLAG_NONE:
            return None, "Invalid flag byte for version 0,1: " + flag_byte

        tweak_bytes = snicker_message[9:41]
        candidate_psbt_serialized = snicker_message[41:]
        # attempt to validate the PSBT's format:
        try:
            cpsbt = btc.PartiallySignedTransaction.from_base64_or_binary(
                candidate_psbt_serialized)
        except:
            return None, "Invalid PSBT format."

        utx = cpsbt.unsigned_tx
        # validate that it contains one signature, and two inputs.
        # else the proposal is invalid. To achieve this, we call
        # PartiallySignedTransaction.sign() with an empty KeyStore,
        # which populates the 'is_signed' info fields for us. Note that
        # we do not use the PSBTWalletMixin.sign_psbt() which automatically
        # signs with our keys.
        if not len(utx.vin) == 2:
            return None, "PSBT proposal does not contain 2 inputs."
        testsignresult = cpsbt.sign(btc.KeyStore(), finalize=False)
        print("got sign result: ", testsignresult)
        # Note: "num_inputs_signed" refers to how many *we* signed,
        # which is obviously none here as we provided no keys.
        if not (testsignresult.num_inputs_signed == 0 and \
                testsignresult.num_inputs_final == 1 and \
                not testsignresult.is_final):
            return None, "PSBT proposal does not contain 1 signature."

        # Validate that we own one SNICKER style output:
        spk = btc.verify_snicker_output(utx, our_pub, tweak_bytes)

        if spk[0] == -1:
            return None, "Tweaked destination not found exactly once."
        our_output_index = spk[0]
        our_output_amount = utx.vout[our_output_index].nValue

        # At least one other output must have an amount equal to that at
        # `our_output_index`, according to the spec.
        found = 0
        for i, o in enumerate(utx.vout):
            if i == our_output_index:
                continue
            if o.nValue == our_output_amount:
                found += 1
        if found != 1:
            return None, "Invalid SNICKER, there are not two equal outputs."

        # To allow the acceptance callback to assess validity, we must identify
        # which input is ours and which is(are) not.
        # TODO This check may (will) change if we allow non-p2sh-pwpkh inputs:
        unsigned_index = -1
        for i, psbtinputsigninfo in enumerate(testsignresult.inputs_info):
            if psbtinputsigninfo is None:
                unsigned_index = i
                break
        assert unsigned_index != -1
        # All validation checks passed. We now check whether the
        #transaction is acceptable according to the caller:
        if not acceptance_callback([utx.vin[unsigned_index]],
                [x for i, x in enumerate(utx.vin) if i != unsigned_index],
                [utx.vout[our_output_index]],
                [x for i, x in enumerate(utx.vout) if i != our_output_index]):
            return None, "Caller rejected transaction for signing."

        # Acceptance passed, prepare the deserialized tx for signing by us:
        signresult_and_signedpsbt, err = self.sign_psbt(cpsbt.serialize(),
                                                        with_sign_result=True)
        if err:
            return None, "Unable to sign proposed PSBT, reason: " + err
        signresult, signed_psbt = signresult_and_signedpsbt
        assert signresult.num_inputs_signed == 1
        assert signresult.num_inputs_final == 2
        assert signresult.is_final
        # we now know the transaction is valid and fully signed; return to caller,
        # along with supporting data for this tx:
        return (signed_psbt.extract_transaction(), tweak_bytes, spk[1])

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
        super().__init__(storage, **kwargs)

    def _load_storage(self):
        super()._load_storage()
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
        super().save()

    @classmethod
    def initialize(cls, storage, network, max_mixdepth=2, timestamp=None,
                   write=True, **kwargs):
        super(ImportWalletMixin, cls).initialize(
            storage, network, max_mixdepth, timestamp, write=False, **kwargs)
        storage.data[cls._IMPORTED_STORAGE_KEY] = {}

        if write:
            storage.save()

    def import_private_key(self, mixdepth, wif):
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

        privkey, key_type_wif = self._ENGINE.wif_to_privkey(wif)
        # FIXME: there is no established standard for encoding key type in wif
        #if key_type is not None and key_type_wif is not None and \
        #        key_type != key_type_wif:
        #    raise WalletError("Expected key type does not match WIF type.")

        # default to wallet key type
        key_type = self.TYPE
        engine = self._ENGINES[key_type]

        if engine.key_to_script(privkey) in self._script_map:
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
            script = self.get_script_from_path(path)

        # we need to retain indices
        self._imported[path[1]][path[2]] = (b'', -1)

        del self._script_map[script]

    def _cache_imported_key(self, mixdepth, privkey, key_type, index):
        engine = self._ENGINES[key_type]
        path = (self._IMPORTED_ROOT_PATH, mixdepth, index)

        self._script_map[engine.key_to_script(privkey)] = path

        return path

    def _get_mixdepth_from_path(self, path):
        if not self._is_imported_path(path):
            return super()._get_mixdepth_from_path(path)

        assert len(path) == 3
        return path[1]

    def _get_key_from_path(self, path):
        if not self._is_imported_path(path):
            return super()._get_key_from_path(path)

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
            return super().path_repr_to_path(pathstr)

        return self._IMPORTED_ROOT_PATH, int(spath[1]), int(spath[2])

    def get_path_repr(self, path):
        if not self._is_imported_path(path):
            return super().get_path_repr(path)

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
            return super().get_details(path)
        return path[1], 'imported', path[2]

    def get_script_from_path(self, path):
        if not self._is_imported_path(path):
            return super().get_script_from_path(path)

        priv, engine = self._get_key_from_path(path)
        return engine.key_to_script(priv)


class BIP39WalletMixin(object):
    """
    Mixin to use BIP-39 mnemonic seed with BIP32Wallet
    """
    _BIP39_EXTENSION_KEY = b'seed_extension'
    MNEMONIC_LANG = 'english'

    def _load_storage(self):
        super()._load_storage()
        self._entropy_extension = self._storage.data.get(self._BIP39_EXTENSION_KEY)

    @classmethod
    def initialize(cls, storage, network, max_mixdepth=2, timestamp=None,
                   entropy=None, entropy_extension=None, write=True, **kwargs):
        super(BIP39WalletMixin, cls).initialize(
            storage, network, max_mixdepth, timestamp, entropy,
            write=False, **kwargs)
        if entropy_extension:
            # Note: future reads from storage will retrieve this data
            # as binary, so set it as binary on initialization for consistency.
            # Note that this is in contrast to the mnemonic wordlist, which is
            # handled by the mnemonic package, which returns the words as a string.
            storage.data[cls._BIP39_EXTENSION_KEY] = entropy_extension.encode("utf-8")

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
        entropy = super()._create_master_key()
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
    BIP32_EXT_ID = BaseWallet.ADDRESS_TYPE_EXTERNAL
    BIP32_INT_ID = BaseWallet.ADDRESS_TYPE_INTERNAL
    ENTROPY_BYTES = 16

    def __init__(self, storage, **kwargs):
        self._entropy = None
        # {mixdepth: {type: index}} with type being 0/1 corresponding
        #  to external/internal addresses
        self._index_cache = None
        # path is a tuple of BIP32 levels,
        # m is the master key's fingerprint
        # other levels are ints
        super().__init__(storage, **kwargs)
        assert self._index_cache is not None
        assert self._verify_entropy(self._entropy)

        _master_entropy = self._create_master_key()
        assert _master_entropy
        assert isinstance(_master_entropy, bytes)
        self._master_key = self._derive_bip32_master_key(_master_entropy)

        # used to verify paths for sanity checking and for wallet id creation
        self._key_ident = b''  # otherwise get_bip32_* won't work
        self._key_ident = self._get_key_ident()
        self._populate_script_map()
        self.disable_new_scripts = False

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
        super()._load_storage()
        self._entropy = self._storage.data[self._STORAGE_ENTROPY_KEY]

        self._index_cache = collections.defaultdict(
            lambda: collections.defaultdict(int))

        for md, data in self._storage.data[self._STORAGE_INDEX_CACHE].items():
            md = int(md)
            md_map = self._index_cache[md]
            for t, k in data.items():
                md_map[int(t)] = k

        self.max_mixdepth = max(0, 0, *self._index_cache.keys())

    def _get_key_ident(self):
        return sha256(sha256(
            self.get_bip32_priv_export(0, 0).encode('ascii')).digest())\
            .digest()[:3]

    def _populate_script_map(self):
        for md in self._index_cache:
            for address_type in (self.BIP32_EXT_ID, self.BIP32_INT_ID):
                for i in range(self._index_cache[md][address_type]):
                    path = self.get_path(md, address_type, i)
                    script = self.get_script_from_path(path)
                    self._script_map[script] = path

    def save(self):
        for md, data in self._index_cache.items():
            str_data = {}
            str_md = _int_to_bytestr(md)

            for t, k in data.items():
                str_data[_int_to_bytestr(t)] = k

            self._storage.data[self._STORAGE_INDEX_CACHE][str_md] = str_data

        super().save()

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

    @classmethod
    def _get_supported_address_types(cls):
        return (cls.BIP32_EXT_ID, cls.BIP32_INT_ID)

    def get_script_from_path(self, path):
        if not self._is_my_bip32_path(path):
            raise WalletError("unable to get script for unknown key path")

        md, address_type, index = self.get_details(path)

        if not 0 <= md <= self.max_mixdepth:
            raise WalletError("Mixdepth outside of wallet's range.")
        assert address_type in self._get_supported_address_types()

        current_index = self._index_cache[md][address_type]

        if index == current_index \
                and address_type != FidelityBondMixin.BIP32_TIMELOCK_ID:
            #special case for timelocked addresses because for them the
            #concept of a "next address" cant be used
            return self.get_new_script_override_disable(md, address_type)

        priv, engine = self._get_key_from_path(path)
        script = engine.key_to_script(priv)

        return script

    def get_path(self, mixdepth=None, address_type=None, index=None):
        if mixdepth is not None:
            assert isinstance(mixdepth, Integral)
            if not 0 <= mixdepth <= self.max_mixdepth:
                raise WalletError("Mixdepth outside of wallet's range.")

        if address_type is not None:
            if mixdepth is None:
                raise Exception("mixdepth must be set if address_type is set")

        if index is not None:
            assert isinstance(index, Integral)
            if address_type is None:
                raise Exception("address_type must be set if index is set")
            assert index <= self._index_cache[mixdepth][address_type]
            assert index < self.BIP32_MAX_PATH_LEVEL
            return tuple(chain(self._get_bip32_export_path(mixdepth, address_type),
                               (index,)))

        return tuple(self._get_bip32_export_path(mixdepth, address_type))

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

    def _get_key_from_path(self, path):
        if not self._is_my_bip32_path(path):
            raise WalletError("Invalid path, unknown root: {}".format(path))

        return self._ENGINE.derive_bip32_privkey(self._master_key, path), \
            self._ENGINE

    def _is_my_bip32_path(self, path):
        return path[0] == self._key_ident

    def get_new_script(self, mixdepth, address_type):
        if self.disable_new_scripts:
            raise RuntimeError("Obtaining new wallet addresses "
                + "disabled, due to nohistory mode")
        return self.get_new_script_override_disable(mixdepth, address_type)

    def get_new_script_override_disable(self, mixdepth, address_type):
        # This is called by get_script_from_path and calls back there. We need to
        # ensure all conditions match to avoid endless recursion.
        index = self.get_index_cache_and_increment(mixdepth, address_type)
        return self.get_script_and_update_map(mixdepth, address_type, index)

    def get_index_cache_and_increment(self, mixdepth, address_type):
        index = self._index_cache[mixdepth][address_type]
        self._index_cache[mixdepth][address_type] += 1
        return index

    def get_script_and_update_map(self, *args):
        path = self.get_path(*args)
        script = self.get_script_from_path(path)
        self._script_map[script] = path
        return script

    def get_script(self, mixdepth, address_type, index):
        path = self.get_path(mixdepth, address_type, index)
        return self.get_script_from_path(path)

    @deprecated
    def get_key(self, mixdepth, address_type, index):
        path = self.get_path(mixdepth, address_type, index)
        priv = self._ENGINE.derive_bip32_privkey(self._master_key, path)
        return hexlify(priv).decode('ascii')

    def get_bip32_priv_export(self, mixdepth=None, address_type=None):
        path = self._get_bip32_export_path(mixdepth, address_type)
        return self._ENGINE.derive_bip32_priv_export(self._master_key, path)

    def get_bip32_pub_export(self, mixdepth=None, address_type=None):
        path = self._get_bip32_export_path(mixdepth, address_type)
        return self._ENGINE.derive_bip32_pub_export(self._master_key, path)

    def _get_bip32_export_path(self, mixdepth=None, address_type=None):
        if mixdepth is None:
            assert address_type is None
            path = tuple()
        else:
            assert 0 <= mixdepth <= self.max_mixdepth
            if address_type is None:
                path = (self._get_bip32_mixdepth_path_level(mixdepth),)
            else:
                path = (self._get_bip32_mixdepth_path_level(mixdepth), address_type)

        return tuple(chain(self._get_bip32_base_path(), path))

    def _get_bip32_base_path(self):
        return self._key_ident,

    @classmethod
    def _get_bip32_mixdepth_path_level(cls, mixdepth):
        return mixdepth

    def get_next_unused_index(self, mixdepth, address_type):
        assert 0 <= mixdepth <= self.max_mixdepth

        if self._index_cache[mixdepth][address_type] >= self.BIP32_MAX_PATH_LEVEL:
            # FIXME: theoretically this should work for up to
            # self.BIP32_MAX_PATH_LEVEL * 2, no?
            raise WalletError("All addresses used up, cannot generate new ones.")

        return self._index_cache[mixdepth][address_type]

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

    def set_next_index(self, mixdepth, address_type, index, force=False):
        if not (force or index <= self._index_cache[mixdepth][address_type]):
            raise Exception("cannot advance index without force=True")
        self._index_cache[mixdepth][address_type] = index

    def get_details(self, path):
        if not self._is_my_bip32_path(path):
            raise Exception("path does not belong to wallet")
        return self._get_mixdepth_from_path(path), path[-2], path[-1]


class LegacyWallet(ImportWalletMixin, PSBTWalletMixin, BIP32Wallet):
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

class FidelityBondMixin(object):
    BIP32_TIMELOCK_ID = 2
    BIP32_BURN_ID = 3

    """
    Explaination of time number

    incrementing time numbers (0, 1, 2, 3, 4...
    will produce datetimes
    suitable for timelocking  (1st january, 1st april, 1st july ....
    this greatly reduces the number of possible timelock values
    and is helpful for recovery of funds because the wallet can search
    the only addresses corresponding to timenumbers which are far fewer

    For example, if TIMENUMBER_UNIT = 2 (i.e. every time number is two months)
    then there are 6 timelocks per year so just 600 possible
    addresses per century per pubkey. Easily searchable when recovering a
    wallet from seed phrase. Therefore the user doesn't need to store any
    dates, the seed phrase is sufficent for recovery.
    """
    #should be a factor of 12, the number of months in a year
    TIMENUMBER_UNIT = 1

    # all timelocks are 1st of the month at midnight
    TIMELOCK_DAY_AND_SHORTER = (1, 0, 0, 0, 0)
    TIMELOCK_EPOCH_YEAR = 2020
    TIMELOCK_EPOCH_MONTH = 1 #january
    MONTHS_IN_YEAR = 12

    TIMELOCK_ERA_YEARS = 30
    TIMENUMBERS_PER_PUBKEY = TIMELOCK_ERA_YEARS * MONTHS_IN_YEAR // TIMENUMBER_UNIT

    """
    As each pubkey corresponds to hundreds of addresses, to reduce load the
    given gap limit will be reduced by this factor. Also these timelocked
    addresses are never handed out to takers so there wont be a problem of
    having many used addresses with no transactions on them.
    """
    TIMELOCK_GAP_LIMIT_REDUCTION_FACTOR = 6

    _TIMELOCK_ENGINE = ENGINES[TYPE_TIMELOCK_P2WSH]

    #only one mixdepth will have fidelity bonds in it
    FIDELITY_BOND_MIXDEPTH = 0

    MERKLE_BRANCH_UNAVAILABLE = b"mbu"

    _BURNER_OUTPUT_STORAGE_KEY = b"burner-out"

    _BIP32_PUBKEY_PREFIX = "fbonds-mpk-"

    @classmethod
    def _time_number_to_timestamp(cls, timenumber):
        """
        converts a time number to a unix timestamp
        """
        if not 0 <= timenumber < cls.TIMENUMBERS_PER_PUBKEY:
            raise ValueError()
        year = cls.TIMELOCK_EPOCH_YEAR + (timenumber*cls.TIMENUMBER_UNIT) // cls.MONTHS_IN_YEAR
        month = cls.TIMELOCK_EPOCH_MONTH + (timenumber*cls.TIMENUMBER_UNIT) % cls.MONTHS_IN_YEAR
        return timegm(datetime(year, month, *cls.TIMELOCK_DAY_AND_SHORTER).timetuple())

    @classmethod
    def timestamp_to_time_number(cls, timestamp):
        """
        converts a datetime object to a time number
        """
        dt = datetime.utcfromtimestamp(timestamp)
        if (dt.month - cls.TIMELOCK_EPOCH_MONTH) % cls.TIMENUMBER_UNIT != 0:
            raise ValueError()
        day_and_shorter_tuple = (dt.day, dt.hour, dt.minute, dt.second, dt.microsecond)
        if day_and_shorter_tuple != cls.TIMELOCK_DAY_AND_SHORTER:
            raise ValueError()
        timenumber = (dt.year - cls.TIMELOCK_EPOCH_YEAR)*(cls.MONTHS_IN_YEAR //
            cls.TIMENUMBER_UNIT) + ((dt.month - cls.TIMELOCK_EPOCH_MONTH) // cls.TIMENUMBER_UNIT)
        if timenumber < 0 or timenumber > cls.TIMENUMBERS_PER_PUBKEY:
            raise ValueError("datetime out of range")
        return timenumber

    @classmethod
    def is_timelocked_path(cls, path):
        return len(path) > 4 and path[4] == cls.BIP32_TIMELOCK_ID

    def _get_key_ident(self):
        first_path = self.get_path(0, 0)
        priv, engine = self._get_key_from_path(first_path)
        pub = engine.privkey_to_pubkey(priv)
        return sha256(sha256(pub).digest()).digest()[:3]

    @classmethod
    def get_xpub_from_fidelity_bond_master_pub_key(cls, mpk):
        if mpk.startswith(cls._BIP32_PUBKEY_PREFIX):
            return mpk[len(cls._BIP32_PUBKEY_PREFIX):]
        else:
            return False

    def _populate_script_map(self):
        super()._populate_script_map()
        for md in self._index_cache:
            address_type = self.BIP32_TIMELOCK_ID
            for i in range(self._index_cache[md][address_type]):
                for timenumber in range(self.TIMENUMBERS_PER_PUBKEY):
                    path = self.get_path(md, address_type, i, timenumber)
                    script = self.get_script_from_path(path)
                    self._script_map[script] = path

    def add_utxo(self, txid, index, script, value, height=None):
        super().add_utxo(txid, index, script, value, height)
        #dont use coin control freeze if wallet readonly
        if self._storage.read_only:
            return
        path = self.script_to_path(script)
        if not self.is_timelocked_path(path):
            return
        if datetime.utcfromtimestamp(path[-1]) > datetime.now():
            #freeze utxo if its timelock is in the future
            self.disable_utxo(txid, index, disable=True)

    def get_bip32_pub_export(self, mixdepth=None, address_type=None):
        bip32_pub = super().get_bip32_pub_export(mixdepth, address_type)
        if address_type == None and mixdepth == self.FIDELITY_BOND_MIXDEPTH:
            bip32_pub = self._BIP32_PUBKEY_PREFIX + bip32_pub
        return bip32_pub

    @classmethod
    def _get_supported_address_types(cls):
        return (cls.BIP32_EXT_ID, cls.BIP32_INT_ID, cls.BIP32_TIMELOCK_ID, cls.BIP32_BURN_ID)

    def _get_key_from_path(self, path):
        if self.is_timelocked_path(path):
            key_path = path[:-1]
            locktime = path[-1]
            engine = self._TIMELOCK_ENGINE
            privkey = engine.derive_bip32_privkey(self._master_key, key_path)
            return (privkey, locktime), engine
        else:
            return super()._get_key_from_path(path)

    def get_path(self, mixdepth=None, address_type=None, index=None, timenumber=None):
        if address_type == None or address_type in (self.BIP32_EXT_ID, self.BIP32_INT_ID,
                self.BIP32_BURN_ID) or index == None:
            return super().get_path(mixdepth, address_type, index)
        elif address_type == self.BIP32_TIMELOCK_ID:
            assert timenumber != None
            timestamp = self._time_number_to_timestamp(timenumber)
            return tuple(chain(self._get_bip32_export_path(mixdepth, address_type),
                               (index, timestamp)))
        else:
            assert 0

    """
    We define a new serialization of the bip32 path to include bip65 timelock addresses
    Previously it was m/44'/1'/0'/3/0
    For a timelocked address it will be m/44'/1'/0'/3/0:13245432
    The timelock will be in unix format and added to the end with a colon ":" character
    refering to the pubkey plus the timelock value which together are needed to create the address
    """
    def get_path_repr(self, path):
        if self.is_timelocked_path(path) and len(path) == 7:
            return super().get_path_repr(path[:-1]) + ":" + str(path[-1])
        else:
            return super().get_path_repr(path)

    def path_repr_to_path(self, pathstr):
        if pathstr.find(":") == -1:
            return super().path_repr_to_path(pathstr)
        else:
            colon_chunks = pathstr.split(":")
            if len(colon_chunks) != 2:
                raise WalletError("Not a valid wallet timelock path: {}".format(pathstr))
            return tuple(chain(
                super().path_repr_to_path(colon_chunks[0]), (int(colon_chunks[1]),)))

    def get_details(self, path):
        if self.is_timelocked_path(path):
            return self._get_mixdepth_from_path(path), path[-3], path[-2]
        else:
            return super().get_details(path)

    def _get_default_used_indices(self):
        return {x: [0, 0, 0, 0] for x in range(self.max_mixdepth + 1)}

    def get_script(self, mixdepth, address_type, index, timenumber=None):
        path = self.get_path(mixdepth, address_type, index, timenumber)
        return self.get_script_from_path(path)

    def get_addr(self, mixdepth, address_type, index, timenumber=None):
        script = self.get_script(mixdepth, address_type, index, timenumber)
        return self.script_to_addr(script)

    def add_burner_output(self, path, txhex, block_height, merkle_branch,
            block_index, write=True):
        """
        merkle_branch = None means it was unavailable because of pruning
        """
        if self._BURNER_OUTPUT_STORAGE_KEY not in self._storage.data:
            self._storage.data[self._BURNER_OUTPUT_STORAGE_KEY] = {}
        path = path.encode()
        txhex = unhexlify(txhex)
        if not merkle_branch:
            merkle_branch = self.MERKLE_BRANCH_UNAVAILABLE
        self._storage.data[self._BURNER_OUTPUT_STORAGE_KEY][path] = [txhex,
            block_height, merkle_branch, block_index]
        if write:
            self._storage.save()

    def get_burner_outputs(self):
        """
        Result is a dict {path: [txhex, blockheight, merkleproof, blockindex]}
        """
        return self._storage.data.get(self._BURNER_OUTPUT_STORAGE_KEY, {})

    def set_burner_output_merkle_branch(self, path, merkle_branch):
        path = path.encode()
        self._storage.data[self._BURNER_OUTPUT_STORAGE_KEY][path][2] = \
            merkle_branch

class BIP49Wallet(BIP32PurposedWallet):
    _PURPOSE = 2**31 + 49
    _ENGINE = ENGINES[TYPE_P2SH_P2WPKH]

class BIP84Wallet(BIP32PurposedWallet):
    _PURPOSE = 2**31 + 84
    _ENGINE = ENGINES[TYPE_P2WPKH]

class SegwitLegacyWallet(ImportWalletMixin, BIP39WalletMixin, PSBTWalletMixin, SNICKERWalletMixin, BIP49Wallet):
    TYPE = TYPE_P2SH_P2WPKH

class SegwitWallet(ImportWalletMixin, BIP39WalletMixin, PSBTWalletMixin, SNICKERWalletMixin, BIP84Wallet):
    TYPE = TYPE_P2WPKH

class SegwitLegacyWalletFidelityBonds(FidelityBondMixin, SegwitLegacyWallet):
    TYPE = TYPE_SEGWIT_LEGACY_WALLET_FIDELITY_BONDS


class FidelityBondWatchonlyWallet(FidelityBondMixin, BIP49Wallet):
    TYPE = TYPE_WATCHONLY_FIDELITY_BONDS
    _ENGINE = ENGINES[TYPE_WATCHONLY_P2SH_P2WPKH]
    _TIMELOCK_ENGINE = ENGINES[TYPE_WATCHONLY_TIMELOCK_P2WSH]

    @classmethod
    def _verify_entropy(cls, ent):
        return ent[1:4] == b"pub"

    @classmethod
    def _derive_bip32_master_key(cls, master_entropy):
        return btc.bip32_deserialize(master_entropy.decode())

    def _get_bip32_export_path(self, mixdepth=None, address_type=None):
        path = super()._get_bip32_export_path(mixdepth, address_type)
        return path


WALLET_IMPLEMENTATIONS = {
    LegacyWallet.TYPE: LegacyWallet,
    SegwitLegacyWallet.TYPE: SegwitLegacyWallet,
    SegwitWallet.TYPE: SegwitWallet,
    SegwitLegacyWalletFidelityBonds.TYPE: SegwitLegacyWalletFidelityBonds,
    FidelityBondWatchonlyWallet.TYPE: FidelityBondWatchonlyWallet
}
