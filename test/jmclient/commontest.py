#! /usr/bin/env python
'''Some helper functions for testing'''

import os
import random
from decimal import Decimal
from typing import Callable, List, Optional, Set, Tuple, Union

import jmbitcoin as btc
from jmbase import (get_log, hextobin, bintohex, dictchanger)
from jmbase.support import chunks
from jmclient import (
    jm_single, open_test_wallet_maybe, estimate_tx_fee,
    BlockchainInterface, BIP32Wallet, BaseWallet,
    SegwitWallet, WalletService, BTC_P2SH_P2WPKH)

log = get_log()
'''This code is intended to provide
subprocess startup cross-platform with
some useful options; it could do with
some simplification/improvement.'''
import platform
OS = platform.system()
PINL = '\r\n' if OS == 'Windows' else '\n'

default_max_cj_fee = (1, float('inf'))

# callbacks for making transfers in-script with direct_send:
def dummy_accept_callback(tx, destaddr, actual_amount, fee_est,
                          custom_change_addr):
    return True

def dummy_info_callback(msg):
    pass

class DummyBlockchainInterface(BlockchainInterface):

    def __init__(self) -> None:
        self.fake_query_results = None
        self.qusfail = False
        self.cbh = 1
        self.default_confs = 20
        self.confs_for_qus = {}

    # Dummy abstract method overrides of base class
    def is_address_imported(self, addr: str) -> bool:
        pass
    def is_address_labeled(self, utxo: dict, walletname: str) -> bool:
        pass
    def import_addresses_if_needed(self, addresses: Set[str], wallet_name: str) -> bool:
        pass
    def import_addresses(self, addr_list: List[str], wallet_name: str,
                         restart_cb: Callable[[str], None] = None) -> None:
        pass
    def list_transactions(self, num: int, skip: int = 0) -> List[dict]:
        pass
    def get_deser_from_gettransaction(self, rpcretval: dict) -> Optional[btc.CMutableTransaction]:
        pass
    def get_transaction(self, txid: bytes) -> Optional[dict]:
        pass
    def get_block(self, blockheight: int) -> Optional[str]:
        pass
    def get_best_block_hash(self) -> str:
        pass
    def get_best_block_median_time(self) -> int:
        pass
    def get_block_height(self, blockhash: str) -> int:
        pass
    def get_block_time(self, blockhash: str) -> int:
        pass
    def get_block_hash(self, height: int) -> str:
        pass
    def get_tx_merkle_branch(self, txid: str,
                             blockhash: Optional[str] = None) -> bytes:
        pass
    def verify_tx_merkle_branch(self, txid: str, block_height: int,
                                merkle_branch: bytes) -> bool:
        pass
    def listaddressgroupings(self) -> list:
        pass
    def listunspent(self, minconf: Optional[int] = None) -> List[dict]:
        pass
    def testmempoolaccept(self, rawtx: str) -> bool:
        pass
    def _get_mempool_min_fee(self) -> Optional[int]:
        pass
    def _estimate_fee_basic(self, conf_target: int) -> Optional[Tuple[int, int]]:
        pass
    def get_wallet_rescan_status(self) -> Tuple[bool, Optional[Decimal]]:
        pass
    def rescanblockchain(self, start_height: int, end_height: Optional[int] = None) -> None:
        pass
    def mempoolfullrbf(self) -> bool:
        pass

    def get_current_block_height(self) -> int:
        return 10**6

    def pushtx(self, txbin: bytes) -> bool:
        return True
    
    def insert_fake_query_results(self, fqr: List[dict]) -> None:
        self.fake_query_results = fqr

    def setQUSFail(self, state: bool) -> None:
        self.qusfail = state

    def set_confs(self, confs_utxos) -> None:
        # we hook specific confirmation results
        # for specific utxos so that query_utxo_set
        # can return a non-constant fake value.
        self.confs_for_qus.update(confs_utxos)

    def reset_confs(self) -> None:
        self.confs_for_qus = {}

    def query_utxo_set(self,
                       txouts: Union[Tuple[bytes, int], List[Tuple[bytes, int]]],
                       includeconfs: bool = False,
                       include_mempool: bool = True) -> List[Optional[dict]]:
        if self.qusfail:
            #simulate failure to find the utxo
            return [None]
        if self.fake_query_results:
            result = []
            for x in self.fake_query_results:
                for y in txouts:
                    if y == x['utxo']:
                        result.append(x)
            return result
        result = []
        #external maker utxos
        known_outs = {"03243f4a659e278a1333f8308f6aaf32db4692ee7df0340202750fd6c09150f6:1": "03a2d1cbe977b1feaf8d0d5cc28c686859563d1520b28018be0c2661cf1ebe4857",
                      "498faa8b22534f3b443c6b0ce202f31e12f21668b4f0c7a005146808f250d4c3:0": "02b4b749d54e96b04066b0803e372a43d6ffa16e75a001ae0ed4b235674ab286be",
                      "3f3ea820d706e08ad8dc1d2c392c98facb1b067ae4c671043ae9461057bd2a3c:1": "023bcbafb4f68455e0d1d117c178b0e82a84e66414f0987453d78da034b299c3a9"}
        known_outs = dictchanger(known_outs)
        #our wallet utxos, faked, for podle tests: utxos are doctored (leading 'f'),
        #and the lists are (amt, age)
        wallet_outs = {'f34b635ed8891f16c4ec5b8236ae86164783903e8e8bb47fa9ef2ca31f3c2d7a:0': [10000000, 2],
                       'f780d6e5e381bff01a3519997bb4fcba002493103a198fde334fd264f9835d75:1': [20000000, 6],
                       'fe574db96a4d43a99786b3ea653cda9e4388f377848f489332577e018380cff1:0': [50000000, 3],
                       'fd9711a2ef340750db21efb761f5f7d665d94b312332dc354e252c77e9c48349:0': [50000000, 6]}
        wallet_outs = dictchanger(wallet_outs)
        
        if includeconfs and set(txouts).issubset(set(wallet_outs)):
            #includeconfs used as a trigger for a podle check;
            #here we simulate a variety of amount/age returns
            results = []
            for to in txouts:
                results.append({'value': wallet_outs[to][0],
                                'confirms': wallet_outs[to][1]})
            return results
        if txouts[0] in known_outs:
            scr = BTC_P2SH_P2WPKH.pubkey_to_script(known_outs[txouts[0]])
            addr = btc.CCoinAddress.from_scriptPubKey(scr)
            return [{'value': 200000000,
                     'address': addr,
                     'script': scr,
                     'confirms': self.default_confs}]
        for t in txouts:
            result_dict = {'value': 200000000,
                           'address': "mrcNu71ztWjAQA6ww9kHiW3zBWSQidHXTQ",
                           'script': hextobin('76a91479b000887626b294a914501a4cd226b58b23598388ac')}
            if includeconfs:
                if t in self.confs_for_qus:
                    confs = self.confs_for_qus[t]
                else:
                    confs = self.default_confs
                result_dict['confirms'] = confs
            result.append(result_dict)        
        return result

    def estimate_fee_per_kb(self, tx_fees: int) -> int:
        return 30000


def create_wallet_for_sync(wallet_structure, a, **kwargs):
    #We need a distinct seed for each run so as not to step over each other;
    #make it through a deterministic hash of all parameters including optionals.
    preimage = "".join([str(x) for x in a] + [str(y) for y in kwargs.values()]).encode("utf-8")
    print("using preimage: ", preimage)
    seedh = bintohex(btc.Hash(preimage))[:32]
    return make_wallets(
        1, [wallet_structure], fixed_seeds=[seedh], **kwargs)[0]['wallet']

def make_sign_and_push(ins_full,
                       wallet_service,
                       amount,
                       output_addr=None,
                       change_addr=None,
                       hashcode=btc.SIGHASH_ALL,
                       estimate_fee = False):
    """Utility function for easily building transactions
    from wallets.
    `ins_full` should be a list of dicts in format returned
    by wallet.select_utxos:
    {(txid, index): {"script":..,"value":..,"path":..}}
    ... although the path is not used.
    The "script" and "value" data is used to allow signing.
    """
    assert isinstance(wallet_service, WalletService)
    total = sum(x['value'] for x in ins_full.values())
    ins = list(ins_full.keys())
    #random output address and change addr
    output_addr = wallet_service.get_new_addr(1, BaseWallet.ADDRESS_TYPE_INTERNAL) if not output_addr else output_addr
    change_addr = wallet_service.get_new_addr(0, BaseWallet.ADDRESS_TYPE_INTERNAL) if not change_addr else change_addr
    fee_est = estimate_tx_fee(len(ins), 2) if estimate_fee else 10000
    outs = [{'value': amount,
             'address': output_addr}, {'value': total - amount - fee_est,
                                       'address': change_addr}]

    tx = btc.mktx(ins, outs)
    scripts = {}
    for i, j in enumerate(ins):
        scripts[i] = (ins_full[j]["script"], ins_full[j]["value"])

    success, msg = wallet_service.sign_tx(tx, scripts, hashcode=hashcode)
    if not success:
        return False
    #pushtx returns False on any error
    push_succeed = jm_single().bc_interface.pushtx(tx.serialize())
    if push_succeed:
        # in normal operation this happens automatically
        # but in some tests there is no monitoring loop:
        wallet_service.process_new_tx(tx)
        return tx.GetTxid()[::-1]
    else:
        return False

def make_wallets(n,
                 wallet_structures=None,
                 mean_amt=1,
                 sdev_amt=0,
                 start_index=0,
                 fixed_seeds=None,
                 wallet_cls=SegwitWallet,
                 mixdepths=5,
                 populate_internal=BaseWallet.ADDRESS_TYPE_EXTERNAL):
    '''n: number of wallets to be created
       wallet_structure: array of n arrays , each subarray
       specifying the number of addresses to be populated with coins
       at each depth (for now, this will only populate coins into 'receive' addresses)
       mean_amt: the number of coins (in btc units) in each address as above
       sdev_amt: if randomness in amouts is desired, specify here.
       Returns: a dict of dicts of form {0:{'seed':seed,'wallet':Wallet object},1:..,}
       '''
    # FIXME: this is basically the same code as test/common.py
    assert mixdepths > 0
    if len(wallet_structures) != n:
        raise Exception("Number of wallets doesn't match wallet structures")
    if not fixed_seeds:
        seeds = chunks(bintohex(os.urandom(
            BIP32Wallet.ENTROPY_BYTES * n)),
            BIP32Wallet.ENTROPY_BYTES * 2)
    else:
        seeds = fixed_seeds
    wallets = {}
    for i in range(n):
        assert len(seeds[i]) == BIP32Wallet.ENTROPY_BYTES * 2

        w = open_test_wallet_maybe(seeds[i], seeds[i], mixdepths - 1,
                                   test_wallet_cls=wallet_cls)
        wallet_service = WalletService(w)
        wallets[i + start_index] = {'seed': seeds[i],
                                    'wallet': wallet_service}
        if mean_amt != 0:
            for j in range(mixdepths):
                for k in range(wallet_structures[i][j]):
                    deviation = sdev_amt * random.random()
                    amt = mean_amt - sdev_amt / 2.0 + deviation
                    if amt < 0: amt = 0.001
                    amt = float(Decimal(amt).quantize(Decimal(10)**-8))
                    jm_single().bc_interface.grab_coins(wallet_service.get_new_addr(
                        j, populate_internal), amt)
    return wallets


def interact(process, inputs, expected):
    if len(inputs) != len(expected):
        raise Exception("Invalid inputs to interact()")
    for i, inp in enumerate(inputs):
        process.expect(expected[i])
        process.sendline(inp)

def ensure_bip65_activated():
    #on regtest bip65 activates on height 1351
    #https://github.com/bitcoin/bitcoin/blob/1d1f8bbf57118e01904448108a104e20f50d2544/src/chainparams.cpp#L262
    BIP65Height = 1351
    current_height = jm_single().bc_interface.get_current_block_height()
    until_bip65_activation = BIP65Height - current_height + 1
    if until_bip65_activation > 0:
        jm_single().bc_interface.tick_forward_chain(until_bip65_activation)

