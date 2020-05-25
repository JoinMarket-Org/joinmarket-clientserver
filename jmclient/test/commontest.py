#! /usr/bin/env python
'''Some helper functions for testing'''

import os
import binascii
import random
from decimal import Decimal

from jmbase import get_log
from jmclient import (
    jm_single, open_test_wallet_maybe, estimate_tx_fee,
    BlockchainInterface, get_p2sh_vbyte, BIP32Wallet,
    SegwitLegacyWallet, WalletService)
from jmbase.support import chunks
import jmbitcoin as btc

log = get_log()
'''This code is intended to provide
subprocess startup cross-platform with
some useful options; it could do with
some simplification/improvement.'''
import platform
OS = platform.system()
PINL = '\r\n' if OS == 'Windows' else '\n'

default_max_cj_fee = (1, float('inf'))

class DummyBlockchainInterface(BlockchainInterface):
    def __init__(self):
        self.fake_query_results = None
        self.qusfail = False
        self.cbh = 1

    def get_current_block_height(self):
        self.cbh += 1
        return self.cbh

    def rpc(self, a, b):
        return None
    def sync_addresses(self, wallet):
        pass
    def sync_unspent(self, wallet):
        pass
    def import_addresses(self, addr_list, wallet_name, restart_cb=None):
        pass
    def is_address_imported(self, addr):
        pass
    
    def pushtx(self, txhex):
        print("pushing: " + str(txhex))
        return True
    
    def insert_fake_query_results(self, fqr):
        self.fake_query_results = fqr

    def setQUSFail(self, state):
        self.qusfail = state
    
    def query_utxo_set(self, txouts,includeconf=False):
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
        #our wallet utxos, faked, for podle tests: utxos are doctored (leading 'f'),
        #and the lists are (amt, age)
        wallet_outs = {'f34b635ed8891f16c4ec5b8236ae86164783903e8e8bb47fa9ef2ca31f3c2d7a:0': [10000000, 2],
                       'f780d6e5e381bff01a3519997bb4fcba002493103a198fde334fd264f9835d75:1': [20000000, 6],
                       'fe574db96a4d43a99786b3ea653cda9e4388f377848f489332577e018380cff1:0': [50000000, 3],
                       'fd9711a2ef340750db21efb761f5f7d665d94b312332dc354e252c77e9c48349:0': [50000000, 6]}
        
        if includeconf and set(txouts).issubset(set(wallet_outs)):
            #includeconf used as a trigger for a podle check;
            #here we simulate a variety of amount/age returns
            results = []
            for to in txouts:
                results.append({'value': wallet_outs[to][0],
                                'confirms': wallet_outs[to][1]})
            return results
        if txouts[0] in known_outs:
            addr = btc.pubkey_to_p2sh_p2wpkh_address(
                        known_outs[txouts[0]], get_p2sh_vbyte())
            return [{'value': 200000000,
                     'address': addr,
                     'script': btc.address_to_script(addr),
                     'confirms': 20}]
        for t in txouts:
            result_dict = {'value': 10000000000,
                           'address': "mrcNu71ztWjAQA6ww9kHiW3zBWSQidHXTQ",
                           'script': '76a91479b000887626b294a914501a4cd226b58b23598388ac'}
            if includeconf:
                result_dict['confirms'] = 20
            result.append(result_dict)        
        return result

    def estimate_fee_per_kb(self, N):
        return 30000


def create_wallet_for_sync(wallet_structure, a, **kwargs):
    #We need a distinct seed for each run so as not to step over each other;
    #make it through a deterministic hash
    seedh = btc.sha256("".join([str(x) for x in a]))[:32]
    return make_wallets(
        1, [wallet_structure], fixed_seeds=[seedh], **kwargs)[0]['wallet']


def binarize_tx(tx):
    for o in tx['outs']:
        o['script'] = binascii.unhexlify(o['script'])
    for i in tx['ins']:
        i['outpoint']['hash'] = binascii.unhexlify(i['outpoint']['hash'])


def make_sign_and_push(ins_full,
                       wallet_service,
                       amount,
                       output_addr=None,
                       change_addr=None,
                       hashcode=btc.SIGHASH_ALL,
                       estimate_fee = False):
    """Utility function for easily building transactions
    from wallets
    """
    assert isinstance(wallet_service, WalletService)
    total = sum(x['value'] for x in ins_full.values())
    ins = list(ins_full.keys())
    #random output address and change addr
    output_addr = wallet_service.get_new_addr(1, 1) if not output_addr else output_addr
    change_addr = wallet_service.get_new_addr(0, 1) if not change_addr else change_addr
    fee_est = estimate_tx_fee(len(ins), 2) if estimate_fee else 10000
    outs = [{'value': amount,
             'address': output_addr}, {'value': total - amount - fee_est,
                                       'address': change_addr}]

    de_tx = btc.deserialize(btc.mktx(ins, outs))
    scripts = {}
    for index, ins in enumerate(de_tx['ins']):
        utxo = ins['outpoint']['hash'] + ':' + str(ins['outpoint']['index'])
        script = wallet_service.addr_to_script(ins_full[utxo]['address'])
        scripts[index] = (script, ins_full[utxo]['value'])
    binarize_tx(de_tx)
    de_tx = wallet_service.sign_tx(de_tx, scripts, hashcode=hashcode)
    #pushtx returns False on any error
    push_succeed = jm_single().bc_interface.pushtx(btc.serialize(de_tx))
    if push_succeed:
        txid = btc.txhash(btc.serialize(de_tx))
        # in normal operation this happens automatically
        # but in some tests there is no monitoring loop:
        wallet_service.process_new_tx(de_tx, txid)
        return txid
    else:
        return False

def make_wallets(n,
                 wallet_structures=None,
                 mean_amt=1,
                 sdev_amt=0,
                 start_index=0,
                 fixed_seeds=None,
                 wallet_cls=SegwitLegacyWallet,
                 mixdepths=5,
                 populate_internal=False):
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
        seeds = chunks(binascii.hexlify(os.urandom(BIP32Wallet.ENTROPY_BYTES * n)).decode('ascii'),
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
    current_height = jm_single().bc_interface.rpc("getblockchaininfo", [])["blocks"]
    until_bip65_activation = BIP65Height - current_height + 1
    if until_bip65_activation > 0:
        jm_single().bc_interface.tick_forward_chain(until_bip65_activation)

