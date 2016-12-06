#! /usr/bin/env python
from __future__ import absolute_import
'''Some helper functions for testing'''

import sys
import os
import time
import binascii
import pexpect
import random
import subprocess
import platform
from decimal import Decimal

from jmclient import (jm_single, Wallet, get_log, estimate_tx_fee,
                      BlockchainInterface)
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

class DummyBlockchainInterface(BlockchainInterface):
    def __init__(self):
        self.fake_query_results = None
        self.qusfail = False

    def sync_addresses(self, wallet):
        pass
    def sync_unspent(self, wallet):
        pass
    def add_tx_notify(self,
                      txd,
                      unconfirmfun,
                      confirmfun,
                      notifyaddr,
                      timeoutfun=None):
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
            return [{'value': 200000000,
                    'address': btc.pubkey_to_address(known_outs[txouts[0]], magicbyte=0x6f),
                    'confirms': 20}]
        for t in txouts:
            result_dict = {'value': 10000000000,
                        'address': "mrcNu71ztWjAQA6ww9kHiW3zBWSQidHXTQ"}
            if includeconf:
                result_dict['confirms'] = 20
            result.append(result_dict)        
        return result

    def estimate_fee_per_kb(self, N):
        return 30000

class TestWallet(Wallet):
    """Implementation of wallet
    that allows passing in a password
    for removal of command line interrupt.
    """

    def __init__(self,
                 seedarg,
                 max_mix_depth=2,
                 gaplimit=6,
                 extend_mixdepth=False,
                 storepassword=False,
                 pwd=None):
        self.given_pwd = pwd
        super(TestWallet, self).__init__(seedarg,
                                     max_mix_depth,
                                     gaplimit,
                                     extend_mixdepth,
                                     storepassword)

    def read_wallet_file_data(self, filename):
        return super(TestWallet, self).read_wallet_file_data(
            filename, self.given_pwd)

def make_sign_and_push(ins_full,
                       wallet,
                       amount,
                       output_addr=None,
                       change_addr=None,
                       hashcode=btc.SIGHASH_ALL,
                       estimate_fee = False):
    """Utility function for easily building transactions
    from wallets
    """
    total = sum(x['value'] for x in ins_full.values())
    ins = ins_full.keys()
    #random output address and change addr
    output_addr = wallet.get_new_addr(1, 1) if not output_addr else output_addr
    change_addr = wallet.get_new_addr(1, 0) if not change_addr else change_addr
    fee_est = estimate_tx_fee(len(ins), 2) if estimate_fee else 10000
    outs = [{'value': amount,
             'address': output_addr}, {'value': total - amount - fee_est,
                                       'address': change_addr}]

    tx = btc.mktx(ins, outs)
    de_tx = btc.deserialize(tx)
    for index, ins in enumerate(de_tx['ins']):
        utxo = ins['outpoint']['hash'] + ':' + str(ins['outpoint']['index'])
        addr = ins_full[utxo]['address']
        priv = wallet.get_key_from_addr(addr)
        if index % 2:
            priv = binascii.unhexlify(priv)
        tx = btc.sign(tx, index, priv, hashcode=hashcode)
    #pushtx returns False on any error
    print btc.deserialize(tx)
    push_succeed = jm_single().bc_interface.pushtx(tx)
    if push_succeed:
        return btc.txhash(tx)
    else:
        return False

def local_command(command, bg=False, redirect=''):
    if redirect == 'NULL':
        if OS == 'Windows':
            command.append(' > NUL 2>&1')
        elif OS == 'Linux':
            command.extend(['>', '/dev/null', '2>&1'])
        else:
            print "OS not recognised, quitting."
    elif redirect:
        command.extend(['>', redirect])

    if bg:
        #using subprocess.PIPE seems to cause problems
        FNULL = open(os.devnull, 'w')
        return subprocess.Popen(command,
                                stdout=FNULL,
                                stderr=subprocess.STDOUT,
                                close_fds=True)
    else:
        #in case of foreground execution, we can use the output; if not
        #it doesn't matter
        return subprocess.check_output(command)


def make_wallets(n,
                 wallet_structures=None,
                 mean_amt=1,
                 sdev_amt=0,
                 start_index=0,
                 fixed_seeds=None,
                 test_wallet=False,
                 passwords=None):
    '''n: number of wallets to be created
       wallet_structure: array of n arrays , each subarray
       specifying the number of addresses to be populated with coins
       at each depth (for now, this will only populate coins into 'receive' addresses)
       mean_amt: the number of coins (in btc units) in each address as above
       sdev_amt: if randomness in amouts is desired, specify here.
       Returns: a dict of dicts of form {0:{'seed':seed,'wallet':Wallet object},1:..,}
       Default Wallet constructor is joinmarket.Wallet, else use TestWallet,
       which takes a password parameter as in the list passwords.
       '''
    if len(wallet_structures) != n:
        raise Exception("Number of wallets doesn't match wallet structures")
    if not fixed_seeds:
        seeds = chunks(binascii.hexlify(os.urandom(15 * n)), 15 * 2)
    else:
        seeds = fixed_seeds
    wallets = {}
    for i in range(n):
        if test_wallet:
            w = Wallet(seeds[i], passwords[i], max_mix_depth=5)
        else:
            w = Wallet(seeds[i], None, max_mix_depth=5)
        wallets[i + start_index] = {'seed': seeds[i],
                                    'wallet': w}
        for j in range(5):
            for k in range(wallet_structures[i][j]):
                deviation = sdev_amt * random.random()
                amt = mean_amt - sdev_amt / 2.0 + deviation
                if amt < 0: amt = 0.001
                amt = float(Decimal(amt).quantize(Decimal(10)**-8))
                jm_single().bc_interface.grab_coins(
                    wallets[i + start_index]['wallet'].get_external_addr(j),
                    amt)
            #reset the index so the coins can be seen if running in same script
            wallets[i + start_index]['wallet'].index[j][0] -= wallet_structures[i][j]
    return wallets


def interact(process, inputs, expected):
    if len(inputs) != len(expected):
        raise Exception("Invalid inputs to interact()")
    for i, inp in enumerate(inputs):
        process.expect(expected[i])
        process.sendline(inp)
