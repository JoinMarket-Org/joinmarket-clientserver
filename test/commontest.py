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

data_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(data_dir))

from joinmarket import jm_single, Wallet, get_log
from joinmarket.support import chunks
from joinmarket.wallet import estimate_tx_fee
import bitcoin as btc

log = get_log()
'''This code is intended to provide
subprocess startup cross-platform with
some useful options; it could do with
some simplification/improvement.'''
import platform
OS = platform.system()
PINL = '\r\n' if OS == 'Windows' else '\n'

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
            w = TestWallet(seeds[i], max_mix_depth=5, pwd=passwords[i])
        else:
            w = Wallet(seeds[i], max_mix_depth=5)
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
