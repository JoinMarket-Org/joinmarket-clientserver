#! /usr/bin/env python
from __future__ import absolute_import
'''Test creation of segwit transactions.'''

import sys
import os
import time
import binascii
import json
from common import make_wallets
from pprint import pformat
import jmbitcoin as btc
import pytest
from jmclient import (load_program_config, jm_single, get_p2pk_vbyte,
                      get_log, get_p2sh_vbyte, Wallet)
log = get_log()


def test_segwit_valid_txs(setup_segwit):
    with open("test/tx_segwit_valid.json", "r") as f:
        json_data = f.read()
    valid_txs = json.loads(json_data)
    for j in valid_txs:
        if len(j) < 2:
            continue
        deserialized_tx = btc.deserialize(str(j[1]))
        print pformat(deserialized_tx)
        assert btc.serialize(deserialized_tx) == str(j[1])
        #TODO use bcinterface to decoderawtransaction
        #and compare the json values


def get_utxo_from_txid(txid, addr):
    """Given a txid and an address for one of the outputs,
    return "txid:n" where n is the index of the output
    """
    rawtx = jm_single().bc_interface.rpc("getrawtransaction", [txid, 1])
    ins = []
    for u in rawtx["vout"]:
        if u["scriptPubKey"]["addresses"][0] == addr:
            ins.append(txid + ":" + str(u["n"]))
    assert len(ins) == 1
    return ins[0]


def make_sign_and_push(ins_sw,
                       wallet,
                       amount,
                       other_ins=None,
                       output_addr=None,
                       change_addr=None,
                       hashcode=btc.SIGHASH_ALL):
    """A more complicated version of the function in test_tx_creation;
    will merge to this one once finished.
    ins_sw have this structure:
    {"txid:n":(amount, priv, index), "txid2:n2":(amount2, priv2, index2), ..}
    if other_ins is not None, it has the same format, 
    these inputs are assumed to be plain p2pkh.
    All of these inputs in these two sets will be consumed.
    They are ordered according to the "index" fields (to allow testing
    of specific ordering)
    It's assumed that they contain sufficient coins to satisy the
    required output specified in "amount", plus some extra for fees and a
    change output.
    The output_addr and change_addr, if None, are taken from the wallet
    and are ordinary p2pkh outputs.
    All amounts are in satoshis and only converted to btc for grab_coins
    """
    #total value of all inputs
    print ins_sw
    print other_ins
    total = sum([x[0] for x in ins_sw.values()])
    total += sum([x[0] for x in other_ins.values()])
    #construct the other inputs
    ins1 = other_ins
    ins1.update(ins_sw)
    ins1 = sorted(ins1.keys(), key=lambda k: ins1[k][2])
    #random output address and change addr
    output_addr = wallet.get_new_addr(1, 1) if not output_addr else output_addr
    change_addr = wallet.get_new_addr(1, 0) if not change_addr else change_addr
    outs = [{'value': amount,
             'address': output_addr}, {'value': total - amount - 10000,
                                       'address': change_addr}]
    tx = btc.mktx(ins1, outs)
    de_tx = btc.deserialize(tx)
    for index, ins in enumerate(de_tx['ins']):
        utxo = ins['outpoint']['hash'] + ':' + str(ins['outpoint']['index'])
        temp_ins = ins_sw if utxo in ins_sw.keys() else other_ins
        amt, priv, n = temp_ins[utxo]
        temp_amt = amt if utxo in ins_sw.keys() else None
        #for better test code coverage
        print "signing tx index: " + str(index) + ", priv: " + priv
        if index % 2:
            priv = binascii.unhexlify(priv)
        ms = "other" if not temp_amt else "amount: " + str(temp_amt)
        print ms
        tx = btc.sign(tx, index, priv, hashcode=hashcode, amount=temp_amt)
    print pformat(btc.deserialize(tx))
    txid = jm_single().bc_interface.pushtx(tx)
    time.sleep(3)
    received = jm_single().bc_interface.get_received_by_addr(
        [output_addr], None)['data'][0]['balance']
    #check coins were transferred as expected
    assert received == amount
    #pushtx returns False on any error
    return txid


@pytest.mark.parametrize(
    "wallet_structure, in_amt, amount, segwit_amt, segwit_ins, o_ins", [
        ([[1, 0, 0, 0, 0]], 1, 1000000, 1, [0, 1, 2], []),
        ([[4, 0, 0, 0, 1]], 3, 100000000, 1, [0, 2], [1, 3]),
        ([[4, 0, 0, 0, 1]], 3, 100000000, 1, [0, 5], [1, 2, 3, 4]),
        ([[2, 0, 0, 0, 2]], 2, 200000007, 0.3, [0, 1, 4, 5], [2, 3, 6]),
    ])
def test_spend_p2sh_p2wpkh_multi(setup_segwit, wallet_structure, in_amt, amount,
                                 segwit_amt, segwit_ins, o_ins):
    """Creates a wallet from which non-segwit inputs/
    outputs can be created, constructs one or more
    p2wpkh in p2sh spendable utxos (by paying into the
    corresponding address) and tests spending them
    in combination.
    wallet_structure is in accordance with commontest.make_wallets, see docs there
    in_amt is the amount to pay into each address into the wallet (non-segwit adds)
    amount (in satoshis) is how much we will pay to the output address
    segwit_amt in BTC is the amount we will fund each new segwit address with
    segwit_ins is a list of input indices (where to place the funding segwit utxos)
    other_ins is a list of input indices (where to place the funding non-sw utxos)
    """
    wallet = make_wallets(1, wallet_structure, in_amt, walletclass=Wallet)[0]['wallet']
    jm_single().bc_interface.sync_wallet(wallet)
    other_ins = {}
    ctr = 0
    for k, v in wallet.unspent.iteritems():
        #only extract as many non-segwit utxos as we need;
        #doesn't matter which they are
        if ctr == len(o_ins):
            break
        other_ins[k] = (v["value"], wallet.get_key_from_addr(v["address"]),
                        o_ins[ctr])
        ctr += 1
    ins_sw = {}
    for i in range(len(segwit_ins)):
        #build segwit ins from "deterministic-random" keys;
        #intended to be the same for each run with the same parameters
        seed = json.dumps([i, wallet_structure, in_amt, amount, segwit_ins,
                           other_ins])
        priv = btc.sha256(seed) + "01"
        pub = btc.privtopub(priv)
        #magicbyte is testnet p2sh
        addr1 = btc.pubkey_to_p2sh_p2wpkh_address(pub, magicbyte=196)
        print "got address for p2shp2wpkh: " + addr1
        txid = jm_single().bc_interface.grab_coins(addr1, segwit_amt)
        #TODO - int cast, fix?
        ins_sw[get_utxo_from_txid(txid, addr1)] = (int(segwit_amt * 100000000),
                                                   priv, segwit_ins[i])
    #make_sign_and_push will sanity check the received amount is correct
    txid = make_sign_and_push(ins_sw, wallet, amount, other_ins)
    #will always be False if it didn't push.
    assert txid


@pytest.fixture(scope="module")
def setup_segwit():
    load_program_config()
    jm_single().bc_interface.tick_forward_chain_interval = 1


'''
Examples of valid segwit from the json with parsing

["Valid P2WPKH (Private key of segwit tests is 
L5AQtV2HDm4xGsseLokK2VAT2EtYKcTm3c7HwqnJBFt9LdaQULsM)"],

[[["0000000000000000000000000000000000000000000000000000000000000100", 
0, "0x00 0x14 0x4c9c3dfac4207d5d8cb89df5722cb3d712385e3f", 1000]],

"01000000
00
01
ins start
in num
01
in txid
000100000000000000000000000000000000000000000000000000000000000000
in txid out index
00000000
sequence
ffffffff
num outs
01
amount
e803000000000000
script
1976a9144c9c3dfac4207d5d8cb89df5722cb3d712385e3f88ac
(number of witnesses = 1, implied by txin length)
witnesses : number 1
item count for this witness
02
signature length
48
signature + hashcode 01
3045022100cfb07164b36ba64c1b1e8c7720a56ad64d96f6ef332d3d37f9cb3c96477dc4450220
0a464cd7a9cf94cd70f66ce4f4f0625ef650052c7afcfe29d7d7e01830ff91ed01
pubkey length
21
pubkey
03596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71
locktime
00000000", "P2SH,WITNESS"],
'''
'''
P2WSH example
01000000
00
01
01
00010000000000000000000000000000000000000000000000000000000000000000
000000
ffffffff
01
amount
e803000000000000
length 25
19
OP_DUP OP_HASH160
76a9
hash length
14
ripemd160(sha256(pubkey))
4c9c3dfac4207d5d8cb89df5722cb3d712385e3f
OP_EQUALVERIFY OP_CHECKSIG
88ac
num items in witness 1
02
length of sig
48
3045022100aa5d8aa40a90f23ce2c3d11bc845ca4a12acd99cbea37de6b9f6d86edebba8cb0220
22dedc2aa0a255f74d04c0b76ece2d7c691f9dd11a64a8ac49f62a99c3a05f9d01
length of scriptSig
23
length of pubkey
21
pubkey
03596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71
CHECKSIG
ac
locktime
00000000
    
"
Example with SIGHASH_SINGLE|SIGHASH_ANYONECANPAY
version
01000000
marker
00
flag
01
num in
04
in1 txid
0001000000000000000000000000000000000000000000000000000000000000
in 1 index
0200000000
in 1 sequence
ffffffff
0001000000000000000000000000000000000000000000000000000000000000
0100000000
ffffffff
0001000000000000000000000000000000000000000000000000000000000000
0000000000
ffffffff
0001000000000000000000000000000000000000000000000000000000000000
0300000000
ffffffff
num outs
05
out 0 amount
540b000000000000
length
01
OP_TRUE - looks like anyonecanspend
51
out 1
amount
d007000000000000
length
01
OP_TRUE
51
out 2
amount
8403000000000000
length
01
OP_TRUE
51
out 3
amount
3c0f000000000000
length
01
OP_TRUE
51
out 4
amount
2c01000000000000
length
01
OP_TRUE
51
witness starts here
first txin witness - none
00
second witness item
num items in witness
02
sig length
48
signature
304502210092f4777a0f17bf5aeb8ae768dec5f2c14feabf9d1fe2c89c78dfed0f13fdb869
02206da90a86042e252bcd1e80a168c719e4a1ddcc3cebea24b9812c5453c79107e983 - SIGHASH_SINGLE|SIGHASH_ANYONECANPAY
length pubkey
21
pubkey
03596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71
locktime
000000000000


"01000000
00
01
01
0001000000000000000000000000000000000000000000000000000000000000
0000000000
ffffffff
01
e803000000000000
19
76a9
14
4c9c3dfac4207d5d8cb89df5722cb3d712385e3f
88
ac
02
48
3045022100aa5d8aa40a90f23ce2c3d11bc845ca4a12acd99cbea37de6b9f6d86edebba8cb
022022dedc2aa0a255f74d04c0b76ece2d7c691f9dd11a64a8ac49f62a99c3a05f9d01
23
21
03596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71
ac
00000000", "P2SH,WITNESS"],


["Valid P2SH(P2WPKH)"],
[[["0000000000000000000000000000000000000000000000000000000000000100", 
0, 
**NOTE: this hash160 is of 00 14 <hash160 of pubkey>** - how P2SHP2WPKH works
"HASH160 0x14 0xfe9c7dacc9fcfbf7e3b7d5ad06aa2b28c5a7b7e3 EQUAL", 1000]],

"
01000000
00
01
01
0001000000000000000000000000000000000000000000000000000000000000
00000000
length of scriptsig
17
length of item
16
witness versoin byte
00
length of item
14
hash160 - of PUBKEY
4c9c3dfac4207d5d8cb89df5722cb3d712385e3f
sequence
ffffffff
num outs
01
amount
e803000000000000
output
1976a9144c9c3dfac4207d5d8cb89df5722cb3d712385e3f88ac
witness for input 0
num items
02
48
3045022100cfb07164b36ba64c1b1e8c7720a56ad64d96f6ef332d3d37f9cb3c96477dc445
02200a464cd7a9cf94cd70f66ce4f4f0625ef650052c7afcfe29d7d7e01830ff91ed01
len pub
21
pub
03596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71
locktime
00000000", "P2SH,WITNESS"],
'''
