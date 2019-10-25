#! /usr/bin/env python
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401
'''Test creation of segwit transactions.'''

import binascii
import json
from common import make_wallets
from pprint import pformat
import jmbitcoin as btc
import pytest
from jmbase import get_log
from jmclient import load_program_config, jm_single, LegacyWallet
log = get_log()


def test_segwit_valid_txs(setup_segwit):
    with open("test/tx_segwit_valid.json", "r") as f:
        json_data = f.read()
    valid_txs = json.loads(json_data)
    for j in valid_txs:
        if len(j) < 2:
            continue
        deserialized_tx = btc.deserialize(str(j[1]))
        print(pformat(deserialized_tx))
        assert btc.serialize(deserialized_tx) == str(j[1])
        #TODO use bcinterface to decoderawtransaction
        #and compare the json values


def binarize_tx(tx):
    for o in tx['outs']:
        o['script'] = binascii.unhexlify(o['script'])
    for i in tx['ins']:
        i['outpoint']['hash'] = binascii.unhexlify(i['outpoint']['hash'])


@pytest.mark.parametrize(
    "wallet_structure, in_amt, amount, segwit_amt, segwit_ins, o_ins", [
        ([[1, 0, 0, 0, 0]], 1, 1000000, 1, [0, 1, 2], []),
        ([[4, 0, 0, 0, 1]], 3, 100000000, 1, [0, 2], [1, 3]),
        ([[4, 0, 0, 0, 1]], 3, 100000000, 1, [0, 5], [1, 2, 3, 4]),
        ([[4, 0, 0, 0, 0]], 2, 200000007, 0.3, [0, 1, 4, 5], [2, 3, 6]),
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
    MIXDEPTH = 0

    # set up wallets and inputs
    nsw_wallet_service = make_wallets(1, wallet_structure, in_amt,
                              walletclass=LegacyWallet)[0]['wallet']
    nsw_wallet_service.sync_wallet(fast=True)
    sw_wallet_service = make_wallets(1, [[len(segwit_ins), 0, 0, 0, 0]], segwit_amt)[0]['wallet']
    sw_wallet_service.sync_wallet(fast=True)

    nsw_utxos = nsw_wallet_service.get_utxos_by_mixdepth(hexfmt=False)[MIXDEPTH]
    sw_utxos = sw_wallet_service.get_utxos_by_mixdepth(hexfmt=False)[MIXDEPTH]
    assert len(o_ins) <= len(nsw_utxos), "sync failed"
    assert len(segwit_ins) <= len(sw_utxos), "sync failed"

    total_amt_in_sat = 0

    nsw_ins = {}
    for nsw_in_index in o_ins:
        total_amt_in_sat += in_amt * 10**8
        nsw_ins[nsw_in_index] = nsw_utxos.popitem()

    sw_ins = {}
    for sw_in_index in segwit_ins:
        total_amt_in_sat += int(segwit_amt * 10**8)
        sw_ins[sw_in_index] = sw_utxos.popitem()

    all_ins = {}
    all_ins.update(nsw_ins)
    all_ins.update(sw_ins)

    # sanity checks
    assert len(all_ins) == len(nsw_ins) + len(sw_ins), \
        "test broken, duplicate index"
    for k in all_ins:
        assert 0 <= k < len(all_ins), "test broken, missing input index"

    # FIXME: encoding mess, mktx should accept binary input formats
    tx_ins = []
    for i, (txid, data) in sorted(all_ins.items(), key=lambda x: x[0]):
        tx_ins.append('{}:{}'.format(binascii.hexlify(txid[0]).decode('ascii'), txid[1]))

    # create outputs
    FEE = 50000
    assert FEE < total_amt_in_sat - amount, "test broken, not enough funds"

    cj_script = nsw_wallet_service.get_new_script(MIXDEPTH + 1, True)
    change_script = nsw_wallet_service.get_new_script(MIXDEPTH, True)
    change_amt = total_amt_in_sat - amount - FEE

    tx_outs = [
        {'script': binascii.hexlify(cj_script).decode('ascii'),
         'value': amount},
        {'script': binascii.hexlify(change_script).decode('ascii'),
         'value': change_amt}]
    tx = btc.deserialize(btc.mktx(tx_ins, tx_outs))

    # import new addresses to bitcoind
    jm_single().bc_interface.import_addresses(
        [nsw_wallet_service.script_to_addr(x)
         for x in [cj_script, change_script]], nsw_wallet_service.get_wallet_name())

    # sign tx
    scripts = {}
    for nsw_in_index in o_ins:
        inp = nsw_ins[nsw_in_index][1]
        scripts[nsw_in_index] = (inp['script'], inp['value'])
    tx = nsw_wallet_service.sign_tx(tx, scripts)

    scripts = {}
    for sw_in_index in segwit_ins:
        inp = sw_ins[sw_in_index][1]
        scripts[sw_in_index] = (inp['script'], inp['value'])
    tx = sw_wallet_service.sign_tx(tx, scripts)

    print(tx)

    # push and verify
    txid = jm_single().bc_interface.pushtx(btc.serialize(tx))
    assert txid

    balances = jm_single().bc_interface.get_received_by_addr(
        [nsw_wallet_service.script_to_addr(cj_script),
         nsw_wallet_service.script_to_addr(change_script)], None)['data']
    assert balances[0]['balance'] == amount
    assert balances[1]['balance'] == change_amt


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
