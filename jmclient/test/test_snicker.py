#! /usr/bin/env python
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401
'''Test of unusual transaction types creation and push to
network to check validity.'''

import binascii
from commontest import make_wallets, binarize_tx

import jmbitcoin as btc
import pytest
from jmbase import get_log
from jmclient import load_program_config, jm_single, sync_wallet,\
     estimate_tx_fee, SNICKERReceiver

log = get_log()
   
@pytest.mark.parametrize(
    "nw, wallet_structures, mean_amt, sdev_amt, amt, net_transfer", [
        (2, [[1, 0, 0, 0, 0]] * 2, 4, 1.4, 20000000, 1000),
    ])
def test_snicker_e2e(setup_snicker, nw, wallet_structures,
                               mean_amt, sdev_amt, amt, net_transfer):
    """ Test strategy:
    1. create two wallets.
    2. with wallet 1 (Receiver), create a single transaction
    tx1, from mixdepth 0 to 1.
    3. with wallet 2 (Proposer), take pubkey of all inputs from tx1, and use
    them to create snicker proposals to the non-change out of tx1,
    in base64 and place in proposals.txt.
    4. Receiver polls for proposals in the file manually (instead of twisted
    LoopingCall) and processes them.
    5. Check for valid final transaction with broadcast.
    """
    wallets = make_wallets(nw, wallet_structures, mean_amt, sdev_amt)
    for w in wallets.values():
        sync_wallet(w['wallet'], fast=True)
    print(wallets)
    wallet_r = wallets[0]['wallet']
    wallet_p = wallets[1]['wallet']
    # next, create a tx from the receiver wallet
    tx1_ins = wallet_r.select_utxos(0, amt)
    #as normal for a coinjoin from m 0:
    output_addr = wallet_r.get_new_addr(1, 1)
    change_addr = wallet_r.get_new_addr(0, 1)
    total = sum(x['value'] for x in tx1_ins.values())
    ins = list(tx1_ins.keys())    
    fee_est = estimate_tx_fee(len(ins), 2)
    outs = [{'value': amt,
             'address': output_addr}, {'value': total - amt - fee_est,
                                       'address': change_addr}]
    de_tx = btc.deserialize(btc.mktx(ins, outs))
    scripts = {}
    for index, ins in enumerate(de_tx['ins']):
        utxo = ins['outpoint']['hash'] + ':' + str(ins['outpoint']['index'])
        script = wallet_r.addr_to_script(tx1_ins[utxo]['address'])
        scripts[index] = (script, tx1_ins[utxo]['value'])
    binarize_tx(de_tx)
    de_tx = wallet_r.sign_tx(de_tx, scripts)
    #pushtx returns False on any error
    push_succeed = jm_single().bc_interface.pushtx(btc.serialize(de_tx))
    assert push_succeed
    print("Parent transaction OK. It was: ")
    print(de_tx)
    removed = wallet_r.remove_old_utxos(de_tx)
    txid1 = btc.txhash(btc.serialize(de_tx))
    added = wallet_r.add_new_utxos(de_tx, txid1)
    txid1_index = 0

    receiver_start_bal = sum([x['value'] for x in wallet_r.get_all_utxos().values()])

    # Now create a proposal for every input index in tx1
    # (version 1 proposals mean we source keys from the/an
    # ancestor transaction)
    binarize_tx(de_tx) # all processing from here must be binary
    propose_keys = []
    for i in de_tx['ins']:
        propose_keys.append(i['txinwitness'][1])
    # the proposer wallet needs to choose a single
    # utxo that is bigger than the output amount of tx1
    prop_m_utxos = wallet_p.get_utxos_by_mixdepth_()[0]
    prop_utxo = prop_m_utxos[list(prop_m_utxos)[0]]
    # get the private key for that utxo
    priv = binascii.unhexlify(wallet_p.get_key_from_addr(
        wallet_p.script_to_addr(prop_utxo['script'])))
    prop_input_amt = prop_utxo['value']
    # construct the arguments for the snicker proposal:
    our_input = list(prop_m_utxos)[0] # should be (txid, index)
    our_input = btc.safe_hexlify(our_input[0])+":"+str(our_input[1])
    their_input = txid1+":"+str(txid1_index)
    our_input_utxo = (prop_input_amt, prop_utxo['script'])
    fee_est = estimate_tx_fee(len(ins), 2)
    net_transfer = 1000 # something non zero to test arithmetic
    change_spk = wallet_p.get_new_script(0, 1)

    encrypted_proposals = []

    for i, p in enumerate(propose_keys):
        their_input_utxo = (de_tx['outs'][i]['value'],
                            de_tx['outs'][i]['script'])
        encrypted_proposals.append(btc.create_proposal(
            our_input, their_input,
            our_input_utxo,
            their_input_utxo,
            net_transfer,
            fee_est,
            priv,
            p,
            prop_utxo['script'],
            change_spk,
            version_byte=1)+b","+binascii.hexlify(p))
    with open("test_proposals.txt", "wb") as f:
        f.write(b"\n".join(encrypted_proposals))
    sR = SNICKERReceiver(wallet_r)
    sR.proposals_source = "test_proposals.txt" # avoid clashing with mainnet
    sR.poll_for_proposals()
    end_utxos = wallet_r.get_all_utxos()
    print("At end the receiver has these utxos: ", end_utxos)
    receiver_end_bal = sum([x['value'] for x in end_utxos.values()])
    assert receiver_end_bal == receiver_start_bal + net_transfer

@pytest.fixture(scope="module")
def setup_snicker():
    load_program_config()
