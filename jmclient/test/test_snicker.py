#! /usr/bin/env python
'''Test of SNICKER functionality using Joinmarket
   wallets as defined in jmclient.wallet.'''

from commontest import make_wallets, dummy_accept_callback, dummy_info_callback

import jmbitcoin as btc
import pytest
from jmbase import get_log, bintohex
from jmclient import (load_test_config, estimate_tx_fee, SNICKERReceiver,
                      direct_send)

log = get_log()

@pytest.mark.parametrize(
    "nw, wallet_structures, mean_amt, sdev_amt, amt, net_transfer", [
        (2, [[1, 0, 0, 0, 0]] * 2, 4, 0, 20000000, 1000),
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
        w['wallet'].sync_wallet(fast=True)
    print(wallets)
    wallet_r = wallets[0]['wallet']
    wallet_p = wallets[1]['wallet']
    # next, create a tx from the receiver wallet
    our_destn_script = wallet_r.get_new_script(1, 1)
    tx = direct_send(wallet_r, btc.coins_to_satoshi(0.3), 0,
                     wallet_r.script_to_addr(our_destn_script),
                     accept_callback=dummy_accept_callback,
                     info_callback=dummy_info_callback,
                     return_transaction=True)    
    
    assert tx, "Failed to spend from receiver wallet"
    print("Parent transaction OK. It was: ")
    print(btc.hrt(tx))
    wallet_r.process_new_tx(tx)
    # we must identify the receiver's output we're going to use;
    # it can be destination or change, that's up to the proposer
    # to guess successfully; here we'll just choose index 0.
    txid1 = tx.GetTxid()[::-1]
    txid1_index = 0

    receiver_start_bal = sum([x['value'] for x in wallet_r.get_all_utxos(
        ).values()])

    # Now create a proposal for every input index in tx1
    # (version 1 proposals mean we source keys from the/an
    # ancestor transaction)
    propose_keys = []
    for i in range(len(tx.vin)):
        # todo check access to pubkey
        sig, pub = [a for a in iter(tx.wit.vtxinwit[i].scriptWitness)]
        propose_keys.append(pub)
    # the proposer wallet needs to choose a single
    # utxo that is bigger than the output amount of tx1
    prop_m_utxos = wallet_p.get_utxos_by_mixdepth()[0]
    prop_utxo = prop_m_utxos[list(prop_m_utxos)[0]]
    # get the private key for that utxo
    priv = wallet_p.get_key_from_addr(
        wallet_p.script_to_addr(prop_utxo['script']))
    prop_input_amt = prop_utxo['value']
    # construct the arguments for the snicker proposal:
    our_input = list(prop_m_utxos)[0] # should be (txid, index)
    their_input = (txid1, txid1_index)
    our_input_utxo = btc.CMutableTxOut(prop_utxo['value'],
                                       prop_utxo['script'])
    fee_est = estimate_tx_fee(len(tx.vin), 2)
    change_spk = wallet_p.get_new_script(0, 1)

    encrypted_proposals = []

    for p in propose_keys:
        # TODO: this can be a loop over all outputs,
        # not just one guessed output, if desired.
        encrypted_proposals.append(
            wallet_p.create_snicker_proposal(
            our_input, their_input,
            our_input_utxo,
            tx.vout[txid1_index],
            net_transfer,
            fee_est,
            priv,
            p,
            prop_utxo['script'],
            change_spk,
            version_byte=1) + b"," + bintohex(p).encode('utf-8'))
    with open("test_proposals.txt", "wb") as f:
        f.write(b"\n".join(encrypted_proposals))
    sR = SNICKERReceiver(wallet_r)
    sR.proposals_source = "test_proposals.txt" # avoid clashing with mainnet
    sR.poll_for_proposals()
    assert len(sR.successful_txs) == 1
    wallet_r.process_new_tx(sR.successful_txs[0])
    end_utxos = wallet_r.get_all_utxos()
    print("At end the receiver has these utxos: ", end_utxos)
    receiver_end_bal = sum([x['value'] for x in end_utxos.values()])
    assert receiver_end_bal == receiver_start_bal + net_transfer

@pytest.fixture(scope="module")
def setup_snicker():
    load_test_config()
