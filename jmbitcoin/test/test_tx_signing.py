#!/usr/bin/env python3

import pytest

import binascii
import hashlib
import jmbitcoin as btc

@pytest.mark.parametrize(
    "addrtype",
    [("p2wpkh"),
     ("p2sh-p2wpkh"),
     ("p2pkh"),
    ])
def test_sign_standard_txs(addrtype):
    # liberally copied from python-bitcoinlib tests,
    # in particular see:
    # https://github.com/petertodd/python-bitcoinlib/pull/227

    # Create the (in)famous correct brainwallet secret key.
    priv = hashlib.sha256(b'correct horse battery staple').digest() + b"\x01"
    pub = btc.privkey_to_pubkey(priv)
    
    # Create an address from that private key.
    # (note that the input utxo is fake so we are really only creating
    # a destination here).
    scriptPubKey = btc.CScript([btc.OP_0, btc.Hash160(pub)])
    address = btc.P2WPKHCoinAddress.from_scriptPubKey(scriptPubKey)
    
    # Create a dummy outpoint; use same 32 bytes for convenience
    txid = priv[:32]
    vout = 2
    amount = btc.coins_to_satoshi(float('0.12345'))
    
    # Calculate an amount for the upcoming new UTXO. Set a high fee to bypass
    # bitcoind minfee setting.
    amount_less_fee = int(amount - btc.coins_to_satoshi(0.01))
    
    # Create a destination to send the coins.
    destination_address = address
    target_scriptPubKey = scriptPubKey
    
    # Create the unsigned transaction.
    txin = btc.CTxIn(btc.COutPoint(txid[::-1], vout))
    txout = btc.CTxOut(amount_less_fee, target_scriptPubKey)
    tx = btc.CMutableTransaction([txin], [txout])
    
    # Calculate the signature hash for the transaction. This is then signed by the
    # private key that controls the UTXO being spent here at this txin_index.
    if addrtype == "p2wpkh":
        sig, msg = btc.sign(tx, 0, priv, amount=amount, native=True)
    elif addrtype == "p2sh-p2wpkh":
        sig, msg = btc.sign(tx, 0, priv, amount=amount, native=False)
    elif addrtype == "p2pkh":
        sig, msg = btc.sign(tx, 0, priv)
    else:
        assert False
    if not sig:
        print(msg)
        raise
    print("created signature: ", binascii.hexlify(sig))
    print("serialized transaction: {}".format(btc.b2x(tx.serialize())))

def test_mk_shuffled_tx():
    # prepare two addresses for the outputs
    pub = btc.privkey_to_pubkey(btc.Hash(b"priv") + b"\x01")
    scriptPubKey = btc.CScript([btc.OP_0, btc.Hash160(pub)])
    addr1 = btc.P2WPKHCoinAddress.from_scriptPubKey(scriptPubKey)
    scriptPubKey_p2sh = scriptPubKey.to_p2sh_scriptPubKey()
    addr2 = btc.CCoinAddress.from_scriptPubKey(scriptPubKey_p2sh)

    ins = [(btc.Hash(b"blah"), 7), (btc.Hash(b"foo"), 15)]
    # note the casts str() ; most calls to mktx will have addresses fed
    # as strings, so this is enforced for simplicity.
    outs = [{"address": str(addr1), "value": btc.coins_to_satoshi(float("0.1"))},
            {"address": str(addr2), "value": btc.coins_to_satoshi(float("45981.23331234"))}]
    tx = btc.make_shuffled_tx(ins, outs, version=2, locktime=500000)

def test_bip143_tv():
    # p2sh-p2wpkh case:
    rawtx_hex = "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"
    inp_spk_hex = "a9144733f37cf4db86fbc2efed2500b4f4e49f31202387"
    value = 10
    redeemScript = "001479091972186c449eb1ded22b78e40d009bdf0089"
    privkey_hex = "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf01"
    pubkey_hex = "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873"
    tx = btc.CMutableTransaction.deserialize(btc.x(rawtx_hex))
    btc.sign(tx, 0, btc.x(privkey_hex), amount=btc.coins_to_satoshi(10), native=False)
    expectedsignedtx = "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000"
    assert btc.b2x(tx.serialize()) == expectedsignedtx