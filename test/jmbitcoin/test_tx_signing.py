import pytest

import hashlib
from jmbase import bintohex
import jmbitcoin as btc
from math import ceil


# Case of spending into a FB, one p2wpkh input, one FB output, one p2wpkh output:
#
# "020000000001019b3a5c6ec9712bd6b1aa1e07ed12a677eb21215430fb84a689664fb0d4fa175a0000000000feffffff0290099c0a000000001600144d32ca4673822334531a2941bb85bff075c384d180b14f0100000000220020dae515a98f31542dd6b21bb0b0e31fccc4ebcdc9ba3e225798bc981ccbb8a21d024830450221009bc5fb8d077b32304c02a886926a68110bc7c5195a92b55977bd4affd23ab2d50220774e88828cf80cba4bb2e277a69a7c693c3566b5b72a0c0cf25cba89df0646d30121036d1baed4008f0d7f03ac41bbdbe46e02eeef6f040f7bdbc41adac30c2cf8831886020000"
#
# case of spending from a FB, single input, to 2 p2wpkh outputs
# "020000000001013499e10a8035a3cb928f5a894b2a3feed7d46ab579f0a2211a17ed1df0e2d9660100000000feffffff02405dc6000000000016001486551870825ef64d7fda89cc2a6fda497ab71a02954d8900000000001600147c24b9a3ddf5eb26142fb3f05a3746a0a582f81a0247304402206ca2049154939b083a5eb22713d3cb78f6673f43828fa4a7ef0f03275584da6c0220770fe7d50ba5e0a5f8039f28c5deaaf1e8b2030008bf51cc8721cf088eab5586012a0480c22e61b175210376e5964ee2c328e85b88a50f02953b1cddb1490825140331a3948023cc19946bac81c22e61"
#
# case of spending from an FB plus one more p2wpkh input, spending to a p2sh output and a p2wpkh output
# "02000000000102117efb788cee9644d5493fc9d1a120598f4f5200bb6909c0ebdac66cf88da80a0100000000feffffffb0f3ce583987d08080684e2c75d2d6871cb2d30f610327671440d7121c14b7ab0000000000feffffff0240a5ae020000000017a914c579342c2c4c9220205e2cdc285617040c924a0a8797027a00000000001600146fad63e6420ec3eb423a105b05c6df6cc8dab92902473044022040f1db3289d8c6e0dd94c0f55254f10512486094e36fd92f4423abc95320418902206718670b3f332d84cf8294ad389155594ebe125988f2f535c58ff3b077471ce9012102f9306fdc84a366f21fed44fbdd9149a046829f26fb52e7a316b19b536c18d2df0247304402207d0fde11ce32f48107ac246a01efad1c22b9466cd9ff4d5683030790bcb34ce5022020014fcf1b1b0606db5ef363568f10476524f7102644691a8a435faa17cbbe88012a04804f5661b17521037a9502304b2810706adef15b884ac7ca0c48c2e5d03cf93934487b44feb7c276ac814f5661"
#
# case of spending from one FB input to one FB output
#
# "0200000000010150c8e3786d357cbe61d8e27de7439e1b32d75d0a0ad596c5ff2863134cbd3ead0100000000feffffff01db84f701000000002200208b8ed0bc565e419dd956c3841b7bb25f7c197e2699002bac58a68f47206e1f340247304402202a639209aa9a2883ad75210edce2165260167435f56cede83e8c74095944f355022050fde591f1fefb615a072a797ace3c332c678e0f9161e58d79efa1705f9ab17c012a04002e7f61b1752103d4d747d0dca80c129c017ec1cdc658945013e04ff3d6946f15ccc9df52c323f0ac012e7f61"
#
# Virtual sizes can be calculated from bitcointx.core.CTransaction.deserialize(unhexlify(txhex)).get_virtual_size()
#
# More cases copied from:
# https://github.com/kristapsk/bitcoin-scripts/blob/0b847bec016638e60313ecec2b81f2e8accd311b/tests/tx-vsize.bats
@pytest.mark.parametrize(
    "inaddrtypes, outaddrtypes, size_expected",
    [(["p2wpkh"], ["p2wsh", "p2wpkh"], 153),
     (["p2wsh"], ["p2wpkh", "p2wpkh"], 143),
     (["p2wsh", "p2wpkh"], ["p2sh-p2wpkh", "p2wpkh"], 212),
     (["p2wsh"], ["p2wsh"], 124),
     (["p2pkh"], ["p2pkh"], 192),
     (["p2pkh"], ["p2pkh", "p2pkh"], 226),
     (["p2pkh"], ["p2sh-p2wpkh", "p2sh-p2wpkh"], 222),
     (["p2pkh"], ["p2pkh", "p2sh-p2wpkh"], 224),
     (["p2sh-p2wpkh"], ["p2sh-p2wpkh"], 134),
     (["p2wpkh"], ["p2wpkh"], 110),
     (["p2wpkh"], ["p2wpkh", "p2tr"], 153),
     ])
def test_tx_size_estimate(inaddrtypes, outaddrtypes, size_expected):
    # non-sw only inputs result in a single integer return,
    # segwit inputs return (witness size, non-witness size)
    x = btc.estimate_tx_size(inaddrtypes, outaddrtypes)
    if btc.there_is_one_segwit_input(inaddrtypes):
        s = ceil((x[0] + x[1] * 4) / 4.0)
    else:
        s = x
    assert s == size_expected

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
    target_scriptPubKey = scriptPubKey
    
    # Create the unsigned transaction.
    txin = btc.CTxIn(btc.COutPoint(txid[::-1], vout))
    txout = btc.CTxOut(amount_less_fee, target_scriptPubKey)
    tx = btc.CMutableTransaction([txin], [txout])
    
    # Calculate the signature hash for the transaction. This is then signed by the
    # private key that controls the UTXO being spent here at this txin_index.
    if addrtype == "p2wpkh":
        sig, msg = btc.sign(tx, 0, priv, amount=amount, native="p2wpkh")
    elif addrtype == "p2sh-p2wpkh":
        sig, msg = btc.sign(tx, 0, priv, amount=amount, native=False)
    elif addrtype == "p2pkh":
        sig, msg = btc.sign(tx, 0, priv)
    else:
        assert False
    if not sig:
        print(msg)
        raise
    print("created signature: ", bintohex(sig))
    print("serialized transaction: {}".format(bintohex(tx.serialize())))
    print("deserialized transaction: {}\n".format(
        btc.human_readable_transaction(tx)))

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
