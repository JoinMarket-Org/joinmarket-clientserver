"""
Module implementing actions that can be taken on
network-serialized bitcoin blocks.
"""

from jmbase import hextobin
from bitcointx.core import CBitcoinTransaction
from bitcointx.core.serialize import VarIntSerializer


def decode_varint(data):
    n, tail = VarIntSerializer.deserialize_partial(data)
    head = data[0 : len(data) - len(tail)]
    return n, len(head)


def get_transactions_in_block(block):
    """`block` is hex output from RPC `getblock`.
    Return:
    yields the block's transactions, type CBitcoinTransaction
    """
    block = hextobin(block)

    # Skipping the header
    transaction_data = block[80:]

    # Decoding the number of transactions, offset is the size of
    # the varint (1 to 9 bytes)
    n_transactions, offset = decode_varint(transaction_data)

    for i in range(n_transactions):
        # This 'strat' of reading in small chunks optimistically is taken from:
        # https://github.com/alecalve/python-bitcoin-blockchain-parser/blob/7a9e15c236b10d2a6dff5e696801c0641af72628/blockchain_parser/utils.py
        # Try from 1024 (1KiB) -> 1073741824 (1GiB) slice widths
        for j in range(0, 20):
            try:
                offset_e = offset + (1024 * 2**j)
                transaction = CBitcoinTransaction.deserialize(
                    transaction_data[offset:offset_e], allow_padding=True
                )
                yield transaction
                break
            except:
                continue

        # Skipping to the next transaction
        offset += len(transaction.serialize())


""" Example block from a regtest:

# Found using `getblockhash 222` followed by `getblock <resultinghash> 0`:

0000003066327ecf2f3e72ec43f358c9c7b34f47374f23f4fcce965d4e18273a5b98f325d11b3b9c3a592c830d49f6281d4055f5732a79a19f9bd8d4afad729772cbf393fa7bdf5fffff7f2000000000010200000
00001010000000000000000000000000000000000000000000000000000000000000000ffffffff0502de000101ffffffff0200f902950000000017a914d2e1d0ea5135f0cbeb4aef06e3cee785d394876a870000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000

Gives (x = above block):

y = list(btc.get_block_transactions(x))
>>> y[0]
CBitcoinTransaction([CBitcoinTxIn(CBitcoinOutPoint(), CBitcoinScript([x('de00'), x('01')]), 0xffffffff)],
[CBitcoinTxOut(25.0*COIN, CBitcoinScript([OP_HASH160, x('d2e1d0ea5135f0cbeb4aef06e3cee785d394876a'), OP_EQUAL])),
CBitcoinTxOut(0.0*COIN, CBitcoinScript([OP_RETURN, x('aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9')]))],
0, 2, CBitcoinTxWitness([CBitcoinTxInWitness(CScriptWitness([x('0000000000000000000000000000000000000000000000000000000000000000')]))]))

(coinbase transaction)
"""
