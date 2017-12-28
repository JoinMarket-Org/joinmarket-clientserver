#!/usr/bin/env python2
from __future__ import print_function
"""
Tool to create or receive a single input, output pair
signed single|acp to allow the receiver to add further
inputs and outputs and broadcast a full transaction.
Thus the original input can be tainted and the taint
can spread to other outputs included.
This is a tool for Joinmarket wallets specifically.
"""
import binascii
import os
import sys
import random
from optparse import OptionParser
from pprint import pformat
import jmbitcoin as btc
from jmclient import (load_program_config, validate_address, jm_single,
                      WalletError, sync_wallet, RegtestBitcoinCoreInterface,
                      estimate_tx_fee, Wallet, SegwitWallet, get_p2pk_vbyte,
                      get_p2sh_vbyte)
from jmbase.support import get_password

def get_parser():
    parser = OptionParser(
        usage=
        'usage: %prog [options] walletfile make utxo\n' + \
        'or: %prog [options] walletfile take amount-in-satoshis destination-addr txhex',
        description='Makes a single|acp signed in-out pair for giving to others '
        +
        'or receives such a pair and creates a full transaction with your utxos. '
        +
        'Primarily useful for spreading utxo taint.')
    parser.add_option(
        '-b',
        '--bump',
        type='int',
        dest='bump',
        default=10000,
        help=
        'How much bigger the output is than the input, when making a single|acp in-out pair.')
    parser.add_option(
        '-m',
        '--mixdepth',
        type='int',
        dest='mixdepth',
        help=
        'Mixing depth to source utxo from. default=0.',
        default=0)
    parser.add_option('-a',
                      '--amtmixdepths',
                      action='store',
                      type='int',
                      dest='amtmixdepths',
                      help='number of mixdepths in wallet, default 5',
                      default=5)
    parser.add_option('-g',
                      '--gap-limit',
                      type="int",
                      action='store',
                      dest='gaplimit',
                      help='gap limit for wallet, default=6',
                      default=6)
    parser.add_option('--fast',
                      action='store_true',
                      dest='fastsync',
                      default=False,
                      help=('choose to do fast wallet sync, only for Core and '
                            'only for previously synced wallet'))    
    return parser

def is_utxo(utxo):
    try:
        txid, N = utxo.split(":")
        assert len(txid) == 64
        N = int(N)
    except:
        return False
    return True

def cli_get_wallet(wallet_name, sync=True):
    walletclass = SegwitWallet if jm_single().config.get(
        "POLICY", "segwit") == "true" else Wallet    
    if not os.path.exists(os.path.join('wallets', wallet_name)):
        wallet = walletclass(wallet_name, None, max_mix_depth=options.amtmixdepths)
    else:
        while True:
            try:
                pwd = get_password("Enter wallet decryption passphrase: ")
                wallet = walletclass(wallet_name, pwd, max_mix_depth=options.amtmixdepths)
            except WalletError:
                print("Wrong password, try again.")
                continue
            except Exception as e:
                print("Failed to load wallet, error message: " + repr(e))
                sys.exit(0)
            break
    if jm_single().config.get("BLOCKCHAIN",
                              "blockchain_source") == "electrum-server":
        jm_single().bc_interface.synctype = "with-script"
    if sync:
        sync_wallet(wallet, fast=options.fastsync)
    return wallet

#======Electrum specific utils=========================
def rev_hex(s):
    return s.decode('hex')[::-1].encode('hex')

def int_to_hex(i, length=1):
    s = hex(i)[2:].rstrip('L')
    s = "0"*(2*length - len(s)) + s
    return rev_hex(s)

def serialize_derivation(roc, i):
    x = ''.join(map(lambda x: int_to_hex(x, 2), (roc, i)))
    print("returning: ", x)
    raw_input()
    return x
#=======================================================

def get_privkey_amount_from_utxo(wallet, utxo):
    """Given a JM wallet and a utxo string, find
    the corresponding private key and amount controlled
    in satoshis.
    """
    for k, v in wallet.unspent.items():
        if k == utxo:
            print("Found utxo, its value is: ", v['value'])
            return wallet.get_key_from_addr(v['address']), v['value']
    return (None, None)

def create_single_acp_pair(utxo_in, priv, addr_out, amount, bump, segwit=False):
    """Given a utxo and a signing key for it, and its amout in satoshis,
    sign a "transaction" consisting of only 1 input and one output, signed
    with single|acp sighash flags so it can be grafted into a bigger
    transaction.
    Also provide a destination address and a 'bump' value (so the creator
    can claim more output in the final transaction.
    Note that, for safety, bump *should* be positive if the recipient
    is untrusted, since otherwise they can waste your money by simply
    broadcasting this transaction without adding any inputs of their own.
    Returns the serialized 1 in, 1 out, and signed transaction.
    """
    assert bump >= 0, "Output of single|acp pair must be bigger than input for safety."
    out = {"address": addr_out, "value": amount + bump}
    tx = btc.mktx([utxo_in], [out])
    amt = amount if segwit else None
    return btc.sign(tx, 0, priv,
                    hashcode=btc.SIGHASH_SINGLE|btc.SIGHASH_ANYONECANPAY,
                    amount=amt)

def graft_onto_single_acp(wallet, txhex, amount, destaddr):
    """Given a serialized txhex which is checked to be of
    form single|acp (one in, one out), a destination address
    and an amount to spend, grafts in this in-out pair (at index zero)
    to our own transaction spending amount amount to destination destaddr,
    and uses a user-specified transaction fee (normal joinmarket
    configuration), and sanity checks that the bump value is not
    greater than user specified bump option.
    Returned: serialized txhex of fully signed transaction.
    """
    d = btc.deserialize(txhex)
    if len(d['ins']) != 1 or len(d['outs']) != 1:
        return (False, "Proposed tx should have 1 in 1 out, has: " + ','.join(
            [str(len(d[x])) for x in ['ins', 'outs']]))
    #most important part: check provider hasn't bumped more than options.bump:
    other_utxo_in = d['ins'][0]['outpoint']['hash'] + ":" + str(d['ins'][0]['outpoint']['index'])
    res = jm_single().bc_interface.query_utxo_set(other_utxo_in)
    assert len(res) == 1
    if not res[0]:
        return (False, "Utxo provided by counterparty not found.")
    excess = d['outs'][0]['value'] - res[0]["value"]
    if not excess  <= options.bump:
        return (False, "Counterparty claims too much excess value: " + str(excess))
    #Last sanity check - ensure that it's single|acp, else we're wasting our time
    try:
        if 'txinwitness' in d['ins'][0]:
            sig, pub = d['ins'][0]['txinwitness']
        else:
            sig, pub = btc.deserialize_script(d['ins'][0]['script'])
        assert sig[-2:] == "83"
    except Exception as e:
        return (False, "The transaction's signature does not parse as signed with "
                "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY, for p2pkh or p2sh-p2wpkh, or "
                "is otherwise invalid, and so is not valid for this function.\n" + repr(e))
    #source inputs for our own chosen spending amount:
    try:
        input_utxos = wallet.select_utxos(options.mixdepth, amount)
    except Exception as e:
        return (False, "Unable to select sufficient coins from mixdepth: " + str(options.mixdepth))
    total_selected = sum([x['value'] for x in input_utxos.values()])
    fee = estimate_tx_fee(len(input_utxos)+1, 3, txtype='p2sh-p2wpkh')
    change_amount = total_selected - amount - excess - fee
    changeaddr = wallet.get_new_addr(options.mixdepth, 1)
    #Build new transaction and, graft in signature
    ins = [other_utxo_in] + list(input_utxos)
    outs = [d['outs'][0], {'address': destaddr, 'value': amount},
            {'address': changeaddr, 'value': change_amount}]
    fulltx = btc.mktx(ins, outs)
    df = btc.deserialize(fulltx)
    #put back in original signature
    df['ins'][0]['script'] = d['ins'][0]['script']
    if 'txinwitness' in d['ins'][0]:
        df['ins'][0]['txinwitness'] = d['ins'][0]['txinwitness']
    fulltx = btc.serialize(df)
    for i, iu in enumerate(input_utxos):
        priv, inamt = get_privkey_amount_from_utxo(wallet, iu)
        print("Signing index: ", i+1, " with privkey: ", priv, " and amount: ", inamt, " for utxo: ", iu)
        fulltx = btc.sign(fulltx, i+1, priv, amount=inamt)
    return (True, fulltx)
        
if __name__ == "__main__":
    parser = get_parser()
    (options, args) = parser.parse_args()
    load_program_config()
    #default args causes wallet sync here:
    wallet = cli_get_wallet(args[0])
    if args[1] not in ['make', 'take']:
        print("Second argument must be 'make' or 'take', see '--help'")
        exit(0)
    if args[1] == "make":
        if len(args) < 3 or not is_utxo(args[2]):
            print("You must provide a utxo as third argument; 64 character hex "
            "txid, followed by ':', followed by the output index. "
            "Use wallet-tool.py method 'showutxos' to select one")
            exit(0)
        utxo_in = args[2]
        priv, amount = get_privkey_amount_from_utxo(wallet, utxo_in)
        if not priv:
            print("Failed to find the utxo's private key from the wallet; check "
                  "if this utxo is actually contained in the wallet using "
                  "wallet-tool.py showutxos")
            exit(0)
        #destination sourced from wallet
        addr_out = wallet.get_new_addr((options.mixdepth+1)%options.amtmixdepths, 1)
        serialized_single_acp = create_single_acp_pair(utxo_in, priv, addr_out, amount,
                                                       options.bump, segwit=True)
        print("Created the following one-in, one-out transaction, which will not "
              "be valid to broadcast itself (negative fee). Pass it to your "
              "counterparty:")
        print(pformat(btc.deserialize(serialized_single_acp)))
        print("Pass the following raw hex to your counterparty:")
        print(serialized_single_acp)
        exit(0)
    elif args[1] == "take":
        try:
            amount, destaddr, txhex = args[2:5]
            #sanity check input
            amount = int(amount)
            assert amount > 0
            assert validate_address(destaddr)
            binascii.unhexlify(txhex)
        except Exception as e:
            print("Syntax error, should be 5 arguments, see --help. ", repr(e))
            exit(0)
        success, complete_tx = graft_onto_single_acp(wallet, txhex, amount, destaddr)
        if not success:
            print("Quitting, reason: " + complete_tx)
            exit(0)
        #allow user to decide whether to broadcast:
        print("The following transaction has been prepared:")
        print(pformat(btc.deserialize(complete_tx)))
        broadcast = raw_input("Do you want to broadcast now? (y/n): ")
        if broadcast == "y":
            success = jm_single().bc_interface.pushtx(complete_tx)
            if not success:
                print("Failed to broadcast.")
            exit(0)
        else:
            print("You chose not to broadcast.")
            exit(0)
    print('done')
