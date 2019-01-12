from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401
from future.utils import iteritems
import json
import os
import sys
import sqlite3
import binascii
from datetime import datetime
from optparse import OptionParser
from numbers import Integral
from collections import Counter
from itertools import islice
from jmclient import (get_network, WALLET_IMPLEMENTATIONS, Storage, podle,
    jm_single, BitcoinCoreInterface, JsonRpcError, sync_wallet, WalletError,
    VolatileStorage, StoragePasswordError,
    is_segwit_mode, SegwitLegacyWallet, LegacyWallet)
from jmbase.support import get_password
from .cryptoengine import TYPE_P2PKH, TYPE_P2SH_P2WPKH
import jmbitcoin as btc


# used for creating new wallets
DEFAULT_MIXDEPTH = 4


def get_wallettool_parser():
    description = (
        'Use this script to monitor and manage your Joinmarket wallet.\n'
        'The method is one of the following: \n'
        '(display) Shows addresses and balances.\n'
        '(displayall) Shows ALL addresses and balances.\n'
        '(summary) Shows a summary of mixing depth balances.\n'
        '(generate) Generates a new wallet.\n'
        '(history) Show all historical transaction details. Requires Bitcoin Core.'
        '(recover) Recovers a wallet from the 12 word recovery seed.\n'
        '(showutxos) Shows all utxos in the wallet.\n'
        '(showseed) Shows the wallet recovery seed and hex seed.\n'
        '(importprivkey) Adds privkeys to this wallet, privkeys are spaces or commas separated.\n'
        '(dumpprivkey) Export a single private key, specify an hd wallet path\n'
        '(signmessage) Sign a message with the private key from an address in \n'
        'the wallet. Use with -H and specify an HD wallet path for the address.')
    parser = OptionParser(usage='usage: %prog [options] [wallet file] [method]',
                          description=description)
    parser.add_option('-p',
                      '--privkey',
                      action='store_true',
                      dest='showprivkey',
                      help='print private key along with address, default false')
    parser.add_option('-m',
                      '--mixdepth',
                      action='store',
                      type='int',
                      dest='mixdepth',
                      help="Mixdepth(s) to use in the wallet. Default: {}"
                           .format(DEFAULT_MIXDEPTH),
                      default=None)
    parser.add_option('-g',
                      '--gap-limit',
                      type="int",
                      action='store',
                      dest='gaplimit',
                      help='gap limit for wallet, default=6',
                      default=6)
    parser.add_option('--csv',
                      action='store_true',
                      dest='csv',
                      default=False,
                      help=('When using the history method, output as csv'))
    parser.add_option('-v', '--verbosity',
                      action='store',
                      type='int',
                      dest='verbosity',
                      default=1,
                      help=('History method verbosity, 0 (least) to 6 (most), '
                            '<=2 batches earnings, even values also list TXIDs'))
    parser.add_option('--fast',
                      action='store_true',
                      dest='fastsync',
                      default=False,
                      help=('choose to do fast wallet sync, only for Core and '
                      'only for previously synced wallet'))
    parser.add_option('-H',
                      '--hd',
                      action='store',
                      type='str',
                      dest='hd_path',
                      help='hd wallet path (e.g. m/0/0/0/000)')
    parser.add_option('--key-type',  # note: keep in sync with map_key_type
                      type='choice',
                      choices=('standard', 'segwit-p2sh'),
                      action='store',
                      dest='key_type',
                      default=None,
                      help=("Key type when importing private keys.\n"
                            "If your address starts with '1' use 'standard', "
                            "if your address starts with '3' use 'segwit-p2sh.\n"
                            "Native segwit addresses (starting with 'bc') are"
                            "not yet supported."))
    return parser


def map_key_type(parser_key_choice):
    if not parser_key_choice:
        return parser_key_choice
    if parser_key_choice == 'standard':
        return TYPE_P2PKH
    if parser_key_choice == 'segwit-p2sh':
        return TYPE_P2SH_P2WPKH
    raise Exception("Unknown key type choice '{}'.".format(parser_key_choice))


"""The classes in this module manage representations
of wallet states; but they know nothing about Bitcoin,
so do not attempt to validate addresses, keys, BIP32 or relationships.
A console based output is provided as default, but underlying serializations
can be used by calling classes for UIs.
"""

bip32sep = '/'

def bip32pathparse(path):
    if not path.startswith('m'):
        return False
    elements = path.split(bip32sep)[1:]
    ret_elements = []
    for e in elements:
        if e[-1] == "'": e = e[:-1]
        try:
            x = int(e)
        except:
            return False
        if not x >= -1:
            #-1 is allowed for dummy branches for imported keys
            return False
        ret_elements.append(x)
    return ret_elements

def test_bip32_pathparse():
    assert bip32pathparse("m/2/1/0017")
    assert not bip32pathparse("n/1/1/1/1")
    assert bip32pathparse("m/0/1'/100'/3'/2/2/21/004/005")
    assert not bip32pathparse("m/0/0/00k")
    return True
"""
WalletView* classes manage wallet representations.
"""

class WalletViewBase(object):
    def __init__(self, wallet_path_repr, children=None, serclass=str,
                 custom_separator=None):
        self.wallet_path_repr = wallet_path_repr
        self.children = children
        self.serclass = serclass
        self.separator = custom_separator if custom_separator else "\t"

    def get_balance(self, include_unconf=True):
        if not include_unconf:
            raise NotImplementedError("Separate conf/unconf balances not impl.")
        return sum([x.get_balance() for x in self.children])

    def get_fmt_balance(self, include_unconf=True):
        return "{0:.08f}".format(self.get_balance(include_unconf))

class WalletViewEntry(WalletViewBase):
    def __init__(self, wallet_path_repr, account, forchange, aindex, addr, amounts,
                 used = 'new', serclass=str, priv=None, custom_separator=None):
        super(WalletViewEntry, self).__init__(wallet_path_repr, serclass=serclass,
                                              custom_separator=custom_separator)
        self.account = account
        assert forchange in [0, 1, -1]
        self.forchange =forchange
        assert isinstance(aindex, Integral)
        assert aindex >= 0
        self.aindex = aindex
        self.address = addr
        self.unconfirmed_amount, self.confirmed_amount = amounts
        #note no validation here
        self.private_key = priv
        self.used = used

    def get_balance(self, include_unconf=True):
        """Overwrites base class since no children
        """
        if not include_unconf:
            raise NotImplementedError("Separate conf/unconf balances not impl.")
        return self.unconfirmed_amount/1e8

    def serialize(self):
        left = self.serialize_wallet_position()
        addr = self.serialize_address()
        amounts = self.serialize_amounts()
        extradata = self.serialize_extra_data()
        return self.serclass(self.separator.join([left, addr, amounts, extradata]))

    def serialize_wallet_position(self):
        return self.wallet_path_repr.ljust(20)

    def serialize_address(self):
        return self.serclass(self.address)

    def serialize_amounts(self, unconf_separate=False, denom="BTC"):
        if denom != "BTC":
            raise NotImplementedError("Altern. denominations not yet implemented.")
        if unconf_separate:
            raise NotImplementedError("Separate handling of unconfirmed funds "
                                      "not yet implemented.")
        return self.serclass("{0:.08f}".format(self.unconfirmed_amount/1e8))

    def serialize_extra_data(self):
        ed = self.used
        if self.private_key:
            ed += self.separator + self.serclass(self.private_key)
        return self.serclass(ed)

class WalletViewBranch(WalletViewBase):
    def __init__(self, wallet_path_repr, account, forchange, branchentries=None,
                 xpub=None, serclass=str, custom_separator=None):
        super(WalletViewBranch, self).__init__(wallet_path_repr, children=branchentries,
                                               serclass=serclass,
                                               custom_separator=custom_separator)
        self.account = account
        assert forchange in [0, 1, -1]
        self.forchange = forchange
        if xpub:
            assert xpub.startswith('xpub') or xpub.startswith('tpub')
        self.xpub = xpub if xpub else ""
        self.branchentries = branchentries

    def serialize(self, entryseparator="\n", summarize=False):
        if summarize:
            return ""
        else:
            lines = [self.serialize_branch_header()]
            for we in self.branchentries:
                lines.append(we.serialize())
            footer = "Balance:" + self.separator + self.get_fmt_balance()
            lines.append(footer)
            return self.serclass(entryseparator.join(lines))

    def serialize_branch_header(self):
        start = "external addresses" if self.forchange == 0 else "internal addresses"
        if self.forchange == -1:
            start = "Imported keys"
        return self.serclass(self.separator.join([start, self.wallet_path_repr,
                                                  self.xpub]))

class WalletViewAccount(WalletViewBase):
    def __init__(self, wallet_path_repr, account, branches=None, account_name="mixdepth",
                 serclass=str, custom_separator=None, xpub=None):
        super(WalletViewAccount, self).__init__(wallet_path_repr, children=branches,
                                                serclass=serclass,
                                                custom_separator=custom_separator)
        self.account = account
        self.account_name = account_name
        self.xpub = xpub
        if branches:
            assert len(branches) in [2, 3] #3 if imported keys
            assert all([isinstance(x, WalletViewBranch) for x in branches])
        self.branches = branches

    def serialize(self, entryseparator="\n", summarize=False):
        header = self.account_name + self.separator + str(self.account)
        if self.xpub:
            header = header + self.separator + self.xpub
        footer = "Balance for mixdepth " + str(
            self.account) + ":" + self.separator + self.get_fmt_balance()
        if summarize:
            return self.serclass(entryseparator.join(
                [x.serialize("", summarize=True) for x in self.branches] + [footer]))
        else:
            return self.serclass(entryseparator.join([header] + [
                x.serialize(entryseparator) for x in self.branches] + [footer]))

class WalletView(WalletViewBase):
    def __init__(self, wallet_path_repr, accounts, wallet_name="JM wallet",
                 serclass=str, custom_separator=None):
        super(WalletView, self).__init__(wallet_path_repr, children=accounts,
                                         serclass=serclass,
                                         custom_separator=custom_separator)
        self.wallet_name = wallet_name
        assert all([isinstance(x, WalletViewAccount) for x in accounts])
        self.accounts = accounts

    def serialize(self, entryseparator="\n", summarize=False):
        header = self.wallet_name
        footer = "Total balance:" + self.separator + self.get_fmt_balance()
        if summarize:
            return self.serclass(entryseparator.join([header] + [
                x.serialize("", summarize=True) for x in self.accounts] + [footer]))
        else:
            return self.serclass(entryseparator.join([header] + [
                x.serialize(entryseparator, summarize=False) for x in self.accounts] + [footer]))


def get_tx_info(txid):
    """
    Retrieve some basic information about the given transaction.

    :param txid: txid as hex-str
    :return: tuple
        is_coinjoin: bool
        cj_amount: int, only useful if is_coinjoin==True
        cj_n: int, number of cj participants, only useful if is_coinjoin==True
        output_script_values: {script: value} dict including all outputs
        blocktime: int, blocktime this tx was mined
        txd: deserialized transaction object (hex-encoded data)
    """
    rpctx = jm_single().bc_interface.rpc('gettransaction', [txid])
    txhex = str(rpctx['hex'])
    txd = btc.deserialize(txhex)
    output_script_values = {binascii.unhexlify(sv['script']): sv['value']
                            for sv in txd['outs']}
    value_freq_list = sorted(
        Counter(output_script_values.values()).most_common(),
        key=lambda x: -x[1])
    non_cj_freq = (0 if len(value_freq_list) == 1 else
                   sum(next(islice(zip(*value_freq_list[1:]), 1, None))))
    is_coinjoin = (value_freq_list[0][1] > 1 and
                   value_freq_list[0][1] in
                   [non_cj_freq, non_cj_freq + 1])
    cj_amount = value_freq_list[0][0]
    cj_n = value_freq_list[0][1]
    return is_coinjoin, cj_amount, cj_n, output_script_values,\
        rpctx.get('blocktime', 0), txd


def get_imported_privkey_branch(wallet, m, showprivkey):
    entries = []
    for path in wallet.yield_imported_paths(m):
        addr = wallet.get_addr_path(path)
        script = wallet.get_script_path(path)
        balance = 0.0
        for data in wallet.get_utxos_by_mixdepth_()[m].values():
            if script == data['script']:
                balance += data['value']
        used = ('used' if balance > 0.0 else 'empty')
        if showprivkey:
            wip_privkey = wallet.get_wif_path(path)
        else:
            wip_privkey = ''
        entries.append(WalletViewEntry(wallet.get_path_repr(path), m, -1,
                                       0, addr, [balance, balance],
                                       used=used, priv=wip_privkey))

    if entries:
        return WalletViewBranch("m/0", m, -1, branchentries=entries)
    return None

def wallet_showutxos(wallet, showprivkey):
    unsp = {}
    max_tries = jm_single().config.getint("POLICY", "taker_utxo_retries")
    utxos = wallet.get_utxos_by_mixdepth()
    for md in utxos:
        for u, av in utxos[md].items():
            key = wallet.get_key_from_addr(av['address'])
            tries = podle.get_podle_tries(u, key, max_tries)
            tries_remaining = max(0, max_tries - tries)
            unsp[u] = {'address': av['address'], 'value': av['value'],
                       'tries': tries, 'tries_remaining': tries_remaining,
                       'external': False}
            if showprivkey:
                unsp[u]['privkey'] = wallet.get_wif_path(av['path'])

    used_commitments, external_commitments = podle.get_podle_commitments()
    for u, ec in iteritems(external_commitments):
        tries = podle.get_podle_tries(utxo=u, max_tries=max_tries,
                                          external=True)
        tries_remaining = max(0, max_tries - tries)
        unsp[u] = {'tries': tries, 'tries_remaining': tries_remaining,
                   'external': True}

    return json.dumps(unsp, indent=4)


def wallet_display(wallet, gaplimit, showprivkey, displayall=False,
        serialized=True, summarized=False):
    """build the walletview object,
    then return its serialization directly if serialized,
    else return the WalletView object.
    """
    def get_addr_status(addr_path, utxos, is_new, is_internal):
        addr_balance = 0
        status = []
        for utxo, utxodata in iteritems(utxos):
            if addr_path != utxodata['path']:
                continue
            addr_balance += utxodata['value']
            is_coinjoin, cj_amount, cj_n = \
                get_tx_info(binascii.hexlify(utxo[0]).decode('ascii'))[:3]
            if is_coinjoin and utxodata['value'] == cj_amount:
                status.append('cj-out')
            elif is_coinjoin:
                status.append('change-out')
            elif is_internal:
                status.append('non-cj-change')
            else:
                status.append('deposit')

        out_status = 'new' if is_new else 'used'
        if len(status) > 1:
            out_status = 'reused'
        elif len(status) == 1:
            out_status = status[0]

        return addr_balance, out_status

    acctlist = []
    utxos = wallet.get_utxos_by_mixdepth_()
    for m in range(wallet.mixdepth + 1):
        branchlist = []
        for forchange in [0, 1]:
            entrylist = []
            if forchange == 0:
                # users would only want to hand out the xpub for externals
                xpub_key = wallet.get_bip32_pub_export(m, forchange)
            else:
                xpub_key = ""

            unused_index = wallet.get_next_unused_index(m, forchange)
            for k in range(unused_index + gaplimit):
                path = wallet.get_path(m, forchange, k)
                addr = wallet.get_addr_path(path)
                balance, used = get_addr_status(
                    path, utxos[m], k >= unused_index, forchange)
                if showprivkey:
                    privkey = wallet.get_wif_path(path)
                else:
                    privkey = ''
                if (displayall or balance > 0 or
                        (used == 'new' and forchange == 0)):
                    entrylist.append(WalletViewEntry(
                        wallet.get_path_repr(path), m, forchange, k, addr,
                        [balance, balance], priv=privkey, used=used))
            wallet.set_next_index(m, forchange, unused_index)
            path = wallet.get_path_repr(wallet.get_path(m, forchange))
            branchlist.append(WalletViewBranch(path, m, forchange, entrylist,
                                               xpub=xpub_key))
        ipb = get_imported_privkey_branch(wallet, m, showprivkey)
        if ipb:
            branchlist.append(ipb)
        #get the xpub key of the whole account
        xpub_account = wallet.get_bip32_pub_export(mixdepth=m)
        path = wallet.get_path_repr(wallet.get_path(m))
        acctlist.append(WalletViewAccount(path, m, branchlist,
                                          xpub=xpub_account))
    path = wallet.get_path_repr(wallet.get_path())
    walletview = WalletView(path, acctlist)
    if serialized:
        return walletview.serialize(summarize=summarized)
    else:
        return walletview

def cli_get_wallet_passphrase_check():
    password = get_password('Enter wallet file encryption passphrase: ')
    password2 = get_password('Reenter wallet file encryption passphrase: ')
    if password != password2:
        print('ERROR. Passwords did not match')
        return False
    return password

def cli_get_wallet_file_name():
    return input('Input wallet file name (default: wallet.jmdat): ')

def cli_display_user_words(words, mnemonic_extension):
    text = 'Write down this wallet recovery mnemonic\n\n' + words +'\n'
    if mnemonic_extension:
        text += '\nAnd this mnemonic extension: ' + mnemonic_extension + '\n'
    print(text)

def cli_user_mnemonic_entry():
    mnemonic_phrase = input("Input mnemonic recovery phrase: ")
    mnemonic_extension = input("Input mnemonic extension, leave blank if there isnt one: ")
    if len(mnemonic_extension.strip()) == 0:
        mnemonic_extension = None
    return (mnemonic_phrase, mnemonic_extension)

def cli_get_mnemonic_extension():
    uin = input("Would you like to use a two-factor mnemonic recovery "
                    "phrase? write 'n' if you don't know what this is (y/n): ")
    if len(uin) == 0 or uin[0] != 'y':
        print("Not using mnemonic extension")
        return None #no mnemonic extension
    print("Note: This will be stored in a reversible way. Do not reuse!")
    return input("Enter mnemonic extension: ")


def wallet_generate_recover_bip39(method, walletspath, default_wallet_name,
                                  mixdepth=DEFAULT_MIXDEPTH,
                                  callbacks=(cli_display_user_words,
                                             cli_user_mnemonic_entry,
                                             cli_get_wallet_passphrase_check,
                                             cli_get_wallet_file_name,
                                             cli_get_mnemonic_extension)):
    """Optionally provide callbacks:
    0 - display seed
    1 - enter seed (for recovery)
    2 - enter wallet password
    3 - enter wallet file name
    4 - enter mnemonic extension
    The defaults are for terminal entry.
    """
    entropy = None
    mnemonic_extension = None
    if method == "generate":
        mnemonic_extension = callbacks[4]()
    elif method == 'recover':
        words, mnemonic_extension = callbacks[1]()
        mnemonic_extension = mnemonic_extension and mnemonic_extension.strip()
        if not words:
            return False
        try:
            entropy = SegwitLegacyWallet.entropy_from_mnemonic(words)
        except WalletError:
            return False
    else:
        raise Exception("unknown method for wallet creation: '{}'"
                        .format(method))

    password = callbacks[2]()
    if not password:
        return False

    wallet_name = callbacks[3]()
    if wallet_name == "cancelled":
        # currently used only by Qt, because user has option
        # to click cancel in dialog.
        return False
    if not wallet_name:
        wallet_name = default_wallet_name
    wallet_path = os.path.join(walletspath, wallet_name)

    wallet = create_wallet(wallet_path, password, mixdepth,
                           entropy=entropy,
                           entropy_extension=mnemonic_extension)
    mnemonic, mnext = wallet.get_mnemonic_words()
    callbacks[0] and callbacks[0](mnemonic, mnext or '')
    wallet.close()
    return True


def wallet_generate_recover(method, walletspath,
                            default_wallet_name='wallet.jmdat',
                            mixdepth=DEFAULT_MIXDEPTH):
    if is_segwit_mode():
        #Here using default callbacks for scripts (not used in Qt)
        return wallet_generate_recover_bip39(
            method, walletspath, default_wallet_name, mixdepth=mixdepth)

    entropy = None
    if method == 'recover':
        seed = input("Input 12 word recovery seed: ")
        try:
            entropy = LegacyWallet.entropy_from_mnemonic(seed)
        except WalletError as e:
            print("Unable to restore seed: {}".format(e.message))
            return False
    elif method != 'generate':
        raise Exception("unknown method for wallet creation: '{}'"
                        .format(method))

    password = cli_get_wallet_passphrase_check()
    if not password:
        return False

    wallet_name = cli_get_wallet_file_name()
    if not wallet_name:
        wallet_name = default_wallet_name
    wallet_path = os.path.join(walletspath, wallet_name)

    wallet = create_wallet(wallet_path, password, mixdepth,
                           wallet_cls=LegacyWallet, entropy=entropy)
    print("Write down and safely store this wallet recovery seed\n\n{}\n"
          .format(wallet.get_mnemonic_words()[0]))
    wallet.close()
    return True


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def wallet_fetch_history(wallet, options):
    # sort txes in a db because python can be really bad with large lists
    con = sqlite3.connect(":memory:")
    con.row_factory = dict_factory
    tx_db = con.cursor()
    tx_db.execute("CREATE TABLE transactions(txid TEXT, "
            "blockhash TEXT, blocktime INTEGER);")
    jm_single().debug_silence[0] = True
    wallet_name = jm_single().bc_interface.get_wallet_name(wallet)
    buf = range(1000)
    t = 0
    while len(buf) == 1000:
        buf = jm_single().bc_interface.rpc('listtransactions', ["*",
            1000, t, True])
        t += len(buf)
        tx_data = ((tx['txid'], tx['blockhash'], tx['blocktime']) for tx
                in buf if 'txid' in tx and 'blockhash' in tx and 'blocktime'
                in tx)
        tx_db.executemany('INSERT INTO transactions VALUES(?, ?, ?);',
                tx_data)

    txes = tx_db.execute(
        'SELECT DISTINCT txid, blockhash, blocktime '
        'FROM transactions ORDER BY blocktime').fetchall()
    wallet_script_set = set(wallet.get_script_path(p)
                            for p in wallet.yield_known_paths())

    def s():
        return ',' if options.csv else ' '
    def sat_to_str(sat):
        return '%.8f'%(sat/1e8)
    def sat_to_str_p(sat):
        return '%+.8f'%(sat/1e8)
    def skip_n1(v):
        return '% 2s'%(str(v)) if v != -1 else ' #'
    def skip_n1_btc(v):
        return sat_to_str(v) if v != -1 else '#' + ' '*10
    def print_row(index, time, tx_type, amount, delta, balance, cj_n,
                  miner_fees, utxo_count, mixdepth_src, mixdepth_dst, txid):
        data = [index, datetime.fromtimestamp(time).strftime("%Y-%m-%d %H:%M"),
                tx_type, sat_to_str(amount), sat_to_str_p(delta),
                sat_to_str(balance), skip_n1(cj_n), sat_to_str(miner_fees),
                '% 3d' % utxo_count, skip_n1(mixdepth_src), skip_n1(mixdepth_dst)]
        if options.verbosity % 2 == 0: data += [txid]
        print(s().join(map('"{}"'.format, data)))


    field_names = ['tx#', 'timestamp', 'type', 'amount/btc',
            'balance-change/btc', 'balance/btc', 'coinjoin-n', 'total-fees',
            'utxo-count', 'mixdepth-from', 'mixdepth-to']
    if options.verbosity % 2 == 0: field_names += ['txid']
    if options.csv:
        print('Bumping verbosity level to 4 due to --csv flag')
        options.verbosity = 4
    if options.verbosity > 0: print(s().join(field_names))
    if options.verbosity <= 2: cj_batch = [0]*8 + [[]]*2
    balance = 0
    utxo_count = 0
    deposits = []
    deposit_times = []
    tx_number = 0
    for tx in txes:
        is_coinjoin, cj_amount, cj_n, output_script_values, blocktime, txd =\
            get_tx_info(tx['txid'])

        our_output_scripts = wallet_script_set.intersection(
            output_script_values.keys())

        rpc_inputs = []
        for ins in txd['ins']:
            try:
                wallet_tx = jm_single().bc_interface.rpc('gettransaction',
                        [ins['outpoint']['hash']])
            except JsonRpcError:
                continue
            input_dict = btc.deserialize(str(wallet_tx['hex']))['outs'][ins[
                'outpoint']['index']]
            rpc_inputs.append(input_dict)

        rpc_input_scripts = set(binascii.unhexlify(ind['script'])
                                for ind in rpc_inputs)
        our_input_scripts = wallet_script_set.intersection(rpc_input_scripts)
        our_input_values = [
            ind['value'] for ind in rpc_inputs
            if binascii.unhexlify(ind['script']) in our_input_scripts]
        our_input_value = sum(our_input_values)
        utxos_consumed = len(our_input_values)

        tx_type = None
        amount = 0
        delta_balance = 0
        fees = 0
        mixdepth_src = -1
        mixdepth_dst = -1
        #TODO this seems to assume all the input addresses are from the same
        # mixdepth, which might not be true
        if len(our_input_scripts) == 0 and len(our_output_scripts) > 0:
            #payment to us
            amount = sum([output_script_values[a] for a in our_output_scripts])
            tx_type = 'deposit    '
            cj_n = -1
            delta_balance = amount
            mixdepth_dst = tuple(wallet.get_script_mixdepth(a)
                                 for a in our_output_scripts)
            if len(mixdepth_dst) == 1:
                mixdepth_dst = mixdepth_dst[0]
        elif len(our_input_scripts) == 0 and len(our_output_scripts) == 0:
            continue            # skip those that don't belong to our wallet
        elif len(our_input_scripts) > 0 and len(our_output_scripts) == 0:
            # we swept coins elsewhere
            if is_coinjoin:
                tx_type = 'cj sweepout'
                amount = cj_amount
                fees = our_input_value - cj_amount
            else:
                tx_type = 'sweep out  '
                amount = sum([v for v in output_script_values.values()])
                fees = our_input_value - amount
            delta_balance = -our_input_value
            mixdepth_src = wallet.get_script_mixdepth(list(our_input_scripts)[0])
        elif len(our_input_scripts) > 0 and len(our_output_scripts) == 1:
            # payment to somewhere with our change address getting the remaining
            change_value = output_script_values[list(our_output_scripts)[0]]
            if is_coinjoin:
                tx_type = 'cj withdraw'
                amount = cj_amount
            else:
                tx_type = 'withdraw'
                #TODO does tx_fee go here? not my_tx_fee only?
                amount = our_input_value - change_value
                cj_n = -1
            delta_balance = change_value - our_input_value
            fees = our_input_value - change_value - cj_amount
            mixdepth_src = wallet.get_script_mixdepth(list(our_input_scripts)[0])
        elif len(our_input_scripts) > 0 and len(our_output_scripts) == 2:
            #payment to self
            out_value = sum([output_script_values[a] for a in our_output_scripts])
            if not is_coinjoin:
                print('this is wrong TODO handle non-coinjoin internal')
            tx_type = 'cj internal'
            amount = cj_amount
            delta_balance = out_value - our_input_value
            mixdepth_src = wallet.get_script_mixdepth(list(our_input_scripts)[0])
            cj_script = list(set([a for a, v in iteritems(output_script_values)
                if v == cj_amount]).intersection(our_output_scripts))[0]
            mixdepth_dst = wallet.get_script_mixdepth(cj_script)
        else:
            tx_type = 'unknown type'
            print('our utxos: ' + str(len(our_input_scripts)) \
                  + ' in, ' + str(len(our_output_scripts)) + ' out')
        balance += delta_balance
        utxo_count += (len(our_output_scripts) - utxos_consumed)
        index = '%4d'%(tx_number)
        tx_number += 1
        if options.verbosity > 0:
            if options.verbosity <= 2:
                n = cj_batch[0]
                if tx_type == 'cj internal':
                    cj_batch[0] += 1
                    cj_batch[1] += blocktime
                    cj_batch[2] += amount
                    cj_batch[3] += delta_balance
                    cj_batch[4] = balance
                    cj_batch[5] += cj_n
                    cj_batch[6] += fees
                    cj_batch[7] += utxo_count
                    cj_batch[8] += [mixdepth_src]
                    cj_batch[9] += [mixdepth_dst]
                elif tx_type != 'unknown type':
                    if n > 0:
                        # print the previously-accumulated batch
                        print_row('N='+"%2d"%n, cj_batch[1]/n, 'cj batch   ',
                                  cj_batch[2], cj_batch[3], cj_batch[4],
                                  cj_batch[5]/n, cj_batch[6], cj_batch[7]/n,
                                  min(cj_batch[8]), max(cj_batch[9]), '...')
                    cj_batch = [0]*8 + [[]]*2 # reset the batch collector
                    # print batch terminating row
                    print_row(index, blocktime, tx_type, amount,
                              delta_balance, balance, cj_n, fees, utxo_count,
                              mixdepth_src, mixdepth_dst, tx['txid'])
            elif options.verbosity >= 5 or \
                 (options.verbosity >= 3 and tx_type != 'unknown type'):
                print_row(index, blocktime, tx_type, amount,
                          delta_balance, balance, cj_n, fees, utxo_count,
                          mixdepth_src, mixdepth_dst, tx['txid'])

        if tx_type != 'cj internal':
            deposits.append(delta_balance)
            deposit_times.append(blocktime)

    # we could have a leftover batch!
    if options.verbosity <= 2:
        n = cj_batch[0]
        if n > 0:
            print_row('N='+"%2d"%n, cj_batch[1]/n, 'cj batch   ', cj_batch[2],
                      cj_batch[3], cj_batch[4], cj_batch[5]/n, cj_batch[6],
                      cj_batch[7]/n, min(cj_batch[8]), max(cj_batch[9]), '...')


    bestblockhash = jm_single().bc_interface.rpc('getbestblockhash', [])
    try:
        #works with pruning enabled, but only after v0.12
        now = jm_single().bc_interface.rpc('getblockheader', [bestblockhash]
                )['time']
    except JsonRpcError:
        now = jm_single().bc_interface.rpc('getblock', [bestblockhash])['time']
    print('     %s best block is %s' % (datetime.fromtimestamp(now)
        .strftime("%Y-%m-%d %H:%M"), bestblockhash))
    total_profit = float(balance - sum(deposits)) / float(100000000)
    print('total profit = %.8f BTC' % total_profit)

    if abs(total_profit) > 0:
        try:
            # https://gist.github.com/chris-belcher/647da261ce718fc8ca10
            import numpy as np
            from scipy.optimize import brentq
            deposit_times = np.array(deposit_times)
            now -= deposit_times[0]
            deposit_times -= deposit_times[0]
            deposits = np.array(deposits)
            def f(r, deposits, deposit_times, now, final_balance):
                return np.sum(np.exp((now - deposit_times) / 60.0 / 60 / 24 /
                    365)**r * deposits) - final_balance
            r = brentq(f, a=1, b=-1, args=(deposits, deposit_times, now, balance))
            print('continuously compounded equivalent annual interest rate = ' +
                str(r * 100) + ' %')
            print('(as if yield generator was a bank account)')
        except ImportError:
            print('scipy not installed, unable to predict accumulation rate')
            print('to add it to this virtualenv, use `pip install scipy`')

    total_wallet_balance = sum(wallet.get_balance_by_mixdepth().values())
    if balance != total_wallet_balance:
        print(('BUG ERROR: wallet balance (%s) does not match balance from ' +
            'history (%s)') % (sat_to_str(total_wallet_balance),
                sat_to_str(balance)))
    wallet_utxo_count = sum(map(len, wallet.get_utxos_by_mixdepth_().values()))
    if utxo_count != wallet_utxo_count:
        print(('BUG ERROR: wallet utxo count (%d) does not match utxo count from ' +
            'history (%s)') % (wallet_utxo_count, utxo_count))


def wallet_showseed(wallet):
    seed, extension = wallet.get_mnemonic_words()
    text = "Wallet mnemonic recovery phrase:\n\n{}\n".format(seed)
    if extension:
        text += "\nWallet mnemonic extension: {}\n".format(extension)
    return text


def wallet_importprivkey(wallet, mixdepth, key_type):
    print("WARNING: This imported key will not be recoverable with your 12 "
          "word mnemonic phrase. Make sure you have backups.")
    print("WARNING: Handling of raw ECDSA bitcoin private keys can lead to "
          "non-intuitive behaviour and loss of funds.\n  Recommended instead "
          "is to use the \'sweep\' feature of sendpayment.py.")
    privkeys = input("Enter private key(s) to import: ")
    privkeys = privkeys.split(',') if ',' in privkeys else privkeys.split()
    imported_addr = []
    import_failed = 0
    # TODO read also one key for each line
    for wif in privkeys:
        # TODO is there any point in only accepting wif format? check what
        # other wallets do
        try:
            path = wallet.import_private_key(mixdepth, wif, key_type=key_type)
        except WalletError as e:
            print("Failed to import key {}: {}".format(wif, e))
            import_failed += 1
        else:
            imported_addr.append(wallet.get_addr_path(path))

    if not imported_addr:
        print("Warning: No keys imported!")
        return

    wallet.save()

    # show addresses to user so they can verify everything went as expected
    print("Imported keys for addresses:\n{}".format('\n'.join(imported_addr)))
    if import_failed:
        print("Warning: failed to import {} keys".format(import_failed))


def wallet_dumpprivkey(wallet, hdpath):
    if not hdpath:
        print("Error: no hd wallet path supplied")
        return False
    path = wallet.path_repr_to_path(hdpath)
    return wallet.get_wif_path(path)  # will raise exception on invalid path


def wallet_signmessage(wallet, hdpath, message):
    msg = message.encode('utf-8')

    if not hdpath:
        return "Error: no key path for signing specified"
    if not message:
        return "Error: no message specified"

    path = wallet.path_repr_to_path(hdpath)
    sig = wallet.sign_message(msg, path)
    return ("Signature: {}\n"
            "To verify this in Bitcoin Core use the RPC command 'verifymessage'"
            .format(sig))


def get_wallet_type():
    if is_segwit_mode():
        return TYPE_P2SH_P2WPKH
    return TYPE_P2PKH


def get_wallet_cls(wtype=None):
    if wtype is None:
        wtype = get_wallet_type()

    cls = WALLET_IMPLEMENTATIONS.get(wtype)

    if not cls:
        raise WalletError("No wallet implementation found for type {}."
                          "".format(wtype))
    return cls


def create_wallet(path, password, max_mixdepth, wallet_cls=None, **kwargs):
    storage = Storage(path, password, create=True)
    wallet_cls = wallet_cls or get_wallet_cls()
    wallet_cls.initialize(storage, get_network(), max_mixdepth=max_mixdepth,
                          **kwargs)
    storage.save()
    return wallet_cls(storage)


def open_test_wallet_maybe(path, seed, max_mixdepth,
                           test_wallet_cls=SegwitLegacyWallet, **kwargs):
    """
    Create a volatile test wallet if path is a hex-encoded string of length 64,
    otherwise run open_wallet().

    params:
        path: path to wallet file, ignored for test wallets
        seed: hex-encoded test seed
        max_mixdepth: maximum mixdepth to use
        kwargs: see open_wallet()

    returns:
        wallet object
    """
    if len(seed) == test_wallet_cls.ENTROPY_BYTES * 2:
        try:
            seed = binascii.unhexlify(seed)
        except binascii.Error:
            pass
        else:
            if max_mixdepth is None:
                max_mixdepth = DEFAULT_MIXDEPTH

            storage = VolatileStorage()
            test_wallet_cls.initialize(
                storage, get_network(), max_mixdepth=max_mixdepth,
                entropy=seed)
            #wallet instantiation insists on no unexpected kwargs,
            #but Qt caller opens both test and mainnet with same args,
            #hence these checks/deletes of unwanted args for tests.
            if 'ask_for_password' in kwargs:
                del kwargs['ask_for_password']
            if 'password' in kwargs:
                del kwargs['password']
            if 'read_only' in kwargs:
                del kwargs['read_only']
            return test_wallet_cls(storage, **kwargs)

    return open_wallet(path, mixdepth=max_mixdepth, **kwargs)


def open_wallet(path, ask_for_password=True, password=None, read_only=False,
                **kwargs):
    """
    Open the wallet file at path and return the corresponding wallet object.

    params:
        path: str, full path to wallet file
        ask_for_password: bool, if False password is assumed unset and user
            will not be asked to type it
        password: password for storage, ignored if ask_for_password is True
        read_only: bool, if True, open wallet in read-only mode
        kwargs: additional options to pass to wallet's init method

    returns:
        wallet object
    """
    if not os.path.isfile(path):
        raise Exception("Failed to open wallet at '{}': not a file".format(path))

    if not Storage.is_storage_file(path):
        raise Exception("Failed to open wallet at '{}': not a valid joinmarket"
                        " wallet.\n\nIf this wallet is in the old json format "
                        "you need to convert it using the conversion script"
                        "at `scripts/convert_old_wallet.py`".format(path))

    if ask_for_password and Storage.is_encrypted_storage_file(path):
        while True:
            try:
                # do not try empty password, assume unencrypted on empty password
                pwd = get_password("Enter wallet decryption passphrase: ") or None
                storage = Storage(path, password=pwd, read_only=read_only)
            except StoragePasswordError:
                print("Wrong password, try again.")
                continue
            except Exception as e:
                print("Failed to load wallet, error message: " + repr(e))
                raise e
            break
    else:
        storage = Storage(path, password, read_only=read_only)

    wallet_cls = get_wallet_cls_from_storage(storage)
    wallet = wallet_cls(storage, **kwargs)
    wallet_sanity_check(wallet)
    return wallet


def get_wallet_cls_from_storage(storage):
    wtype = storage.data.get(b'wallet_type')

    if wtype is None:
        raise WalletError("File {} is not a valid wallet.".format(storage.path))

    return get_wallet_cls(wtype)


def wallet_sanity_check(wallet):
    if wallet.network != get_network():
        raise Exception("Wallet network mismatch: we are on '{}' but wallet "
                        "is on '{}'.".format(get_network(), wallet.network))


def get_wallet_path(file_name, wallet_dir):
    # TODO: move default wallet path to ~/.joinmarket
    wallet_dir = wallet_dir or 'wallets'
    return os.path.join(wallet_dir, file_name)


def wallet_tool_main(wallet_root_path):
    """Main wallet tool script function; returned is a string (output or error)
    """
    parser = get_wallettool_parser()
    (options, args) = parser.parse_args()

    noseed_methods = ['generate', 'recover']
    methods = ['display', 'displayall', 'summary', 'showseed', 'importprivkey',
               'history', 'showutxos']
    methods.extend(noseed_methods)
    noscan_methods = ['showseed', 'importprivkey', 'dumpprivkey', 'signmessage']
    readonly_methods = ['display', 'displayall', 'summary', 'showseed',
                        'history', 'showutxos', 'dumpprivkey', 'signmessage']

    if len(args) < 1:
        parser.error('Needs a wallet file or method')
        sys.exit(0)

    if options.mixdepth is not None and options.mixdepth < 0:
        parser.error("Must have at least one mixdepth.")
        sys.exit(0)

    if args[0] in noseed_methods:
        method = args[0]
        if options.mixdepth is None:
            options.mixdepth = DEFAULT_MIXDEPTH
    else:
        seed = args[0]
        wallet_path = get_wallet_path(seed, wallet_root_path)
        method = ('display' if len(args) == 1 else args[1].lower())
        read_only = method in readonly_methods

        wallet = open_test_wallet_maybe(
            wallet_path, seed, options.mixdepth, read_only=read_only,
            gap_limit=options.gaplimit)

        if method not in noscan_methods:
            # if nothing was configured, we override bitcoind's options so that
            # unconfirmed balance is included in the wallet display by default
            if 'listunspent_args' not in jm_single().config.options('POLICY'):
                jm_single().config.set('POLICY','listunspent_args', '[0]')
            while not jm_single().bc_interface.wallet_synced:
                sync_wallet(wallet, fast=options.fastsync)
    #Now the wallet/data is prepared, execute the script according to the method
    if method == "display":
        return wallet_display(wallet, options.gaplimit, options.showprivkey)
    elif method == "displayall":
        return wallet_display(wallet, options.gaplimit, options.showprivkey,
                              displayall=True)
    elif method == "summary":
        return wallet_display(wallet, options.gaplimit, options.showprivkey, summarized=True)
    elif method == "history":
        if not isinstance(jm_single().bc_interface, BitcoinCoreInterface):
            print('showing history only available when using the Bitcoin Core ' +
                    'blockchain interface')
            sys.exit(0)
        else:
            return wallet_fetch_history(wallet, options)
    elif method == "generate":
        retval = wallet_generate_recover("generate", wallet_root_path,
                                         mixdepth=options.mixdepth)
        return retval if retval else "Failed"
    elif method == "recover":
        retval = wallet_generate_recover("recover", wallet_root_path,
                                         mixdepth=options.mixdepth)
        return retval if retval else "Failed"
    elif method == "showutxos":
        return wallet_showutxos(wallet, options.showprivkey)
    elif method == "showseed":
        return wallet_showseed(wallet)
    elif method == "dumpprivkey":
        return wallet_dumpprivkey(wallet, options.hd_path)
    elif method == "importprivkey":
        #note: must be interactive (security)
        if options.mixdepth is None:
            parser.error("You need to specify a mixdepth with -m")
        wallet_importprivkey(wallet, options.mixdepth,
                             map_key_type(options.key_type))
        return "Key import completed."
    elif method == "signmessage":
        return wallet_signmessage(wallet, options.hd_path, args[2])


#Testing (can port to test modules, TODO)
if __name__ == "__main__":
    if not test_bip32_pathparse():
        sys.exit(0)
    rootpath="m/0"
    walletbranch = 0
    accounts = range(3)
    acctlist = []
    for a in accounts:
        branches = []
        for forchange in range(2):
            entries = []
            for i in range(4):
                entries.append(WalletViewEntry(rootpath, a, forchange,
                                       i, "DUMMYADDRESS"+str(i+a),
                                       [i*10000000, i*10000000]))
            branches.append(WalletViewBranch(rootpath,
                                            a, forchange, branchentries=entries,
                                            xpub="xpubDUMMYXPUB"+str(a+forchange)))
        acctlist.append(WalletViewAccount(rootpath, a, branches=branches))
    wallet = WalletView(rootpath + "/" + str(walletbranch),
                             accounts=acctlist)
    print(wallet.serialize())

