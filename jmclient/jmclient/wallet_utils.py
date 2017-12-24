from __future__ import print_function
import json
import os
import pprint
import sys
import sqlite3
import binascii
from datetime import datetime
from mnemonic import Mnemonic
from optparse import OptionParser
import getpass
from jmclient import (get_network, WALLET_IMPLEMENTATIONS, Storage, podle,
    encryptData, get_p2sh_vbyte, get_p2pk_vbyte, jm_single, mn_decode,
    mn_encode, BitcoinCoreInterface, JsonRpcError, sync_wallet, WalletError,
    BIP49Wallet, ImportWalletMixin, VolatileStorage, StoragePasswordError)
from jmbase.support import get_password
import jmclient.btc as btc

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
                      '--maxmixdepth',
                      action='store',
                      type='int',
                      dest='maxmixdepth',
                      help='how many mixing depths to display, default=5')
    parser.add_option('-g',
                      '--gap-limit',
                      type="int",
                      action='store',
                      dest='gaplimit',
                      help='gap limit for wallet, default=6',
                      default=6)
    parser.add_option('-M',
                      '--mix-depth',
                      type="int",
                      action='store',
                      dest='mixdepth',
                      help='mixing depth to import private key into',
                      default=0)
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
    return parser


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
    def __init__(self, bip32path, children=None, serclass=str,
                 custom_separator=None):
        assert bip32pathparse(bip32path)
        self.bip32path = bip32path
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
    def __init__(self, bip32path, account, forchange, aindex, addr, amounts,
                 used = 'new', serclass=str, priv=None, custom_separator=None):
        self.bip32path = bip32path
        super(WalletViewEntry, self).__init__(bip32path, serclass=serclass,
                                             custom_separator=custom_separator)
        self.account = account
        assert forchange in [0, 1, -1]
        self.forchange =forchange
        assert isinstance(aindex, int)
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
        bippath = self.bip32path + bip32sep + str(self.account) + "'" + \
        bip32sep + str(self.forchange) + bip32sep + "{0:03d}".format(self.aindex)
        assert bip32pathparse(bippath)
        return self.serclass(bippath)

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
    def __init__(self, bip32path, account, forchange, branchentries=None,
                 xpub=None, serclass=str, custom_separator=None):
        super(WalletViewBranch, self).__init__(bip32path, children=branchentries,
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
        bippath = self.bip32path + bip32sep + str(self.account) + "'" + \
            bip32sep + str(self.forchange)
        assert bip32pathparse(bippath)
        start = "external addresses" if self.forchange == 0 else "internal addresses"
        if self.forchange == -1:
            start = "Imported keys"
        return self.serclass(self.separator.join([start, bippath, self.xpub]))

class WalletViewAccount(WalletViewBase):
    def __init__(self, bip32path, account, branches=None, account_name="mixdepth",
                 serclass=str, custom_separator=None, xpub=None):
        super(WalletViewAccount, self).__init__(bip32path, children=branches,
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
    def __init__(self, bip32path, accounts, wallet_name="JM wallet",
                 serclass=str, custom_separator=None):
        super(WalletView, self).__init__(bip32path, children=accounts,
                                              serclass=serclass,
                                              custom_separator=custom_separator)
        self.bip32path = bip32path
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

def get_imported_privkey_branch(wallet, m, showprivkey):
    if m in wallet.imported_privkeys:
        entries = []
        for i, privkey in enumerate(wallet.imported_privkeys[m]):
            pub = btc.privkey_to_pubkey(privkey)
            addr = btc.pubkey_to_p2sh_p2wpkh_address(pub, magicbyte=get_p2sh_vbyte())
            balance = 0.0
            for addrvalue in wallet.unspent.values():
                if addr == addrvalue['address']:
                    balance += addrvalue['value']
            used = ('used' if balance > 0.0 else 'empty')
            if showprivkey:
                wip_privkey = btc.wif_compressed_privkey(
                privkey, get_p2pk_vbyte())
            else:
                wip_privkey = ''
            entries.append(WalletViewEntry("m/0", m, -1,
                                           i, addr, [balance, balance],
                                           used=used,priv=wip_privkey))
        return WalletViewBranch("m/0", m, -1, branchentries=entries)
    return None

def wallet_showutxos(wallet, showprivkey):
    unsp = {}
    max_tries = jm_single().config.getint("POLICY", "taker_utxo_retries")
    for u, av in wallet.unspent.iteritems():
        key = wallet.get_key_from_addr(av['address'])
        tries = podle.get_podle_tries(u, key, max_tries)
        tries_remaining = max(0, max_tries - tries)
        unsp[u] = {'address': av['address'], 'value': av['value'],
                   'tries': tries, 'tries_remaining': tries_remaining,
                   'external': False}
        if showprivkey:
            wifkey = btc.wif_compressed_privkey(key, vbyte=get_p2pk_vbyte())
            unsp[u]['privkey'] = wifkey

    used_commitments, external_commitments = podle.get_podle_commitments()
    for u, ec in external_commitments.iteritems():
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
    acctlist = []
    rootpath = wallet.get_root_path()
    for m in xrange(wallet.max_mixdepth):
        branchlist = []
        for forchange in [0, 1]:
            entrylist = []
            # FIXME: why does this if/else exist?
            if forchange == 0:
                xpub_key = wallet.get_bip32_pub_export(m, forchange)
            else:
                xpub_key = ""

            for k in xrange(wallet.get_next_unused_index(m, forchange) + gaplimit):
                path = wallet.get_path(m, forchange, k)
                addr = wallet.get_addr_path(path)
                balance = 0
                for utxodata in wallet.get_utxos_by_mixdepth_()[m].values():
                    if path == utxodata['path']:
                        balance += utxodata['value']
                used = 'used' if k < wallet.get_next_unused_index(m, forchange) else 'new'
                if showprivkey:
                    privkey = wallet.get_wif_path(path)
                else:
                    privkey = ''
                if (displayall or balance > 0 or
                    (used == 'new' and forchange == 0)):
                    entrylist.append(WalletViewEntry(rootpath, m, forchange, k,
                                                 addr, [balance, balance],
                                                 priv=privkey, used=used))
            branchlist.append(WalletViewBranch(rootpath, m, forchange,
                entrylist, xpub=xpub_key))
        ipb = get_imported_privkey_branch(wallet, m, showprivkey)
        if ipb:
            branchlist.append(ipb)
        #get the xpub key of the whole account
        xpub_account = wallet.get_bip32_pub_export(mixdepth=m)
        acctlist.append(WalletViewAccount(rootpath, m, branchlist,
                                          xpub=xpub_account))
    walletview = WalletView(rootpath, acctlist)
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
    return raw_input('Input wallet file name (default: wallet.json): ')

def cli_display_user_words(words, mnemonic_extension):
    text = 'Write down this wallet recovery mnemonic\n\n' + words +'\n'
    if mnemonic_extension:
        text += '\nAnd this mnemonic extension: ' + mnemonic_extension + '\n'
    print(text)

def cli_user_mnemonic_entry():
    mnemonic_phrase = raw_input("Input 12 word mnemonic recovery phrase: ")
    mnemonic_extension = raw_input("Input mnemonic extension, leave blank if there isnt one: ")
    if len(mnemonic_extension.strip()) == 0:
        mnemonic_extension = None
    return (mnemonic_phrase, mnemonic_extension)

def cli_get_mnemonic_extension():
    uin = raw_input("Would you like to use a two-factor mnemonic recovery "
                    "phrase? write 'n' if you don't know what this is (y/n): ")
    if len(uin) == 0 or uin[0] != 'y':
        print("Not using mnemonic extension")
        return None #no mnemonic extension
    print("Note: This will be stored in a reversible way. Do not reuse!")
    return raw_input("Enter mnemonic extension: ")


def persist_walletfile(walletspath, default_wallet_name, encrypted_entropy,
                       encrypted_mnemonic_extension=None,
                       callbacks=(cli_get_wallet_file_name,)):
    timestamp = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    walletjson = {'creator': 'joinmarket project',
                  'creation_time': timestamp,
                  'encrypted_entropy': encrypted_entropy.encode('hex'),
                  'network': get_network()}
    if encrypted_mnemonic_extension:
        walletjson['encrypted_mnemonic_extension'] = encrypted_mnemonic_extension.encode('hex')
    walletfile = json.dumps(walletjson)
    walletname = callbacks[0]()
    if len(walletname) == 0:
        walletname = default_wallet_name
    walletpath = os.path.join(walletspath, walletname)
    # Does a wallet with the same name exist?
    if os.path.isfile(walletpath):
        print('ERROR: ' + walletpath + ' already exists. Aborting.')
        return False
    else:
        fd = open(walletpath, 'w')
        fd.write(walletfile)
        fd.close()
        print('saved to ' + walletname)
    return True

def wallet_generate_recover_bip39(method, walletspath, default_wallet_name,
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
    #using 128 bit entropy, 12 words, mnemonic module
    m = Mnemonic("english")
    if method == "generate":
        mnemonic_extension = callbacks[4]()
        words = m.generate()
        callbacks[0](words, mnemonic_extension)
    elif method == 'recover':
        words, mnemonic_extension = callbacks[1]()
        if not words:
            return False
    entropy = str(m.to_entropy(words))
    password = callbacks[2]()
    if not password:
        return False
    password_key = btc.bin_dbl_sha256(password)
    encrypted_entropy = encryptData(password_key, entropy)
    encrypted_mnemonic_extension = None
    if mnemonic_extension:
        mnemonic_extension = mnemonic_extension.strip()
        #check all ascii printable
        if not all([a > '\x19' and a < '\x7f' for a in mnemonic_extension]):
            return False
        #padding to stop an adversary easily telling how long the mn extension is
        #padding at the start because of how aes blocks are combined
        #checksum in order to tell whether the decryption was successful
        cleartext_length = 79
        padding_length = cleartext_length - 10 - len(mnemonic_extension)
        if padding_length > 0:
            padding = os.urandom(padding_length).replace('\xff', '\xfe')
        else:
            padding = ''
        cleartext = (padding + '\xff' + mnemonic_extension + '\xff'
            + btc.dbl_sha256(mnemonic_extension)[:8])
        encrypted_mnemonic_extension = encryptData(password_key, cleartext)
    return persist_walletfile(walletspath, default_wallet_name, encrypted_entropy,
                              encrypted_mnemonic_extension, callbacks=(callbacks[3],))

def wallet_generate_recover(method, walletspath,
                            default_wallet_name='wallet.json'):
    if jm_single().config.get("POLICY", "segwit") == "true":
        #Here using default callbacks for scripts (not used in Qt)
        return wallet_generate_recover_bip39(method, walletspath,
                                             default_wallet_name)
    if method == 'generate':
        seed = btc.sha256(os.urandom(64))[:32]
        words = mn_encode(seed)
        print('Write down this wallet recovery seed\n\n' + ' '.join(words) +
              '\n')
    elif method == 'recover':
        words = raw_input('Input 12 word recovery seed: ')
        words = words.split()  # default for split is 1 or more whitespace chars
        if len(words) != 12:
            print('ERROR: Recovery seed phrase must be exactly 12 words.')
            return False
        seed = mn_decode(words)
        print(seed)
    password = cli_get_wallet_passphrase_check()
    if not password:
        return False
    password_key = btc.bin_dbl_sha256(password)
    encrypted_seed = encryptData(password_key, seed.decode('hex'))
    return persist_walletfile(walletspath, default_wallet_name, encrypted_seed)

def wallet_fetch_history(wallet, options):
    # sort txes in a db because python can be really bad with large lists
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    tx_db = con.cursor()
    tx_db.execute("CREATE TABLE transactions(txid TEXT, "
            "blockhash TEXT, blocktime INTEGER);")
    jm_single().debug_silence[0] = True
    wallet_name = jm_single().bc_interface.get_wallet_name(wallet)
    for wn in [wallet_name, ""]:
        buf = range(1000)
        t = 0
        while len(buf) == 1000:
            buf = jm_single().bc_interface.rpc('listtransactions', [wn,
                1000, t, True])
            t += len(buf)
            tx_data = ((tx['txid'], tx['blockhash'], tx['blocktime']) for tx
                    in buf if 'txid' in tx and 'blockhash' in tx and 'blocktime'
                    in tx)
            tx_db.executemany('INSERT INTO transactions VALUES(?, ?, ?);',
                    tx_data)
            txes = tx_db.execute('SELECT DISTINCT txid, blockhash, blocktime '
                    'FROM transactions ORDER BY blocktime').fetchall()
            wallet_addr_cache = wallet.addr_cache
    wallet_addr_set = set(wallet_addr_cache.keys())

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
    for i, tx in enumerate(txes):
        rpctx = jm_single().bc_interface.rpc('gettransaction', [tx['txid']])
        txhex = str(rpctx['hex'])
        txd = btc.deserialize(txhex)
        output_addr_values = dict(((btc.script_to_address(sv['script'],
            get_p2sh_vbyte()), sv['value']) for sv in txd['outs']))
        our_output_addrs = wallet_addr_set.intersection(
                output_addr_values.keys())

        from collections import Counter
        value_freq_list = sorted(Counter(output_addr_values.values())
                .most_common(), key=lambda x: -x[1])
        non_cj_freq = 0 if len(value_freq_list)==1 else sum(zip(
            *value_freq_list[1:])[1])
        is_coinjoin = (value_freq_list[0][1] > 1 and value_freq_list[0][1] in
                [non_cj_freq, non_cj_freq+1])
        cj_amount = value_freq_list[0][0]
        cj_n = value_freq_list[0][1]

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

        rpc_input_addrs = set((btc.script_to_address(ind['script'],
            get_p2sh_vbyte()) for ind in rpc_inputs))
        our_input_addrs = wallet_addr_set.intersection(rpc_input_addrs)
        our_input_values = [ind['value'] for ind in rpc_inputs if btc.
                script_to_address(ind['script'], get_p2sh_vbyte()) in
                our_input_addrs]
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
        if len(our_input_addrs) == 0 and len(our_output_addrs) > 0:
            #payment to us
            amount = sum([output_addr_values[a] for a in our_output_addrs])
            tx_type = 'deposit    '
            cj_n = -1
            delta_balance = amount
            mixdepth_dst = tuple(wallet_addr_cache[a][0] for a in
                    our_output_addrs)
            if len(mixdepth_dst) == 1:
                mixdepth_dst = mixdepth_dst[0]
        elif len(our_input_addrs) == 0 and len(our_output_addrs) == 0:
            continue            # skip those that don't belong to our wallet
        elif len(our_input_addrs) > 0 and len(our_output_addrs) == 0:
            # we swept coins elsewhere
            if is_coinjoin:
                tx_type = 'cj sweepout'
                amount = cj_amount
                fees = our_input_value - cj_amount
            else:
                tx_type = 'sweep out  '
                amount = sum([v for v in output_addr_values.values()])
                fees = our_input_value - amount
            delta_balance = -our_input_value
            mixdepth_src = wallet_addr_cache[list(our_input_addrs)[0]][0]
        elif len(our_input_addrs) > 0 and len(our_output_addrs) == 1:
            # payment to somewhere with our change address getting the remaining
            change_value = output_addr_values[list(our_output_addrs)[0]]
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
            mixdepth_src = wallet_addr_cache[list(our_input_addrs)[0]][0]
        elif len(our_input_addrs) > 0 and len(our_output_addrs) == 2:
            #payment to self
            out_value = sum([output_addr_values[a] for a in our_output_addrs])
            if not is_coinjoin:
                print('this is wrong TODO handle non-coinjoin internal')
            tx_type = 'cj internal'
            amount = cj_amount
            delta_balance = out_value - our_input_value
            mixdepth_src = wallet_addr_cache[list(our_input_addrs)[0]][0]
            cj_addr = list(set([a for a,v in output_addr_values.iteritems()
                if v == cj_amount]).intersection(our_output_addrs))[0]
            mixdepth_dst = wallet_addr_cache[cj_addr][0]
        else:
            tx_type = 'unknown type'
            print('our utxos: ' + str(len(our_input_addrs)) \
                  + ' in, ' + str(len(our_output_addrs)) + ' out')
        balance += delta_balance
        utxo_count += (len(our_output_addrs) - utxos_consumed)
        index = '% 4d'%(i)
        timestamp = datetime.fromtimestamp(rpctx['blocktime']
                ).strftime("%Y-%m-%d %H:%M")
        utxo_count_str = '% 3d' % (utxo_count)
        if options.verbosity > 0:
            if options.verbosity <= 2:
                n = cj_batch[0]
                if tx_type == 'cj internal':
                    cj_batch[0] += 1
                    cj_batch[1] += rpctx['blocktime']
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
                    print_row(index, rpctx['blocktime'], tx_type, amount,
                              delta_balance, balance, cj_n, fees, utxo_count,
                              mixdepth_src, mixdepth_dst, tx['txid'])
            elif options.verbosity >= 5 or \
                 (options.verbosity >= 3 and tx_type != 'unknown type'):
                print_row(index, rpctx['blocktime'], tx_type, amount,
                          delta_balance, balance, cj_n, fees, utxo_count,
                          mixdepth_src, mixdepth_dst, tx['txid'])

        if tx_type != 'cj internal':
            deposits.append(delta_balance)
            deposit_times.append(rpctx['blocktime'])

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
            print('to add it to this virtualenv, use `pip2 install scipy`')

    total_wallet_balance = sum(wallet.get_balance_by_mixdepth().values())
    if balance != total_wallet_balance:
        print(('BUG ERROR: wallet balance (%s) does not match balance from ' +
            'history (%s)') % (sat_to_str(total_wallet_balance),
                sat_to_str(balance)))
    if utxo_count != len(wallet.unspent):
        print(('BUG ERROR: wallet utxo count (%d) does not match utxo count from ' +
            'history (%s)') % (len(wallet.unspent), utxo_count))


def wallet_showseed(wallet):
    seed, extension = wallet.get_mnemonic_words()
    text = "Wallet mnemonic recovery phrase:\n\n{}\n".format(seed)
    if extension:
        text += "\nWallet mnemonic extension: {}\n".format(extension)
    return text


def wallet_importprivkey(wallet, mixdepth):
    print("WARNING: This imported key will not be recoverable with your 12 "
          "word mnemonic phrase. Make sure you have backups.")
    print("WARNING: Handling of raw ECDSA bitcoin private keys can lead to "
          "non-intuitive behaviour and loss of funds.\n  Recommended instead "
          "is to use the \'sweep\' feature of sendpayment.py.")
    privkeys = raw_input("Enter private key(s) to import: ")
    privkeys = privkeys.split(',') if ',' in privkeys else privkeys.split()
    imported_addr = []
    # TODO read also one key for each line
    for wif in privkeys:
        # TODO is there any point in only accepting wif format? check what
        # other wallets do
        imported_addr.append(wallet.import_private_key(mixdepth, wif))
    wallet.save()

    if not imported_addr:
        print("Warning: No keys imported!")
        return

    # show addresses to user so they can verify everything went as expected
    print("Imported keys for addresses:")
    for addr in imported_addr:
        print(addr)


def wallet_dumpprivkey(wallet, hdpath):
    path = wallet.path_repr_to_path(hdpath)
    return wallet.get_wif_path(path)  # will raise exception on invalid path


def wallet_signmessage(wallet, hdpath, message):
    msg = message.encode('utf-8')

    path = wallet.path_repr_to_path(hdpath)
    sig = wallet.sign_message(msg, path)
    return ("Signature: {}\n"
            "To verify this in Bitcoin Core use the RPC command 'verifymessage'"
            "".format(sig))


def get_wallet_type():
    if jm_single().config.get('POLICY', 'segwit') == 'true':
        return 'p2sh-p2wpkh'
    return 'p2pkh'


def get_wallet_cls(wtype=None):
    if wtype is None:
        wtype = get_wallet_type()

    cls = WALLET_IMPLEMENTATIONS.get(wtype)

    if not cls:
        raise WalletError("No wallet implementation found for type {}."
                          "".format(wtype))
    return cls


def create_wallet(path, password, max_mixdepth, **kwargs):
    storage = Storage(path, password, create=True)
    wallet_cls = get_wallet_cls()
    wallet_cls.initialize(storage, get_network(), max_mixdepth=max_mixdepth,
                          **kwargs)


def open_test_wallet_maybe(path, seed, max_mixdepth, **kwargs):
    """
    Create a volatile test wallet if path is a hex-encoded string of length 64,
    otherwise run open_wallet().

    params:
        path: path to wallet file, ignored for test wallets
        seed: hex-encoded test seed
        max_mixdepth: see create_wallet(), ignored when calling open_wallet()
        kwargs: see open_wallet()

    returns:
        wallet object
    """
    class SewgitTestWallet(ImportWalletMixin, BIP49Wallet):
        TYPE = 'p2sh-p2wpkh'

    if len(seed) == SewgitTestWallet.ENTROPY_BYTES * 2:
        try:
            seed = binascii.unhexlify(seed)
        except binascii.Error:
            pass
        else:
            storage = VolatileStorage()
            SewgitTestWallet.initialize(
                storage, get_network(), max_mixdepth=max_mixdepth,
                entropy=seed)
            assert 'ask_for_password' not in kwargs
            assert 'read_only' not in kwargs
            return SewgitTestWallet(storage, **kwargs)

    return open_wallet(path, **kwargs)


def open_wallet(path, ask_for_password=True, read_only=False, **kwargs):
    """
    Open the wallet file at path and return the corresponding wallet object.

    params:
        path: str, full path to wallet file
        ask_for_password: bool, if False password is assumed unset and user
            will not be asked to type it
        read_only: bool, if True, open wallet in read-only mode
        kwargs: additional options to pass to wallet's init method

    returns:
        wallet object
    """
    if ask_for_password:
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
        storage = Storage(path, read_only=read_only)

    wallet_cls = get_wallet_cls(storage)
    wallet = wallet_cls(storage, **kwargs)
    wallet_sanity_check(wallet)
    return wallet


def get_wallet_cls_from_storage(storage):
    wtype = storage.data.get([b'wallet_type'])

    if not wtype:
        raise WalletError("File {} is not a valid wallet.".format(storage.path))

    wtype = wtype.decode('ascii')
    return get_wallet_cls(wtype)


def wallet_sanity_check(wallet):
    if wallet.network != get_network():
        raise Exception("Wallet network mismatch: we are on {} but wallet is "
                        "on {}".format(get_network(), wallet.network))


def get_wallet_path(file_name, wallet_dir):
    # TODO: move default wallet path to ~/.joinmarket
    wallet_dir = wallet_dir or 'wallets'
    return os.path.join(wallet_dir, file_name)


def wallet_tool_main(wallet_root_path):
    """Main wallet tool script function; returned is a string (output or error)
    """
    parser = get_wallettool_parser()
    (options, args) = parser.parse_args()
    # if the index_cache stored in wallet.json is longer than the default
    # then set maxmixdepth to the length of index_cache
    maxmixdepth_configured = True
    if not options.maxmixdepth:
        maxmixdepth_configured = False
        options.maxmixdepth = 5

    noseed_methods = ['generate', 'recover']
    methods = ['display', 'displayall', 'summary', 'showseed', 'importprivkey',
               'history', 'showutxos']
    methods.extend(noseed_methods)
    noscan_methods = ['showseed', 'importprivkey', 'dumpprivkey', 'signmessage']

    if len(args) < 1:
        parser.error('Needs a wallet file or method')
        sys.exit(0)

    if args[0] in noseed_methods:
        method = args[0]
    else:
        seed = args[0]
        wallet_path = get_wallet_path(seed, wallet_root_path)
        method = ('display' if len(args) == 1 else args[1].lower())

        wallet = open_test_wallet_maybe(
            wallet_path, seed, options.maxmixdepth, gap_limit=options.gaplimit)

        if method not in noscan_methods:
            # if nothing was configured, we override bitcoind's options so that
            # unconfirmed balance is included in the wallet display by default
            if 'listunspent_args' not in jm_single().config.options('POLICY'):
                jm_single().config.set('POLICY','listunspent_args', '[0]')
            sync_wallet(wallet, fast=options.fastsync)
    #Now the wallet/data is prepared, execute the script according to the method
    if method == "display":
        return wallet_display(wallet, options.gaplimit, options.showprivkey)
    elif method == "displayall":
        return wallet_display(wallet, options.gaplimit, options.showprivkey, displayall=True)
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
        retval = wallet_generate_recover("generate", wallet_root_path)
        return retval if retval else "Failed"
    elif method == "recover":
        retval = wallet_generate_recover("recover", wallet_root_path)
        return retval if retval else "Failed"
    elif method == "showutxos":
        return wallet_showutxos(wallet, options.showprivkey)
    elif method == "showseed":
        return wallet_showseed(wallet)
    elif method == "dumpprivkey":
        return wallet_dumpprivkey(wallet, options.hd_path)
    elif method == "importprivkey":
        #note: must be interactive (security)
        wallet_importprivkey(wallet, options.mixdepth)
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

