from __future__ import print_function
import json
import os
import pprint
import sys
import datetime
import binascii
from mnemonic import Mnemonic
from optparse import OptionParser
import getpass
from jmclient import (get_network, Wallet, Bip39Wallet, podle,
                      encryptData, get_p2pk_vbyte, jm_single,
                      mn_decode, mn_encode, BitcoinCoreInterface,
                      JsonRpcError, sync_wallet, WalletError, SegwitWallet)
from jmbase.support import get_password
import jmclient.btc as btc

def get_wallettool_parser():
    description = (
        'Use this script to monitor and manage your Joinmarket wallet. The '
        'method is one of the following: \n(display) Shows addresses and '
        'balances. \n(displayall) Shows ALL addresses and balances. '
        '\n(summary) Shows a summary of mixing depth balances.\n(generate) '
        'Generates a new wallet.\n(recover) Recovers a wallet from the 12 '
        'word recovery seed.\n(showutxos) Shows all utxos in the wallet.'
        '\n(showseed) Shows the wallet recovery seed '
        'and hex seed.\n(importprivkey) Adds privkeys to this wallet, '
        'privkeys are spaces or commas separated.\n(dumpprivkey) Export '
        'a single private key, specify an hd wallet path\n'
        '(signmessage) Sign a message with the private key from an address '
        'in the wallet. Use with -H and specify an HD wallet '
        'path for the address.')
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
    for e in elements:
        if e[-1] == "'": e = e[:-1]
        try:
            x = int(e)
        except:
            return False
        if not e >= -1:
            #-1 is allowed for dummy branches for imported keys
            return False
    return True

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

    def serialize(self, entryseparator="\n"):
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

    def serialize(self, entryseparator="\n"):
        header = self.account_name + self.separator + str(self.account)
        if self.xpub:
            header = header + self.separator + self.xpub
        footer = "Balance for mixdepth " + str(
            self.account) + ":" + self.separator + self.get_fmt_balance()
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

    def serialize(self, entryseparator="\n"):
        header = self.wallet_name
        footer = "Total balance:" + self.separator + self.get_fmt_balance()
        return self.serclass(entryseparator.join([header] + [
            x.serialize(entryseparator) for x in self.accounts] + [footer]))

def get_imported_privkey_branch(wallet, m, showprivkey):
    if m in wallet.imported_privkeys:
        entries = []
        for i, privkey in enumerate(wallet.imported_privkeys[m]):
            addr = btc.privtoaddr(privkey, magicbyte=get_p2pk_vbyte())
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
                   serialized=True):
    """build the walletview object,
    then return its serialization directly if serialized,
    else return the WalletView object.
    """
    acctlist = []
    rootpath = wallet.get_root_path()
    for m in range(wallet.max_mix_depth):
        branchlist = []
        for forchange in [0, 1]:
            entrylist = []
            if forchange == 0:
                xpub_key = btc.bip32_privtopub(wallet.keys[m][forchange])
            else:
                xpub_key = ""

            for k in range(wallet.index[m][forchange] + gaplimit):
                addr = wallet.get_addr(m, forchange, k)
                balance = 0
                for addrvalue in wallet.unspent.values():
                    if addr == addrvalue['address']:
                        balance += addrvalue['value']
                used = 'used' if k < wallet.index[m][forchange] else 'new'
                if showprivkey:
                    privkey = btc.wif_compressed_privkey(
                        wallet.get_key(m, forchange, k), get_p2pk_vbyte())
                else:
                    privkey = ''
                if (displayall or balance > 0 or
                    (used == 'new' and forchange == 0)):
                    entrylist.append(WalletViewEntry(rootpath, m, forchange, k,
                                                 addr, [balance, balance],
                                                 priv=privkey, used=used))
            branchlist.append(WalletViewBranch(rootpath, m, forchange, entrylist,
                                               xpub=xpub_key))
        ipb = get_imported_privkey_branch(wallet, m, showprivkey)
        if ipb:
            branchlist.append(ipb)
        #get the xpub key of the whole account
        xpub_account = btc.bip32_privtopub(
            wallet.get_mixing_depth_keys(wallet.get_master_key())[m])
        acctlist.append(WalletViewAccount(rootpath, m, branchlist,
                                          xpub=xpub_account))
    walletview = WalletView(rootpath, acctlist)
    if serialized:
        return walletview.serialize()
    else:
        return walletview

def cli_password_check():
    password = get_password('Enter wallet encryption passphrase: ')
    password2 = get_password('Reenter wallet encryption passphrase: ')
    if password != password2:
        print('ERROR. Passwords did not match')
        return False, False
    password_key = btc.bin_dbl_sha256(password)
    return password, password_key

def cli_get_walletname():
    return raw_input('Input wallet file name (default: wallet.json): ')

def cli_user_words(words):
    print('Write down this wallet recovery seed\n\n' + words +'\n')

def cli_user_words_entry():
    return raw_input("Input 12 word recovery seed: ")

def persist_walletfile(walletspath, default_wallet_name, encrypted_seed,
                       callbacks=(cli_get_walletname,)):
    timestamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    walletfile = json.dumps({'creator': 'joinmarket project',
                             'creation_time': timestamp,
                             'encrypted_seed': encrypted_seed.encode('hex'),
                             'network': get_network()})
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
                                  callbacks=(cli_user_words,
                                             cli_user_words_entry,
                                             cli_password_check,
                                             cli_get_walletname)):
    """Optionally provide callbacks:
    0 - display seed
    1 - enter seed (for recovery)
    2 - enter password
    3 - enter wallet name
    The defaults are for terminal entry.
    """
    #using 128 bit entropy, 12 words, mnemonic module
    m = Mnemonic("english")
    if method == "generate":
        words = m.generate()
        callbacks[0](words)
    elif method == 'recover':
        words = callbacks[1]()
    entropy = str(m.to_entropy(words))
    password, password_key = callbacks[2]()
    if not password:
        return False
    encrypted_entropy = encryptData(password_key, entropy)
    return persist_walletfile(walletspath, default_wallet_name, encrypted_entropy,
                              callbacks=(callbacks[3],))

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
    password, password_key = cli_password_check()
    if not password:
        return False
    encrypted_seed = encryptData(password_key, seed.decode('hex'))
    return persist_walletfile(walletspath, default_wallet_name, encrypted_seed)

def wallet_showseed(wallet):
    if isinstance(wallet, Bip39Wallet):
        if not wallet.entropy:
            return "Entropy is not initialized."
        m = Mnemonic("english")
        return "Wallet recovery seed\n\n" + m.to_mnemonic(wallet.entropy) + "\n"
    hexseed = wallet.seed
    print("hexseed = " + hexseed)
    words = mn_encode(hexseed)
    return "Wallet recovery seed\n\n" + " ".join(words) + "\n"

def wallet_importprivkey(wallet, mixdepth):
    print('WARNING: This imported key will not be recoverable with your 12 ' +
          'word mnemonic seed. Make sure you have backups.')
    print('WARNING: Handling of raw ECDSA bitcoin private keys can lead to '
          'non-intuitive behaviour and loss of funds.\n  Recommended instead '
          'is to use the \'sweep\' feature of sendpayment.py ')
    privkeys = raw_input('Enter private key(s) to import: ')
    privkeys = privkeys.split(',') if ',' in privkeys else privkeys.split()
    # TODO read also one key for each line
    for privkey in privkeys:
        # TODO is there any point in only accepting wif format? check what
        # other wallets do
        privkey_bin = btc.from_wif_privkey(privkey,
                                        vbyte=get_p2pk_vbyte()).decode('hex')[:-1]
        encrypted_privkey = encryptData(wallet.password_key, privkey_bin)
        if 'imported_keys' not in wallet.walletdata:
            wallet.walletdata['imported_keys'] = []
        wallet.walletdata['imported_keys'].append(
            {'encrypted_privkey': encrypted_privkey.encode('hex'),
             'mixdepth': mixdepth})
    if wallet.walletdata['imported_keys']:
        fd = open(wallet.path, 'w')
        fd.write(json.dumps(wallet.walletdata))
        fd.close()
        print('Private key(s) successfully imported')

def wallet_dumpprivkey(wallet, hdpath):
    if bip32pathparse(hdpath):
        m, forchange, k = [int(y) for y in hdpath[4:].split('/')]
        key = wallet.get_key(m, forchange, k)
        wifkey = btc.wif_compressed_privkey(key, vbyte=get_p2pk_vbyte())
        return wifkey
    else:
        return hdpath + " is not a valid hd wallet path"

def wallet_signmessage(wallet, hdpath, message):
    if hdpath.startswith(wallet.get_root_path()):
        m, forchange, k = [int(y) for y in hdpath[4:].split('/')]
        key = wallet.get_key(m, forchange, k)
        addr = btc.privkey_to_address(key, magicbyte=get_p2pk_vbyte())
        print('Using address: ' + addr)
    else:
        print('%s is not a valid hd wallet path' % hdpath)
        return None
    sig = btc.ecdsa_sign(message, key, formsg=True)
    retval = "Signature: " + str(sig) + "\n"
    retval += "To verify this in Bitcoin Core use the RPC command 'verifymessage'"
    return retval

def wallet_tool_main(wallet_root_path):
    """Main wallet tool script function; returned is a string (output or error)
    """
    parser = get_wallettool_parser()
    (options, args) = parser.parse_args()
    walletclass = SegwitWallet if jm_single().config.get(
        "POLICY", "segwit") == "true" else Wallet
    # if the index_cache stored in wallet.json is longer than the default
    # then set maxmixdepth to the length of index_cache
    maxmixdepth_configured = True
    if not options.maxmixdepth:
        maxmixdepth_configured = False
        options.maxmixdepth = 5

    noseed_methods = ['generate', 'recover']
    methods = ['display', 'displayall', 'summary', 'showseed', 'importprivkey',
               'showutxos']
    methods.extend(noseed_methods)
    noscan_methods = ['showseed', 'importprivkey', 'dumpprivkey', 'signmessage']

    if len(args) < 1:
        parser.error('Needs a wallet file or method')
        sys.exit(0)

    if args[0] in noseed_methods:
        method = args[0]
    else:
        seed = args[0]
        method = ('display' if len(args) == 1 else args[1].lower())
        if not os.path.exists(os.path.join(wallet_root_path, seed)):
            wallet = walletclass(seed, None, options.maxmixdepth,
                            options.gaplimit, extend_mixdepth= not maxmixdepth_configured,
                            storepassword=(method == 'importprivkey'),
                            wallet_dir=wallet_root_path)
        else:
            while True:
                try:
                    pwd = get_password("Enter wallet decryption passphrase: ")
                    wallet = walletclass(seed, pwd,
                            options.maxmixdepth,
                            options.gaplimit,
                            extend_mixdepth=not maxmixdepth_configured,
                            storepassword=(method == 'importprivkey'),
                            wallet_dir=wallet_root_path)
                except WalletError:
                    print("Wrong password, try again.")
                    continue
                except Exception as e:
                    print("Failed to load wallet, error message: " + repr(e))
                    sys.exit(0)
                break
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
        return wallet_display(wallet, options.gaplimit, options.showprivkey,
                              displayall=True)
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
        return wallet_signmessage(wallet, options.hd_path, args[1])

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
            