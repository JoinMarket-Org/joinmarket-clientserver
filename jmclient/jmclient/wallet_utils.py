import json
import os
import sys
import sqlite3
import binascii
from datetime import datetime
from calendar import timegm
from optparse import OptionParser
from numbers import Integral
from collections import Counter
from itertools import islice
from jmclient import (get_network, WALLET_IMPLEMENTATIONS, Storage, podle,
    jm_single, BitcoinCoreInterface, WalletError,
    VolatileStorage, StoragePasswordError, is_segwit_mode, SegwitLegacyWallet,
    LegacyWallet, SegwitWallet, FidelityBondMixin, FidelityBondWatchonlyWallet,
    is_native_segwit_mode, load_program_config, add_base_options, check_regtest)
from jmclient.wallet_service import WalletService
from jmbase.support import (get_password, jmprint, EXIT_FAILURE,
                            EXIT_ARGERROR, utxo_to_utxostr, hextobin)

from .cryptoengine import TYPE_P2PKH, TYPE_P2SH_P2WPKH, TYPE_P2WPKH, \
    TYPE_SEGWIT_LEGACY_WALLET_FIDELITY_BONDS
from .output import fmt_utxo
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
        '(changepass) Changes the encryption passphrase of the wallet.\n'
        '(history) Show all historical transaction details. Requires Bitcoin Core.'
        '(recover) Recovers a wallet from the 12 word recovery seed.\n'
        '(showutxos) Shows all utxos in the wallet.\n'
        '(showseed) Shows the wallet recovery seed and hex seed.\n'
        '(importprivkey) Adds privkeys to this wallet, privkeys are spaces or commas separated.\n'
        '(dumpprivkey) Export a single private key, specify an hd wallet path\n'
        '(signmessage) Sign a message with the private key from an address in \n'
        'the wallet. Use with -H and specify an HD wallet path for the address.\n'
        '(freeze) Freeze or un-freeze a specific utxo. Specify mixdepth with -m.\n'
        '(gettimelockaddress) Obtain a timelocked address. Argument is locktime value as yyyy-mm. For example `2021-03`\n'
        '(addtxoutproof) Add a tx out proof as metadata to a burner transaction. Specify path with '
            '-H and proof which is output of Bitcoin Core\'s RPC call gettxoutproof\n'
        '(createwatchonly) Create a watch-only fidelity bond wallet')
    parser = OptionParser(usage='usage: %prog [options] [wallet file] [method] [args..]',
                          description=description)
    add_base_options(parser)
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
                            "if your address starts with '3' use 'segwit-p2sh'.\n"
                            "Native segwit addresses (starting with 'bc') are "
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
    def __init__(self, wallet_path_repr, account, address_type, aindex, addr, amounts,
                 used = 'new', serclass=str, priv=None, custom_separator=None):
        super().__init__(wallet_path_repr, serclass=serclass,
                         custom_separator=custom_separator)
        self.account = account
        assert address_type in [SegwitWallet.BIP32_EXT_ID,
            SegwitWallet.BIP32_INT_ID, -1, FidelityBondMixin.BIP32_TIMELOCK_ID,
            FidelityBondMixin.BIP32_BURN_ID]
        self.address_type = address_type
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

class WalletViewEntryBurnOutput(WalletViewEntry):
    # balance in burn outputs shouldnt be counted
    # towards the total balance
    def get_balance(self, include_unconf=True):
        return 0

class WalletViewBranch(WalletViewBase):
    def __init__(self, wallet_path_repr, account, address_type, branchentries=None,
                 xpub=None, serclass=str, custom_separator=None):
        super().__init__(wallet_path_repr, children=branchentries,
                         serclass=serclass, custom_separator=custom_separator)
        self.account = account
        assert address_type in [SegwitWallet.BIP32_EXT_ID,
            SegwitWallet.BIP32_INT_ID, -1, FidelityBondMixin.BIP32_TIMELOCK_ID,
            FidelityBondMixin.BIP32_BURN_ID]
        self.address_type = address_type
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
        start = "external addresses" if self.address_type == 0 else "internal addresses"
        if self.address_type == -1:
            start = "Imported keys"
        return self.serclass(self.separator.join([start, self.wallet_path_repr,
                                                  self.xpub]))

class WalletViewAccount(WalletViewBase):
    def __init__(self, wallet_path_repr, account, branches=None, account_name="mixdepth",
                 serclass=str, custom_separator=None, xpub=None):
        super().__init__(wallet_path_repr, children=branches, serclass=serclass,
                         custom_separator=custom_separator)
        self.account = account
        self.account_name = account_name
        self.xpub = xpub
        if branches:
            assert len(branches) in [2, 3, 4] #3 if imported keys, 4 if fidelity bonds
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
        super().__init__(wallet_path_repr, children=accounts, serclass=serclass,
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
    rpctx = jm_single().bc_interface.get_transaction(txid)
    txhex = str(rpctx['hex'])
    tx = btc.CMutableTransaction.deserialize(hextobin(txhex))
    output_script_values = {x.scriptPubKey: x.nValue for x in tx.vout}
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
        rpctx.get('blocktime', 0), tx


def get_imported_privkey_branch(wallet_service, m, showprivkey):
    entries = []
    for path in wallet_service.yield_imported_paths(m):
        addr = wallet_service.get_address_from_path(path)
        script = wallet_service.get_script_from_path(path)
        balance = 0.0
        for data in wallet_service.get_utxos_by_mixdepth(
            include_disabled=True)[m].values():
            if script == data['script']:
                balance += data['value']
        used = ('used' if balance > 0.0 else 'empty')
        if showprivkey:
            wip_privkey = wallet_service.get_wif_path(path)
        else:
            wip_privkey = ''
        entries.append(WalletViewEntry(wallet_service.get_path_repr(path), m, -1,
                                       0, addr, [balance, balance],
                                       used=used, priv=wip_privkey))

    if entries:
        return WalletViewBranch("m/0", m, -1, branchentries=entries)
    return None

def wallet_showutxos(wallet_service, showprivkey):
    unsp = {}
    max_tries = jm_single().config.getint("POLICY", "taker_utxo_retries")
    utxos = wallet_service.get_utxos_by_mixdepth(include_disabled=True,
        includeconfs=True)
    for md in utxos:
        (enabled, disabled) = get_utxos_enabled_disabled(wallet_service, md)
        utxo_d = []
        for k, v in disabled.items():
            utxo_d.append(k)
        for u, av in utxos[md].items():
            success, us = utxo_to_utxostr(u)
            assert success
            key = wallet_service.get_key_from_addr(av['address'])
            tries = podle.get_podle_tries(u, key, max_tries)
            tries_remaining = max(0, max_tries - tries)
            mixdepth = wallet_service.wallet.get_details(av['path'])[0]
            unsp[us] = {'address': av['address'], 'value': av['value'],
                       'tries': tries, 'tries_remaining': tries_remaining,
                       'external': False,
                       'mixdepth': mixdepth,
                       'confirmations': av['confs'],
                       'frozen': True if u in utxo_d else False}
            if showprivkey:
                unsp[us]['privkey'] = wallet_service.get_wif_path(av['path'])

    used_commitments, external_commitments = podle.get_podle_commitments()
    for u, ec in external_commitments.items():
        success, us = utxo_to_utxostr(u)
        assert success
        tries = podle.get_podle_tries(utxo=u, max_tries=max_tries,
                                          external=True)
        tries_remaining = max(0, max_tries - tries)
        unsp[us] = {'tries': tries, 'tries_remaining': tries_remaining,
                   'external': True}

    return json.dumps(unsp, indent=4)


def wallet_display(wallet_service, showprivkey, displayall=False,
        serialized=True, summarized=False):
    """build the walletview object,
    then return its serialization directly if serialized,
    else return the WalletView object.
    """
    def get_addr_status(addr_path, utxos, is_new, is_internal):
        addr_balance = 0
        status = []
        for utxo, utxodata in utxos.items():
            if addr_path != utxodata['path']:
                continue
            addr_balance += utxodata['value']
            #TODO it is a failure of abstraction here that
            # the bitcoin core interface is used directly
            #the function should either be removed or added to bci
            #or possibly add some kind of `gettransaction` function
            # to bci
            if jm_single().bc_interface.__class__ == BitcoinCoreInterface:
                is_coinjoin, cj_amount, cj_n = \
                    get_tx_info(utxo[0])[:3]
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
    # TODO - either optionally not show disabled utxos, or
    # mark them differently in display (labels; colors)
    utxos = wallet_service.get_utxos_by_mixdepth(include_disabled=True)
    for m in range(wallet_service.mixdepth + 1):
        branchlist = []
        for address_type in [0, 1]:
            entrylist = []
            if address_type == 0:
                # users would only want to hand out the xpub for externals
                xpub_key = wallet_service.get_bip32_pub_export(m, address_type)
            else:
                xpub_key = ""

            unused_index = wallet_service.get_next_unused_index(m, address_type)
            for k in range(unused_index + wallet_service.gap_limit):
                path = wallet_service.get_path(m, address_type, k)
                addr = wallet_service.get_address_from_path(path)
                balance, used = get_addr_status(
                    path, utxos[m], k >= unused_index, address_type)
                if showprivkey:
                    privkey = wallet_service.get_wif_path(path)
                else:
                    privkey = ''
                if (displayall or balance > 0 or
                        (used == 'new' and address_type == 0)):
                    entrylist.append(WalletViewEntry(
                        wallet_service.get_path_repr(path), m, address_type, k, addr,
                        [balance, balance], priv=privkey, used=used))
            wallet_service.set_next_index(m, address_type, unused_index)
            path = wallet_service.get_path_repr(wallet_service.get_path(m, address_type))
            branchlist.append(WalletViewBranch(path, m, address_type, entrylist,
                                               xpub=xpub_key))

        if m == FidelityBondMixin.FIDELITY_BOND_MIXDEPTH and \
                isinstance(wallet_service.wallet, FidelityBondMixin):
            address_type = FidelityBondMixin.BIP32_TIMELOCK_ID
            unused_index = wallet_service.get_next_unused_index(m, address_type)
            timelocked_gaplimit = (wallet_service.wallet.gap_limit
                    // FidelityBondMixin.TIMELOCK_GAP_LIMIT_REDUCTION_FACTOR)
            entrylist = []
            for k in range(unused_index + timelocked_gaplimit):
                for timenumber in range(FidelityBondMixin.TIMENUMBERS_PER_PUBKEY):
                    path = wallet_service.get_path(m, address_type, k, timenumber)
                    addr = wallet_service.get_address_from_path(path)
                    timelock = datetime.utcfromtimestamp(path[-1])

                    balance = sum([utxodata["value"] for utxo, utxodata in
                        iteritems(utxos[m]) if path == utxodata["path"]])
                    status = timelock.strftime("%Y-%m-%d") + " [" + (
                        "LOCKED" if datetime.now() < timelock else "UNLOCKED") + "]"
                    privkey = ""
                    if showprivkey:
                        privkey = wallet_service.get_wif_path(path)
                    if displayall or balance > 0:
                        entrylist.append(WalletViewEntry(
                            wallet_service.get_path_repr(path), m, address_type, k,
                            addr, [balance, balance], priv=privkey, used=status))
            xpub_key = wallet_service.get_bip32_pub_export(m, address_type)
            path = wallet_service.get_path_repr(wallet_service.get_path(m, address_type))
            branchlist.append(WalletViewBranch(path, m, address_type, entrylist,
                xpub=xpub_key))

            entrylist = []
            address_type = FidelityBondMixin.BIP32_BURN_ID
            unused_index = wallet_service.get_next_unused_index(m, address_type)
            burner_outputs = wallet_service.wallet.get_burner_outputs()
            wallet_service.set_next_index(m, address_type, unused_index +
                wallet_service.wallet.gap_limit, force=True)
            for k in range(unused_index + wallet_service.wallet.gap_limit):
                path = wallet_service.get_path(m, address_type, k)
                path_repr = wallet_service.get_path_repr(path)
                path_repr_b = path_repr.encode()

                privkey, engine = wallet_service._get_key_from_path(path)
                pubkey = engine.privkey_to_pubkey(privkey)
                pubkeyhash = btc.bin_hash160(pubkey)
                output = "BURN-" + binascii.hexlify(pubkeyhash).decode()

                balance = 0
                status = "no transaction"
                if path_repr_b in burner_outputs:
                    txhex, blockheight, merkle_branch, blockindex = burner_outputs[path_repr_b]
                    txhex = binascii.hexlify(txhex).decode()
                    txd = btc.deserialize(txhex)
                    assert len(txd["outs"]) == 1
                    balance = txd["outs"][0]["value"]
                    script = binascii.unhexlify(txd["outs"][0]["script"])
                    assert script[0] == 0x6a #OP_RETURN
                    tx_pubkeyhash = script[2:]
                    assert tx_pubkeyhash == pubkeyhash
                    status = btc.txhash(txhex) + (" [NO MERKLE PROOF]" if
                        merkle_branch == FidelityBondMixin.MERKLE_BRANCH_UNAVAILABLE else "")
                privkey = (wallet_service.get_wif_path(path) if showprivkey else "")
                if displayall or balance > 0:
                    entrylist.append(WalletViewEntryBurnOutput(path_repr, m,
                        address_type, k, output, [balance, balance],
                        priv=privkey, used=status))
            wallet_service.set_next_index(m, address_type, unused_index)

            xpub_key = wallet_service.get_bip32_pub_export(m, address_type)
            path = wallet_service.get_path_repr(wallet_service.get_path(m, address_type))
            branchlist.append(WalletViewBranch(path, m, address_type, entrylist,
                xpub=xpub_key))

        ipb = get_imported_privkey_branch(wallet_service, m, showprivkey)
        if ipb:
            branchlist.append(ipb)
        #get the xpub key of the whole account
        xpub_account = wallet_service.get_bip32_pub_export(mixdepth=m)
        path = wallet_service.get_path_repr(wallet_service.get_path(m))
        acctlist.append(WalletViewAccount(path, m, branchlist,
                                          xpub=xpub_account))
    path = wallet_service.get_path_repr(wallet_service.get_path())
    walletview = WalletView(path, acctlist)
    if serialized:
        return walletview.serialize(summarize=summarized)
    else:
        return walletview

def cli_get_wallet_passphrase_check():
    password = get_password("Enter new passphrase to encrypt wallet: ")
    password2 = get_password("Reenter new passphrase to encrypt wallet: ")
    if password != password2:
        jmprint('ERROR. Passwords did not match', "error")
        return False
    return password

def cli_get_wallet_file_name(defaultname="wallet.jmdat"):
    return input('Input wallet file name (default: ' + defaultname + '): ')

def cli_display_user_words(words, mnemonic_extension):
    text = 'Write down this wallet recovery mnemonic\n\n' + words +'\n'
    if mnemonic_extension:
        text += '\nAnd this mnemonic extension: ' + mnemonic_extension.decode(
            'utf-8') + '\n'
    jmprint(text, "important")

def cli_user_mnemonic_entry():
    mnemonic_phrase = input("Input mnemonic recovery phrase: ")
    mnemonic_extension = input("Input mnemonic extension, leave blank if there isnt one: ")
    if len(mnemonic_extension.strip()) == 0:
        mnemonic_extension = None
    return (mnemonic_phrase, mnemonic_extension)

def cli_do_use_mnemonic_extension():
    uin = input("Would you like to use a two-factor mnemonic recovery "
                    "phrase? write 'n' if you don't know what this is (y/n): ")
    if len(uin) == 0 or uin[0] != 'y':
        jmprint("Not using mnemonic extension", "info")
        return False #no mnemonic extension
    else:
        return True

def cli_get_mnemonic_extension():
    jmprint("Note: This will be stored in a reversible way. Do not reuse!",
            "info")
    return input("Enter mnemonic extension: ")

def cli_do_support_fidelity_bonds():
    uin = input("Would you like this wallet to support fidelity bonds? "
            "write 'n' if you don't know what this is (y/n): ")
    if len(uin) == 0 or uin[0] != 'y':
        jmprint("Not supporting fidelity bonds", "info")
        return False
    else:
        return True

def wallet_generate_recover_bip39(method, walletspath, default_wallet_name,
        display_seed_callback, enter_seed_callback, enter_wallet_password_callback,
        enter_wallet_file_name_callback, enter_if_use_seed_extension,
        enter_seed_extension_callback, enter_do_support_fidelity_bonds, mixdepth=DEFAULT_MIXDEPTH):
    entropy = None
    mnemonic_extension = None
    if method == "generate":
        if enter_if_use_seed_extension():
            mnemonic_extension = enter_seed_extension_callback()
            if not mnemonic_extension:
                return False
    elif method == 'recover':
        words, mnemonic_extension = enter_seed_callback()
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

    password = enter_wallet_password_callback()
    if not password:
        return False

    wallet_name = enter_wallet_file_name_callback()
    if wallet_name == "cancelled":
        # currently used only by Qt, because user has option
        # to click cancel in dialog.
        return False
    if not wallet_name:
        wallet_name = default_wallet_name
    wallet_path = os.path.join(walletspath, wallet_name)

    # disable creating fidelity bond wallets for now until the
    # rest of the fidelity bond feature is created
    #support_fidelity_bonds = enter_do_support_fidelity_bonds()
    support_fidelity_bonds = False
    wallet_cls = get_wallet_cls(get_configured_wallet_type(support_fidelity_bonds))

    wallet = create_wallet(wallet_path, password, mixdepth, wallet_cls,
                           entropy=entropy,
                           entropy_extension=mnemonic_extension)
    mnemonic, mnext = wallet.get_mnemonic_words()
    display_seed_callback and display_seed_callback(mnemonic, mnext or '')
    wallet.close()
    return True


def wallet_generate_recover(method, walletspath,
                            default_wallet_name='wallet.jmdat',
                            mixdepth=DEFAULT_MIXDEPTH):
    if is_segwit_mode():
        #Here using default callbacks for scripts (not used in Qt)
        return wallet_generate_recover_bip39(method, walletspath,
            default_wallet_name, cli_display_user_words, cli_user_mnemonic_entry,
            cli_get_wallet_passphrase_check, cli_get_wallet_file_name,
            cli_do_use_mnemonic_extension, cli_get_mnemonic_extension,
            cli_do_support_fidelity_bonds, mixdepth=mixdepth)

    entropy = None
    if method == 'recover':
        seed = input("Input 12 word recovery seed: ")
        try:
            entropy = LegacyWallet.entropy_from_mnemonic(seed)
        except WalletError as e:
            jmprint("Unable to restore seed: {}".format(e.message), "error")
            return ""
    elif method != 'generate':
        raise Exception("unknown method for wallet creation: '{}'"
                        .format(method))

    password = cli_get_wallet_passphrase_check()
    if not password:
        return ""

    wallet_name = cli_get_wallet_file_name()
    if not wallet_name:
        wallet_name = default_wallet_name
    wallet_path = os.path.join(walletspath, wallet_name)

    wallet = create_wallet(wallet_path, password, mixdepth,
                           wallet_cls=LegacyWallet, entropy=entropy)
    jmprint("Write down and safely store this wallet recovery seed\n\n{}\n"
          .format(wallet.get_mnemonic_words()[0]), "important")
    wallet.close()
    return True


def wallet_change_passphrase(walletservice,
                             enter_wallet_passphrase_callback=cli_get_wallet_passphrase_check):
    passphrase = enter_wallet_passphrase_callback()
    if passphrase:
        walletservice.change_wallet_passphrase(passphrase)
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
            "blockhash TEXT, blocktime INTEGER, conflicts INTEGER);")
    jm_single().debug_silence[0] = True
    wallet_name = wallet.get_wallet_name()
    buf = range(1000)
    t = 0
    while len(buf) == 1000:
        buf = jm_single().bc_interface.list_transactions(1000, t)
        t += len(buf)
        # confirmed
        tx_data = ((tx['txid'], tx['blockhash'], tx['blocktime'], 0) for tx
                in buf if 'txid' in tx and 'blockhash' in tx and 'blocktime'
                in tx)
        tx_db.executemany('INSERT INTO transactions VALUES(?, ?, ?, ?);',
                tx_data)
        # unconfirmed
        uc_tx_data = ((tx['txid'], None, None, len(tx['walletconflicts'])) for
                tx in buf if 'txid' in tx and 'blockhash' not in tx and
                'blocktme' not in tx)
        tx_db.executemany('INSERT INTO transactions VALUES(?, ?, ?, ?);',
                uc_tx_data)

    txes = tx_db.execute(
        'SELECT DISTINCT txid, blockhash, blocktime '
        'FROM transactions '
        'WHERE (blockhash IS NOT NULL AND blocktime IS NOT NULL) OR conflicts = 0 '
        'ORDER BY blocktime').fetchall()
    wallet_script_set = set(wallet.get_script_from_path(p)
                            for p in wallet.yield_known_paths())

    def s():
        return ',' if options.csv else ' '
    def sat_to_str_na(sat):
        if sat == 0:
            return "N/A       "
        else:
            return btc.sat_to_str(sat)
    def skip_n1(v):
        return '% 2s'%(str(v)) if v != -1 else ' #'
    def skip_n1_btc(v):
        return btc.sat_to_str(v) if v != -1 else '#' + ' '*10
    def print_row(index, time, tx_type, amount, delta, balance, cj_n,
                  total_fees, utxo_count, mixdepth_src, mixdepth_dst, txid):
        data = [index, datetime.fromtimestamp(time).strftime("%Y-%m-%d %H:%M"),
                tx_type, btc.sat_to_str(amount), btc.sat_to_str_p(delta),
                btc.sat_to_str(balance), skip_n1(cj_n), sat_to_str_na(total_fees),
                '% 3d' % utxo_count, skip_n1(mixdepth_src), skip_n1(mixdepth_dst)]
        if options.verbosity % 2 == 0: data += [txid]
        jmprint(s().join(map('"{}"'.format, data)), "info")


    field_names = ['tx#', 'timestamp', 'type', 'amount/btc',
            'balance-change/btc', 'balance/btc', 'coinjoin-n', 'total-fees',
            'utxo-count', 'mixdepth-from', 'mixdepth-to']
    if options.verbosity % 2 == 0: field_names += ['txid']
    if options.csv:
        jmprint('Bumping verbosity level to 4 due to --csv flag', "debug")
        options.verbosity = 4
    if options.verbosity > 0: jmprint(s().join(field_names), "info")
    if options.verbosity <= 2: cj_batch = [0]*8 + [[]]*2
    balance = 0
    unconfirmed_balance = 0
    utxo_count = 0
    unconfirmed_utxo_count = 0
    deposits = []
    deposit_times = []
    tx_number = 0
    for tx in txes:
        is_coinjoin, cj_amount, cj_n, output_script_values, blocktime, txd =\
            get_tx_info(hextobin(tx['txid']))

        # unconfirmed transactions don't have blocktime, get_tx_info() returns
        # 0 in that case
        is_confirmed = (blocktime != 0)

        our_output_scripts = wallet_script_set.intersection(
            output_script_values.keys())

        rpc_inputs = []
        for ins in txd.vin:
            wallet_tx = jm_single().bc_interface.get_transaction(
                ins.prevout.hash[::-1])
            if wallet_tx is None:
                continue
            inp = btc.CMutableTransaction.deserialize(hextobin(
                wallet_tx['hex'])).vout[ins.prevout.n]
            input_dict = {"script": inp.scriptPubKey, "value": inp.nValue}
            rpc_inputs.append(input_dict)

        rpc_input_scripts = set(ind['script'] for ind in rpc_inputs)
        our_input_scripts = wallet_script_set.intersection(rpc_input_scripts)
        our_input_values = [
            ind['value'] for ind in rpc_inputs
            if ind['script'] in our_input_scripts]
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
            our_output_script = list(our_output_scripts)[0]
            our_output_value = output_script_values[our_output_script]
            fees = our_input_value - our_output_value - cj_amount
            if is_coinjoin:
                amount = cj_amount
                if our_output_value == cj_amount:
                    #a sweep coinjoin with no change address back to our wallet
                    tx_type = 'cj intsweep'
                    mixdepth_dst = wallet.get_script_mixdepth(our_output_script)
                    fees = 0
                else:
                    #payment elsewhere with our change address getting the remaining
                    #our_output_value is the change output
                    tx_type = 'cj withdraw'
            else:
                tx_type = 'withdraw   '
                #TODO does tx_fee go here? not my_tx_fee only?
                amount = our_input_value - our_output_value
                cj_n = -1
                fees = 0
            delta_balance = our_output_value - our_input_value
            mixdepth_src = wallet.get_script_mixdepth(list(our_input_scripts)[0])
        elif len(our_input_scripts) > 0 and len(our_output_scripts) == 2:
            #payment to self
            out_value = sum([output_script_values[a] for a in our_output_scripts])
            if not is_coinjoin:
                jmprint('this is wrong TODO handle non-coinjoin internal', "warning")
            tx_type = 'cj internal'
            amount = cj_amount
            delta_balance = out_value - our_input_value
            mixdepth_src = wallet.get_script_mixdepth(list(our_input_scripts)[0])
            cj_script = list(set([a for a, v in output_script_values.items()
                if v == cj_amount]).intersection(our_output_scripts))[0]
            mixdepth_dst = wallet.get_script_mixdepth(cj_script)
        else:
            tx_type = 'unknown type'
            jmprint('our utxos: ' + str(len(our_input_scripts)) \
                  + ' in, ' + str(len(our_output_scripts)) + ' out')

        if is_confirmed:
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

        else:
            unconfirmed_balance += delta_balance
            utxo_count += (len(our_output_scripts) - utxos_consumed)

    # we could have a leftover batch!
    if options.verbosity <= 2:
        n = cj_batch[0]
        if n > 0:
            print_row('N='+"%2d"%n, cj_batch[1]/n, 'cj batch   ', cj_batch[2],
                      cj_batch[3], cj_batch[4], cj_batch[5]/n, cj_batch[6],
                      cj_batch[7]/n, min(cj_batch[8]), max(cj_batch[9]), '...')


    bestblockhash = jm_single().bc_interface.get_best_block_hash()
    now = jm_single().bc_interface.get_block_time(bestblockhash)
    jmprint('        %s best block is %s' % (datetime.fromtimestamp(now)
        .strftime("%Y-%m-%d %H:%M"), bestblockhash))
    total_profit = float(balance - sum(deposits)) / float(100000000)
    jmprint('total profit = %.8f BTC' % total_profit)

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
            jmprint('continuously compounded equivalent annual interest rate = ' +
                str(r * 100) + ' %')
            jmprint('(as if yield generator was a bank account)')
        except ImportError:
            jmprint('scipy not installed, unable to predict accumulation rate')
            jmprint('to add it to this virtualenv, use `pip install scipy`')

    # includes disabled utxos in accounting:
    total_wallet_balance = sum(wallet.get_balance_by_mixdepth(
        include_disabled=True).values())
    if balance + unconfirmed_balance != total_wallet_balance:
        jmprint(('BUG ERROR: wallet balance (%s) does not match balance from ' +
            'history (%s)') % (btc.sat_to_str(total_wallet_balance),
                btc.sat_to_str(balance)))
    wallet_utxo_count = sum(map(len, wallet.get_utxos_by_mixdepth(
        include_disabled=True).values()))
    if utxo_count + unconfirmed_utxo_count != wallet_utxo_count:
        jmprint(('BUG ERROR: wallet utxo count (%d) does not match utxo count from ' +
            'history (%s)') % (wallet_utxo_count, utxo_count))

    if unconfirmed_balance != 0:
        jmprint('unconfirmed balance change = %s BTC' % btc.sat_to_str(unconfirmed_balance))

    # wallet-tool.py prints return value, so return empty string instead of None here
    return ''


def wallet_showseed(wallet):
    seed, extension = wallet.get_mnemonic_words()
    text = "Wallet mnemonic recovery phrase:\n\n{}\n".format(seed)
    if extension:
        text += "\nWallet mnemonic extension: {}\n".format(extension.decode('utf-8'))
    return text


def wallet_importprivkey(wallet, mixdepth, key_type):
    jmprint("WARNING: This imported key will not be recoverable with your 12 "
          "word mnemonic phrase. Make sure you have backups.", "warning")
    jmprint("WARNING: Make sure that the type of the public address previously "
          "derived from this private key matches the wallet type you are "
          "currently using.")
    jmprint("WARNING: Handling of raw ECDSA bitcoin private keys can lead to "
          "non-intuitive behaviour and loss of funds.\n  Recommended instead "
          "is to use the \'sweep\' feature of sendpayment.py.", "warning")
    privkeys = input("Enter private key(s) to import: ")
    privkeys = privkeys.split(',') if ',' in privkeys else privkeys.split()
    imported_addr = []
    import_failed = 0
    # TODO read also one key for each line
    for wif in privkeys:
        # TODO is there any point in only accepting wif format? check what
        # other wallets do
        try:
            path = wallet.import_private_key(mixdepth, wif)
        except WalletError as e:
            print("Failed to import key {}: {}".format(wif, e))
            import_failed += 1
        else:
            imported_addr.append(wallet.get_address_from_path(path))

    if not imported_addr:
        jmprint("Warning: No keys imported!", "error")
        return

    wallet.save()

    # show addresses to user so they can verify everything went as expected
    jmprint("Imported keys for addresses:\n{}".format('\n'.join(imported_addr)),
            "success")
    if import_failed:
        jmprint("Warning: failed to import {} keys".format(import_failed),
                "error")


def wallet_dumpprivkey(wallet, hdpath):
    if not hdpath:
        jmprint("Error: no hd wallet path supplied", "error")
        return ""
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
    retval = "Signature: {}\nTo verify this in Bitcoin Core".format(sig)
    return retval + " use the RPC command 'verifymessage'"

def display_utxos_for_disable_choice_default(wallet_service, utxos_enabled,
        utxos_disabled):
    """ CLI implementation of the callback required as described in
    wallet_disableutxo
    """

    def default_user_choice(umax):
        jmprint("Choose an index 0 .. {} to freeze/unfreeze or "
                "-1 to just quit.".format(umax))
        while True:
            try:
                ret = int(input())
            except ValueError:
                jmprint("Invalid choice, must be an integer.", "error")
                continue
            if not isinstance(ret, int) or ret < -1 or ret > umax:
                jmprint("Invalid choice, must be between: -1 and {}, "
                        "try again.".format(umax), "error")
                continue
            break
        return ret

    def output_utxos(utxos, status, start=0):
        for (txid, idx), v in utxos.items():
            value = v['value']
            jmprint("{:4}: {} ({}): {} -- {}".format(
                start, fmt_utxo((txid, idx)),
                wallet_service.wallet.script_to_addr(v["script"]),
                btc.amount_to_str(value), status))
            start += 1
            yield txid, idx

    jmprint("List of UTXOs:")
    ulist = list(output_utxos(utxos_disabled, 'FROZEN'))
    disabled_max = len(ulist) - 1
    ulist.extend(output_utxos(utxos_enabled, 'NOT FROZEN', start=len(ulist)))
    max_id = len(ulist) - 1
    chosen_idx = default_user_choice(max_id)
    if chosen_idx == -1:
        return None
    # the return value 'disable' is the action we are going to take;
    # so it should be true if the utxos is currently unfrozen/enabled.
    disable = False if chosen_idx <= disabled_max else True
    return ulist[chosen_idx], disable

def get_utxos_enabled_disabled(wallet_service, md):
    """ Returns dicts for enabled and disabled separately
    """
    utxos_enabled = wallet_service.get_utxos_by_mixdepth()[md]
    utxos_all = wallet_service.get_utxos_by_mixdepth(include_disabled=True)[md]
    utxos_disabled_keyset = set(utxos_all).difference(set(utxos_enabled))
    utxos_disabled = {}
    for u in utxos_disabled_keyset:
        utxos_disabled[u] = utxos_all[u]
    return utxos_enabled, utxos_disabled

def wallet_freezeutxo(wallet_service, md, display_callback=None, info_callback=None):
    """ Given a wallet and a mixdepth, display to the user
    the set of available utxos, indexed by integer, and accept a choice
    of index to "freeze", then commit this disabling to the wallet storage,
    so that this disable-ment is persisted. Also allow unfreezing of a
    chosen utxo which is currently frozen.
    Callbacks for display and reporting can be specified in the keyword
    arguments as explained below, otherwise default CLI is used.

    ** display_callback signature:
    args:
    1. wallet_service
    2. utxos_enabled ; dict of utxos as format in wallet.py.
    3. utxos_disabled ; as above, for disabled
    returns:
    1.((txid(str), index(int)), disabled(bool)) of chosen utxo
    for freezing/unfreezing, or None for no action/cancel.
    ** info_callback signature:
    args:
    1. message (str)
    2. type (str) ("info", "error" etc as per jmprint)
    returns: None
    """
    if display_callback is None:
        display_callback = display_utxos_for_disable_choice_default
    if info_callback is None:
        info_callback = jmprint
    if md is None:
        info_callback("Specify the mixdepth with the -m flag", "error")
        return "Failed"
    while True:
        utxos_enabled, utxos_disabled = get_utxos_enabled_disabled(
            wallet_service, md)
        if utxos_disabled == {} and utxos_enabled == {}:
            info_callback("The mixdepth: " + str(md) + \
                " contains no utxos to freeze/unfreeze.", "error")
            return "Failed"
        display_ret = display_callback(wallet_service,
            utxos_enabled, utxos_disabled)
        if display_ret is None:
            break
        (txid, index), disable = display_ret
        wallet_service.disable_utxo(txid, index, disable)
        if disable:
            info_callback("Utxo: {} is now frozen and unavailable for spending."
                          .format(fmt_utxo((txid, index))))
        else:
            info_callback("Utxo: {} is now unfrozen and available for spending."
                          .format(fmt_utxo((txid, index))))
    return "Done"



def wallet_gettimelockaddress(wallet, locktime_string):
    if not isinstance(wallet, FidelityBondMixin):
        jmprint("Error: not a fidelity bond wallet", "error")
        return ""

    m = FidelityBondMixin.FIDELITY_BOND_MIXDEPTH
    address_type = FidelityBondMixin.BIP32_TIMELOCK_ID
    index = wallet.get_next_unused_index(m, address_type)
    lock_datetime = datetime.strptime(locktime_string, "%Y-%m")
    timenumber = FidelityBondMixin.timestamp_to_time_number(timegm(
        lock_datetime.timetuple()))

    path = wallet.get_path(m, address_type, index, timenumber)
    jmprint("path = " + wallet.get_path_repr(path), "info")
    jmprint("Coins sent to this address will be not be spendable until "
        + lock_datetime.strftime("%B %Y") + ". Full date: "
        + str(lock_datetime))
    addr = wallet.get_address_from_path(path)
    return addr

def wallet_addtxoutproof(wallet_service, hdpath, txoutproof):
    if not isinstance(wallet_service.wallet, FidelityBondMixin):
        jmprint("Error: not a fidelity bond wallet", "error")
        return ""
    path = hdpath.encode()
    if path not in wallet_service.wallet.get_burner_outputs():
        jmprint("Error: unknown burner transaction with on that path", "error")
        return ""
    txhex, block_height, old_merkle_branch, block_index = \
        wallet_service.wallet.get_burner_outputs()[path]
    new_merkle_branch = jm_single().bc_interface.core_proof_to_merkle_branch(txoutproof)
    txhex = binascii.hexlify(txhex).decode()
    txid = btc.txhash(txhex)
    if not jm_single().bc_interface.verify_tx_merkle_branch(txid, block_height,
            new_merkle_branch):
        jmprint("Error: tx out proof invalid", "error")
        return ""
    wallet_service.wallet.add_burner_output(hdpath, txhex, block_height,
        new_merkle_branch, block_index)
    return "Done"

def wallet_createwatchonly(wallet_root_path, master_pub_key):

    wallet_name = cli_get_wallet_file_name(defaultname="watchonly.jmdat")
    if not wallet_name:
        DEFAULT_WATCHONLY_WALLET_NAME = "watchonly.jmdat"
        wallet_name = DEFAULT_WATCHONLY_WALLET_NAME

    wallet_path = os.path.join(wallet_root_path, wallet_name)

    password = cli_get_wallet_passphrase_check()
    if not password:
        return ""

    entropy = FidelityBondMixin.get_xpub_from_fidelity_bond_master_pub_key(master_pub_key)
    if not entropy:
        jmprint("Error with provided master pub key", "error")
        return ""
    entropy = entropy.encode()

    wallet = create_wallet(wallet_path, password,
        max_mixdepth=FidelityBondMixin.FIDELITY_BOND_MIXDEPTH,
        wallet_cls=FidelityBondWatchonlyWallet, entropy=entropy)
    return "Done"

def get_configured_wallet_type(support_fidelity_bonds):
    configured_type = TYPE_P2PKH
    if is_segwit_mode():
        if is_native_segwit_mode():
            configured_type = TYPE_P2WPKH
        else:
            configured_type = TYPE_P2SH_P2WPKH

    if not support_fidelity_bonds:
        return configured_type

    if configured_type == TYPE_P2SH_P2WPKH:
        return TYPE_SEGWIT_LEGACY_WALLET_FIDELITY_BONDS
    else:
        raise ValueError("Fidelity bonds not supported with the configured "
            "options of segwit and native. Edit joinmarket.cfg")

def get_wallet_cls(wtype):
    cls = WALLET_IMPLEMENTATIONS.get(wtype)
    if not cls:
        raise WalletError("No wallet implementation found for type {}."
                          "".format(wtype))
    return cls

def create_wallet(path, password, max_mixdepth, wallet_cls, **kwargs):
    storage = Storage(path, password, create=True)
    wallet_cls.initialize(storage, get_network(), max_mixdepth=max_mixdepth,
                          **kwargs)
    storage.save()
    return wallet_cls(storage)


def open_test_wallet_maybe(path, seed, max_mixdepth,
                           test_wallet_cls=SegwitLegacyWallet, wallet_password_stdin=False, **kwargs):
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
    # If the native flag is set in the config, it overrides the argument
    # test_wallet_cls
    if jm_single().config.get("POLICY", "native") == "true":
        test_wallet_cls = SegwitWallet
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

    if wallet_password_stdin is True:
        stdin = sys.stdin.read()
        password = stdin.encode('utf-8')
        return open_wallet(path, ask_for_password=False, password=password, mixdepth=max_mixdepth, **kwargs)

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
                        "you need to convert it using the conversion script "
                        "at `scripts/convert_old_wallet.py`".format(path))

    if ask_for_password and Storage.is_encrypted_storage_file(path):
        while True:
            try:
                # do not try empty password, assume unencrypted on empty password
                pwd = get_password("Enter passphrase to decrypt wallet: ") or None
                storage = Storage(path, password=pwd, read_only=read_only)
            except StoragePasswordError:
                jmprint("Wrong password, try again.", "warning")
                continue
            except Exception as e:
                jmprint("Failed to load wallet, error message: " + repr(e),
                        "error")
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


def get_wallet_path(file_name, wallet_dir=None):
    if not wallet_dir:
        wallet_dir = os.path.join(jm_single().datadir, 'wallets')
    return os.path.join(wallet_dir, file_name)


def wallet_tool_main(wallet_root_path):
    """Main wallet tool script function; returned is a string (output or error)
    """
    parser = get_wallettool_parser()
    (options, args) = parser.parse_args()
    load_program_config(config_path=options.datadir)
    check_regtest(blockchain_start=False)
    # full path to the wallets/ subdirectory in the user data area:
    wallet_root_path = os.path.join(jm_single().datadir, wallet_root_path)
    noseed_methods = ['generate', 'recover', 'createwatchonly']
    methods = ['display', 'displayall', 'summary', 'showseed', 'importprivkey',
               'history', 'showutxos', 'freeze', 'gettimelockaddress',
               'addtxoutproof', 'changepass']
    methods.extend(noseed_methods)
    noscan_methods = ['showseed', 'importprivkey', 'dumpprivkey', 'signmessage',
                      'changepass']
    readonly_methods = ['display', 'displayall', 'summary', 'showseed',
                        'history', 'showutxos', 'dumpprivkey', 'signmessage',
                        'gettimelockaddress']

    if len(args) < 1:
        parser.error('Needs a wallet file or method')
        sys.exit(EXIT_ARGERROR)

    if options.mixdepth is not None and options.mixdepth < 0:
        parser.error("Must have at least one mixdepth.")
        sys.exit(EXIT_ARGERROR)

    if args[0] in noseed_methods:
        method = args[0]
        if options.mixdepth is None:
            options.mixdepth = DEFAULT_MIXDEPTH
    else:
        seed = args[0]
        wallet_path = get_wallet_path(seed, wallet_root_path)
        method = ('display' if len(args) == 1 else args[1].lower())
        read_only = method in readonly_methods

        #special case needed for fidelity bond burner outputs
        #maybe theres a better way to do this
        if options.recoversync:
            read_only = False

        wallet = open_test_wallet_maybe(
            wallet_path, seed, options.mixdepth, read_only=read_only,
            wallet_password_stdin=options.wallet_password_stdin, gap_limit=options.gaplimit)

        # this object is only to respect the layering,
        # the service will not be started since this is a synchronous script:
        wallet_service = WalletService(wallet)

        if method not in noscan_methods and jm_single().bc_interface is not None:
            # if nothing was configured, we override bitcoind's options so that
            # unconfirmed balance is included in the wallet display by default
            if 'listunspent_args' not in jm_single().config.options('POLICY'):
                jm_single().config.set('POLICY','listunspent_args', '[0]')
            while True:
                if wallet_service.sync_wallet(fast = not options.recoversync):
                    break

    #Now the wallet/data is prepared, execute the script according to the method
    if method == "display":
        return wallet_display(wallet_service, options.showprivkey)
    elif method == "displayall":
        return wallet_display(wallet_service, options.showprivkey,
                              displayall=True)
    elif method == "summary":
        return wallet_display(wallet_service, options.showprivkey, summarized=True)
    elif method == "history":
        if not isinstance(jm_single().bc_interface, BitcoinCoreInterface):
            jmprint('showing history only available when using the Bitcoin Core ' +
                    'blockchain interface', "error")
            sys.exit(EXIT_ARGERROR)
        else:
            return wallet_fetch_history(wallet_service, options)
    elif method == "generate":
        retval = wallet_generate_recover("generate", wallet_root_path,
                                         mixdepth=options.mixdepth)
        return "Generated wallet OK" if retval else "Failed"
    elif method == "recover":
        retval = wallet_generate_recover("recover", wallet_root_path,
                                         mixdepth=options.mixdepth)
        return "Recovered wallet OK" if retval else "Failed"
    elif method == "changepass":
        retval = wallet_change_passphrase(wallet_service)
        return "Changed encryption passphrase OK" if retval else "Failed"
    elif method == "showutxos":
        return wallet_showutxos(wallet_service, options.showprivkey)
    elif method == "showseed":
        return wallet_showseed(wallet_service)
    elif method == "dumpprivkey":
        return wallet_dumpprivkey(wallet_service, options.hd_path)
    elif method == "importprivkey":
        #note: must be interactive (security)
        if options.mixdepth is None:
            parser.error("You need to specify a mixdepth with -m")
        wallet_importprivkey(wallet_service, options.mixdepth,
                             map_key_type(options.key_type))
        return "Key import completed."
    elif method == "signmessage":
        if len(args) < 3:
            jmprint('Must provide message to sign', "error")
            sys.exit(EXIT_ARGERROR)
        return wallet_signmessage(wallet_service, options.hd_path, args[2])
    elif method == "freeze":
        return wallet_freezeutxo(wallet_service, options.mixdepth)
    elif method == "gettimelockaddress":
        if len(args) < 3:
            jmprint('Must have locktime value yyyy-mm. For example 2021-03', "error")
            sys.exit(EXIT_ARGERROR)
        return wallet_gettimelockaddress(wallet_service.wallet, args[2])
    elif method == "addtxoutproof":
        if len(args) < 3:
            jmprint('Must have txout proof, which is the output of Bitcoin '
                + 'Core\'s RPC call gettxoutproof', "error")
            sys.exit(EXIT_ARGERROR)
        return wallet_addtxoutproof(wallet_service, options.hd_path, args[2])
    elif method == "createwatchonly":
        if len(args) < 2:
            jmprint("args: [master public key]", "error")
            sys.exit(EXIT_ARGERROR)
        return wallet_createwatchonly(wallet_root_path, args[1])
    else:
        parser.error("Unknown wallet-tool method: " + method)
        sys.exit(EXIT_ARGERROR)


#Testing (can port to test modules, TODO)
if __name__ == "__main__":
    if not test_bip32_pathparse():
        sys.exit(EXIT_FAILURE)
    rootpath="m/0"
    walletbranch = 0
    accounts = range(3)
    acctlist = []
    for a in accounts:
        branches = []
        for address_type in range(2):
            entries = []
            for i in range(4):
                entries.append(WalletViewEntry(rootpath, a, address_type,
                                       i, "DUMMYADDRESS"+str(i+a),
                                       [i*10000000, i*10000000]))
            branches.append(WalletViewBranch(rootpath,
                                            a, address_type, branchentries=entries,
                                            xpub="xpubDUMMYXPUB"+str(a+address_type)))
        acctlist.append(WalletViewAccount(rootpath, a, branches=branches))
    wallet = WalletView(rootpath + "/" + str(walletbranch),
                             accounts=acctlist)
    jmprint(wallet.serialize(), "success")

