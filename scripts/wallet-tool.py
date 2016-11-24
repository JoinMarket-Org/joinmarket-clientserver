from __future__ import absolute_import, print_function

import datetime
import getpass
import json
import os
import sys
import sqlite3
from optparse import OptionParser

from jmclient import (load_program_config, get_network, Wallet,
                      encryptData, get_p2pk_vbyte, jm_single,
                      mn_decode, mn_encode, BitcoinCoreInterface,
                      JsonRpcError, sync_wallet)

import jmclient.btc as btc

description = (
    'Does useful little tasks involving your bip32 wallet. The '
    'method is one of the following: (display) Shows addresses and '
    'balances. (displayall) Shows ALL addresses and balances. '
    '(summary) Shows a summary of mixing depth balances. (generate) '
    'Generates a new wallet. (recover) Recovers a wallet from the 12 '
    'word recovery seed. (showutxos) Shows all utxos in the wallet, '
    'including the corresponding private keys if -p is chosen; the '
    'data is also written to a file "walletname.json.utxos" if the '
    'option -u is chosen (so be careful about private keys). '
    '(showseed) Shows the wallet recovery seed '
    'and hex seed. (importprivkey) Adds privkeys to this wallet, '
    'privkeys are spaces or commas separated. (dumpprivkey) Export '
    'a single private key, specify an hd wallet path (listwallets) '
    'Lists all wallets with creator and timestamp. (history) Show '
    'all historical transaction details. Requires Bitcoin Core.')

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
(options, args) = parser.parse_args()

# if the index_cache stored in wallet.json is longer than the default
# then set maxmixdepth to the length of index_cache
maxmixdepth_configured = True
if not options.maxmixdepth:
    maxmixdepth_configured = False
    options.maxmixdepth = 5

noseed_methods = ['generate', 'recover', 'listwallets']
methods = ['display', 'displayall', 'summary', 'showseed', 'importprivkey',
    'history', 'showutxos']
methods.extend(noseed_methods)
noscan_methods = ['showseed', 'importprivkey', 'dumpprivkey']

if len(args) < 1:
    parser.error('Needs a wallet file or method')
    sys.exit(0)

load_program_config()

if args[0] in noseed_methods:
    method = args[0]
else:
    seed = args[0]
    method = ('display' if len(args) == 1 else args[1].lower())
    wallet = Wallet(seed,
                    options.maxmixdepth,
                    options.gaplimit,
                    extend_mixdepth=not maxmixdepth_configured,
                    storepassword=(method == 'importprivkey'))
    if method == 'history' and not isinstance(jm_single().bc_interface,
            BitcoinCoreInterface):
        print('showing history only available when using the Bitcoin Core ' +
            'blockchain interface')
        sys.exit(0)
    if method not in noscan_methods:
        # if nothing was configured, we override bitcoind's options so that
        # unconfirmed balance is included in the wallet display by default
        if 'listunspent_args' not in jm_single().config.options('POLICY'):
            jm_single().config.set('POLICY','listunspent_args', '[0]')

        sync_wallet(wallet, fast=options.fastsync)

if method == 'showutxos':
    unsp = {}
    if options.showprivkey:
        for u, av in wallet.unspent.iteritems():
            addr = av['address']
            key = wallet.get_key_from_addr(addr)
            wifkey = btc.wif_compressed_privkey(key, vbyte=get_p2pk_vbyte())
            unsp[u] = {'address': av['address'],
                       'value': av['value'], 'privkey': wifkey}
    else:
        unsp = wallet.unspent
    print(json.dumps(unsp, indent=4))
    sys.exit(0)

if method == 'display' or method == 'displayall' or method == 'summary':

    def cus_print(s):
        if method != 'summary':
            print(s)

    total_balance = 0
    for m in range(wallet.max_mix_depth):
        cus_print('mixing depth %d m/0/%d/' % (m, m))
        balance_depth = 0
        for forchange in [0, 1]:
            if forchange == 0:
                xpub_key = btc.bip32_privtopub(wallet.keys[m][forchange])
            else:
                xpub_key = ''
            cus_print(' ' + ('external' if forchange == 0 else 'internal') +
                      ' addresses m/0/%d/%d' % (m, forchange) + ' ' + xpub_key)

            for k in range(wallet.index[m][forchange] + options.gaplimit):
                addr = wallet.get_addr(m, forchange, k)
                balance = 0.0
                for addrvalue in wallet.unspent.values():
                    if addr == addrvalue['address']:
                        balance += addrvalue['value']
                balance_depth += balance
                used = ('used' if k < wallet.index[m][forchange] else ' new')
                if options.showprivkey:
                    privkey = btc.wif_compressed_privkey(
                    wallet.get_key(m, forchange, k), get_p2pk_vbyte())
                else:
                    privkey = ''
                if (method == 'displayall' or balance > 0 or
                    (used == ' new' and forchange == 0)):
                    cus_print('  m/0/%d/%d/%03d %-35s%s %.8f btc %s' %
                              (m, forchange, k, addr, used, balance / 1e8,
                               privkey))
        if m in wallet.imported_privkeys:
            cus_print(' import addresses')
            for privkey in wallet.imported_privkeys[m]:
                addr = btc.privtoaddr(privkey, magicbyte=get_p2pk_vbyte())
                balance = 0.0
                for addrvalue in wallet.unspent.values():
                    if addr == addrvalue['address']:
                        balance += addrvalue['value']
                used = (' used' if balance > 0.0 else 'empty')
                balance_depth += balance
                if options.showprivkey:
                    wip_privkey = btc.wif_compressed_privkey(
                    privkey, get_p2pk_vbyte())
                else:
                    wip_privkey = ''
                cus_print(' ' * 13 + '%-35s%s %.8f btc %s' % (
                    addr, used, balance / 1e8, wip_privkey))
        total_balance += balance_depth
        print('for mixdepth=%d balance=%.8fbtc' % (m, balance_depth / 1e8))
    print('total balance = %.8fbtc' % (total_balance / 1e8))
elif method == 'generate' or method == 'recover':
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
            sys.exit(0)
        seed = mn_decode(words)
        print(seed)
    password = getpass.getpass('Enter wallet encryption passphrase: ')
    password2 = getpass.getpass('Reenter wallet encryption passphrase: ')
    if password != password2:
        print('ERROR. Passwords did not match')
        sys.exit(0)
    password_key = btc.bin_dbl_sha256(password)
    encrypted_seed = encryptData(password_key, seed.decode('hex'))
    timestamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    walletfile = json.dumps({'creator': 'joinmarket project',
                             'creation_time': timestamp,
                             'encrypted_seed': encrypted_seed.encode('hex'),
                             'network': get_network()})
    walletname = raw_input('Input wallet file name (default: wallet.json): ')
    if len(walletname) == 0:
        walletname = 'wallet.json'
    walletpath = os.path.join('wallets', walletname)
    # Does a wallet with the same name exist?
    if os.path.isfile(walletpath):
        print('ERROR: ' + walletpath + ' already exists. Aborting.')
        sys.exit(0)
    else:
        fd = open(walletpath, 'w')
        fd.write(walletfile)
        fd.close()
        print('saved to ' + walletname)
elif method == 'showseed':
    hexseed = wallet.seed
    print('hexseed = ' + hexseed)
    words = mn_encode(hexseed)
    print('Wallet recovery seed\n\n' + ' '.join(words) + '\n')
elif method == 'importprivkey':
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
             'mixdepth': options.mixdepth})
    if wallet.walletdata['imported_keys']:
        fd = open(wallet.path, 'w')
        fd.write(json.dumps(wallet.walletdata))
        fd.close()
        print('Private key(s) successfully imported')
elif method == 'dumpprivkey':
    if options.hd_path.startswith('m/0/'):
        m, forchange, k = [int(y) for y in options.hd_path[4:].split('/')]
        key = wallet.get_key(m, forchange, k)
        wifkey = btc.wif_compressed_privkey(key, vbyte=get_p2pk_vbyte())
        print(wifkey)
    else:
        print('%s is not a valid hd wallet path' % options.hd_path)
elif method == 'listwallets':
    # Fetch list of wallets
    possible_wallets = []
    for (dirpath, dirnames, filenames) in os.walk('wallets'):
        possible_wallets.extend(filenames)
        # Breaking as we only want the top dir, not subdirs
        break
    # For each possible wallet file, read json to list
    walletjsons = []
    for possible_wallet in possible_wallets:
        fd = open(os.path.join('wallets', possible_wallet), 'r')
        try:
            walletfile = fd.read()
            walletjson = json.loads(walletfile)
            # Add filename to json format
            walletjson['filename'] = possible_wallet
            walletjsons.append(walletjson)
        except ValueError:
            pass
    # Sort wallets by date
    walletjsons.sort(key=lambda r: r['creation_time'])
    i = 1
    print(' ')
    for walletjson in walletjsons:
        print('Wallet #' + str(i) + ' (' + walletjson['filename'] + '):')
        print('Creation time:\t' + walletjson['creation_time'])
        print('Creator:\t' + walletjson['creator'])
        print('Network:\t' + walletjson['network'])
        print(' ')
        i += 1
    print(str(i - 1) + ' Wallets have been found.')
elif method == 'history':
    #sort txes in a db because python can be really bad with large lists
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

    field_names = ['tx#', 'timestamp', 'type', 'amount/btc',
        'balance-change/btc', 'balance/btc', 'coinjoin-n', 'total-fees',
        'utxo-count', 'mixdepth-from', 'mixdepth-to']
    if options.csv:
        field_names += ['txid']
    l = s().join(field_names)
    print(l)
    balance = 0
    utxo_count = 0
    deposits = []
    deposit_times = []
    for i, tx in enumerate(txes):
        rpctx = jm_single().bc_interface.rpc('gettransaction', [tx['txid']])
        txhex = str(rpctx['hex'])
        txd = btc.deserialize(txhex)
        output_addr_values = dict(((btc.script_to_address(sv['script'],
            get_p2pk_vbyte()), sv['value']) for sv in txd['outs']))
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
            get_p2pk_vbyte()) for ind in rpc_inputs))
        our_input_addrs = wallet_addr_set.intersection(rpc_input_addrs)
        our_input_values = [ind['value'] for ind in rpc_inputs if btc.
            script_to_address(ind['script'], get_p2pk_vbyte()) in
            our_input_addrs]
        our_input_value = sum(our_input_values)
        utxos_consumed = len(our_input_values)

        tx_type = None
        amount = 0
        delta_balance = 0
        fees = -1
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
        elif len(our_input_addrs) > 0 and len(our_output_addrs) == 0:
            #we swept coins elsewhere
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
            #payment out somewhere with our change address getting the remaining
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
        balance += delta_balance
        utxo_count += (len(our_output_addrs) - utxos_consumed)
        index = '% 4d'%(i)
        timestamp = datetime.datetime.fromtimestamp(rpctx['blocktime']
            ).strftime("%Y-%m-%d %H:%M")
        utxo_count_str = '% 3d' % (utxo_count)
        printable_data = [index, timestamp, tx_type, sat_to_str(amount),
            sat_to_str_p(delta_balance), sat_to_str(balance), skip_n1(cj_n),
            skip_n1_btc(fees), utxo_count_str, skip_n1(mixdepth_src),
            skip_n1(mixdepth_dst)]
        if options.csv:
            printable_data += [tx['txid']]
        l = s().join(map('"{}"'.format, printable_data))
        print(l)

        if tx_type != 'cj internal':
            deposits.append(delta_balance)
            deposit_times.append(rpctx['blocktime'])

    bestblockhash = jm_single().bc_interface.rpc('getbestblockhash', [])
    try:
        #works with pruning enabled, but only after v0.12
        now = jm_single().bc_interface.rpc('getblockheader', [bestblockhash]
            )['time']
    except JsonRpcError:
        now = jm_single().bc_interface.rpc('getblock', [bestblockhash])['time']
    print('     %s best block is %s' % (datetime.datetime.fromtimestamp(now)
        .strftime("%Y-%m-%d %H:%M"), bestblockhash))
    try:
        #https://gist.github.com/chris-belcher/647da261ce718fc8ca10
        import numpy as np
        from scipy.optimize import brentq
        deposit_times = np.array(deposit_times)
        now -= deposit_times[0]
        deposit_times -= deposit_times[0]
        deposits = np.array(deposits)
        def f(r, deposits, deposit_times, now, final_balance):
            return np.sum(np.exp((now - deposit_times) / 60.0 / 60 / 24 /
                365)**r * deposits) - final_balance
        r = brentq(f, a=1, b=-1, args=(deposits, deposit_times, now,
            balance))
        print('continuously compounded equivalent annual interest rate = ' +
            str(r * 100) + ' %')
        print('(as if yield generator was a bank account)')
    except ImportError:
        print('numpy/scipy not installed, unable to calculate effective ' +
            'interest rate')

    total_wallet_balance = sum(wallet.get_balance_by_mixdepth().values())
    if balance != total_wallet_balance:
        print(('BUG ERROR: wallet balance (%s) does not match balance from ' +
            'history (%s)') % (sat_to_str(total_wallet_balance),
            sat_to_str(balance)))
    if utxo_count != len(wallet.unspent):
        print(('BUG ERROR: wallet utxo count (%d) does not match utxo count from ' +
            'history (%s)') % (len(wallet.unspent), utxo_count))
