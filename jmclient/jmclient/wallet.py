from __future__ import print_function
import json
import os
import pprint
import sys
from decimal import Decimal

from ConfigParser import NoSectionError
from getpass import getpass

import btc
from jmclient.slowaes import decryptData
from jmclient.blockchaininterface import BitcoinCoreInterface, RegtestBitcoinCoreInterface
from jmclient.configure import jm_single, get_network, get_p2pk_vbyte
from jmbase.support import get_log
from jmclient.support import select_gradual, select_greedy,select_greediest, select

log = get_log()

class WalletError(Exception):
    pass

def estimate_tx_fee(ins, outs, txtype='p2pkh'):
    '''Returns an estimate of the number of satoshis required
    for a transaction with the given number of inputs and outputs,
    based on information from the blockchain interface.
    '''
    tx_estimated_bytes = btc.estimate_tx_size(ins, outs, txtype)
    log.debug("Estimated transaction size: "+str(tx_estimated_bytes))
    fee_per_kb = jm_single().bc_interface.estimate_fee_per_kb(
        jm_single().config.getint("POLICY", "tx_fees"))
    absurd_fee = jm_single().config.getint("POLICY", "absurd_fee_per_kb")
    if fee_per_kb > absurd_fee:
        #This error is considered critical; for safety reasons, shut down.
        raise ValueError("Estimated fee per kB greater than absurd value: " + \
                         str(absurd_fee) + ", quitting.")
    log.debug("got estimated tx bytes: "+str(tx_estimated_bytes))
    return int((tx_estimated_bytes * fee_per_kb)/Decimal(1000.0))

class AbstractWallet(object):
    """
    Abstract wallet for use with JoinMarket
    Mostly written with Wallet in mind, the default JoinMarket HD wallet
    """

    def __init__(self):
        self.max_mix_depth = 0
        self.unspent = None
        self.utxo_selector = select
        try:
            config = jm_single().config
            if config.get("POLICY", "merge_algorithm") == "gradual":
                self.utxo_selector = select_gradual
            elif config.get("POLICY", "merge_algorithm") == "greedy":
                self.utxo_selector = select_greedy
            elif config.get("POLICY", "merge_algorithm") == "greediest":
                self.utxo_selector = select_greediest
            elif config.get("POLICY", "merge_algorithm") != "default":
                raise Exception("Unknown merge algorithm")
        except NoSectionError:
            pass

    def get_key_from_addr(self, addr):
        return None

    def get_utxos_by_mixdepth(self):
        return None

    def get_external_addr(self, mixing_depth):
        """
        Return an address suitable for external distribution, including funding
        the wallet from other sources, or receiving payments or donations.
        JoinMarket will never generate these addresses for internal use.
        """
        return None

    def get_internal_addr(self, mixing_depth):
        """
        Return an address for internal usage, as change addresses and when
        participating in transactions initiated by other parties.
        """
        return None

    def update_cache_index(self):
        pass

    def remove_old_utxos(self, tx):
        pass

    def add_new_utxos(self, tx, txid):
        pass

    def select_utxos(self, mixdepth, amount):
        utxo_list = self.get_utxos_by_mixdepth()[mixdepth]
        unspent = [{'utxo': utxo,
                    'value': addrval['value']}
                   for utxo, addrval in utxo_list.iteritems()]
        inputs = self.utxo_selector(unspent, amount)
        log.debug('for mixdepth={} amount={} selected:'.format(
            mixdepth, amount))
        log.debug(pprint.pformat(inputs))
        return dict([(i['utxo'], {'value': i['value'],
                             'address': utxo_list[i['utxo']]['address']})
                     for i in inputs])

    def get_balance_by_mixdepth(self):
        mix_balance = {}
        for m in range(self.max_mix_depth):
            mix_balance[m] = 0
        for mixdepth, utxos in self.get_utxos_by_mixdepth().iteritems():
            mix_balance[mixdepth] = sum(
                    [addrval['value'] for addrval in utxos.values()])
        return mix_balance

class Wallet(AbstractWallet):
    def __init__(self,
                 seedarg,
                 pwd,
                 max_mix_depth=2,
                 gaplimit=6,
                 extend_mixdepth=False,
                 storepassword=False):
        super(Wallet, self).__init__()
        self.max_mix_depth = max_mix_depth
        self.storepassword = storepassword
        # key is address, value is (mixdepth, forchange, index) if mixdepth =
        #  -1 it's an imported key and index refers to imported_privkeys
        self.addr_cache = {}
        self.unspent = {}
        self.spent_utxos = []
        self.imported_privkeys = {}
        self.seed = self.read_wallet_file_data(seedarg, pwd)
        if not self.seed:
            raise WalletError("Failed to decrypt wallet")
        if extend_mixdepth and len(self.index_cache) > max_mix_depth:
            self.max_mix_depth = len(self.index_cache)
        self.gaplimit = gaplimit
        master = btc.bip32_master_key(self.seed, (btc.MAINNET_PRIVATE if
            get_network() == 'mainnet' else btc.TESTNET_PRIVATE))
        m_0 = btc.bip32_ckd(master, 0)
        mixing_depth_keys = [btc.bip32_ckd(m_0, c)
                             for c in range(self.max_mix_depth)]
        self.keys = [(btc.bip32_ckd(m, 0), btc.bip32_ckd(m, 1))
                     for m in mixing_depth_keys]

        # self.index = [[0, 0]]*max_mix_depth
        self.index = []
        for i in range(self.max_mix_depth):
            self.index.append([0, 0])

    def read_wallet_file_data(self, filename, pwd=None):
        self.path = None
        self.index_cache = [[0, 0]] * self.max_mix_depth
        path = os.path.join('wallets', filename)
        if not os.path.isfile(path):
            if get_network() == 'testnet':
                log.debug('filename interpreted as seed, only available in '
                          'testnet because this probably has lower entropy')
                return filename
            else:
                raise IOError('wallet file not found')
        if not pwd:
            log.info("Password required for non-testnet seed wallet")
            return None
        self.path = path
        fd = open(path, 'r')
        walletfile = fd.read()
        fd.close()
        walletdata = json.loads(walletfile)
        if walletdata['network'] != get_network():
            raise ValueError('wallet network(%s) does not match '
                   'joinmarket configured network(%s)' % (
                walletdata['network'], get_network()))
        if 'index_cache' in walletdata:
            self.index_cache = walletdata['index_cache']
        password_key = btc.bin_dbl_sha256(pwd)
        encrypted_seed = walletdata['encrypted_seed']
        try:
            decrypted_seed = decryptData(
                    password_key,
                    encrypted_seed.decode('hex')).encode('hex')
            # there is a small probability of getting a valid PKCS7
            # padding by chance from a wrong password; sanity check the
            # seed length
            if len(decrypted_seed) != 32:
                raise ValueError
        except ValueError:
            log.info('Incorrect password')
            return None
        if self.storepassword:
            self.password_key = password_key
            self.walletdata = walletdata
        if 'imported_keys' in walletdata:
            for epk_m in walletdata['imported_keys']:
                privkey = decryptData(
                        password_key,
                        epk_m['encrypted_privkey'].decode( 'hex')).encode('hex')
                #Imported keys are stored as 32 byte strings only, so the
                #second version below is sufficient, really.
                if len(privkey) != 64:
                    raise Exception(
                    "Unexpected privkey format; already compressed?:" + privkey)
                privkey += "01"
                if epk_m['mixdepth'] not in self.imported_privkeys:
                    self.imported_privkeys[epk_m['mixdepth']] = []
                self.addr_cache[btc.privtoaddr(
                        privkey, magicbyte=get_p2pk_vbyte())] = (epk_m['mixdepth'], -1,
                    len(self.imported_privkeys[epk_m['mixdepth']]))
                self.imported_privkeys[epk_m['mixdepth']].append(privkey)
        return decrypted_seed

    def update_cache_index(self):
        if not self.path:
            return
        if not os.path.isfile(self.path):
            return
        fd = open(self.path, 'r')
        walletfile = fd.read()
        fd.close()
        walletdata = json.loads(walletfile)
        walletdata['index_cache'] = self.index
        walletfile = json.dumps(walletdata)
        fd = open(self.path, 'w')
        fd.write(walletfile)
        fd.close()

    def get_key(self, mixing_depth, forchange, i):
        return btc.bip32_extract_key(btc.bip32_ckd(
                self.keys[mixing_depth][forchange], i))

    def get_addr(self, mixing_depth, forchange, i):
        return btc.privtoaddr(
                self.get_key(mixing_depth, forchange, i), magicbyte=get_p2pk_vbyte())

    def get_new_addr(self, mixing_depth, forchange):
        index = self.index[mixing_depth]
        addr = self.get_addr(mixing_depth, forchange, index[forchange])
        self.addr_cache[addr] = (mixing_depth, forchange, index[forchange])
        index[forchange] += 1
        # self.update_cache_index()
        bc_interface = jm_single().bc_interface
        if isinstance(bc_interface, BitcoinCoreInterface) or isinstance(
            bc_interface, RegtestBitcoinCoreInterface):
            # do not import in the middle of sync_wallet()
            if bc_interface.wallet_synced:
                if bc_interface.rpc('getaccount', [addr]) == '':
                    log.debug('importing address ' + addr + ' to bitcoin core')
                    bc_interface.rpc(
                            'importaddress',
                            [addr, bc_interface.get_wallet_name(self), False])
        return addr

    def get_external_addr(self, mixing_depth):
        return self.get_new_addr(mixing_depth, 0)

    def get_internal_addr(self, mixing_depth):
        return self.get_new_addr(mixing_depth, 1)

    def get_key_from_addr(self, addr):
        if addr not in self.addr_cache:
            return None
        ac = self.addr_cache[addr]
        if ac[1] >= 0:
            return self.get_key(*ac)
        else:
            return self.imported_privkeys[ac[0]][ac[2]]

    def remove_old_utxos(self, tx):
        removed_utxos = {}
        for ins in tx['ins']:
            utxo = ins['outpoint']['hash'] + ':' + str(ins['outpoint']['index'])
            if utxo not in self.unspent:
                continue
            removed_utxos[utxo] = self.unspent[utxo]
            del self.unspent[utxo]
        log.debug('removed utxos, wallet now is \n' + pprint.pformat(
                self.get_utxos_by_mixdepth()))
        self.spent_utxos += removed_utxos.keys()
        return removed_utxos

    def add_new_utxos(self, tx, txid):
        added_utxos = {}
        for index, outs in enumerate(tx['outs']):
            addr = btc.script_to_address(outs['script'], get_p2pk_vbyte())
            if addr not in self.addr_cache:
                continue
            addrdict = {'address': addr, 'value': outs['value']}
            utxo = txid + ':' + str(index)
            added_utxos[utxo] = addrdict
            self.unspent[utxo] = addrdict
        log.debug('added utxos, wallet now is \n' + pprint.pformat(
                self.get_utxos_by_mixdepth()))
        return added_utxos

    def get_utxos_by_mixdepth(self):
        """
        returns a list of utxos sorted by different mix levels
        """
        mix_utxo_list = {}
        for m in range(self.max_mix_depth):
            mix_utxo_list[m] = {}
        for utxo, addrvalue in self.unspent.iteritems():
            mixdepth = self.addr_cache[addrvalue['address']][0]
            if mixdepth not in mix_utxo_list:
                mix_utxo_list[mixdepth] = {}
            mix_utxo_list[mixdepth][utxo] = addrvalue
        log.debug('get_utxos_by_mixdepth = \n' + pprint.pformat(mix_utxo_list))
        return mix_utxo_list


class BitcoinCoreWallet(AbstractWallet): #pragma: no cover
    def __init__(self, fromaccount):
        super(BitcoinCoreWallet, self).__init__()
        if not isinstance(jm_single().bc_interface,
                          BitcoinCoreInterface):
            raise RuntimeError('Bitcoin Core wallet can only be used when '
                               'blockchain interface is BitcoinCoreInterface')
        self.fromaccount = fromaccount
        self.max_mix_depth = 1

    def get_key_from_addr(self, addr):
        self.ensure_wallet_unlocked()
        wifkey = jm_single().bc_interface.rpc('dumpprivkey', [addr])
        return btc.from_wif_privkey(wifkey, vbyte=get_p2pk_vbyte())

    def get_utxos_by_mixdepth(self):
        unspent_list = jm_single().bc_interface.rpc('listunspent', [])
        result = {0: {}}
        for u in unspent_list:
            if not u['spendable']:
                continue
            if self.fromaccount and (
                        ('account' not in u) or u['account'] !=
                        self.fromaccount):
                continue
            result[0][u['txid'] + ':' + str(u['vout'])] = {
                'address': u['address'],
                'value': int(Decimal(str(u['amount'])) * Decimal('1e8'))}
        return result

    def get_internal_addr(self, mixing_depth):
        return jm_single().bc_interface.rpc('getrawchangeaddress', [])

    @staticmethod
    def ensure_wallet_unlocked():
        wallet_info = jm_single().bc_interface.rpc('getwalletinfo', [])
        if 'unlocked_until' in wallet_info and wallet_info[
            'unlocked_until'] <= 0:
            while True:
                password = getpass(
                        'Enter passphrase to unlock wallet: ')
                if password == '':
                    raise RuntimeError('Aborting wallet unlock')
                try:
                    # TODO cleanly unlock wallet after use, not with arbitrary timeout
                    jm_single().bc_interface.rpc(
                            'walletpassphrase', [password, 10])
                    break
                except jm_single().JsonRpcError as exc:
                    if exc.code != -14:
                        raise exc
                        # Wrong passphrase, try again.
