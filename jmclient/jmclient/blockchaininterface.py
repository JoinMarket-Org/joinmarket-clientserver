from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401

import abc
import ast
import random
import sys
import time
import binascii
from copy import deepcopy
from decimal import Decimal
from twisted.internet import reactor, task

import jmbitcoin as btc

from jmclient.jsonrpc import JsonRpcConnectionError, JsonRpcError
from jmclient.configure import get_p2pk_vbyte, jm_single
from jmbase.support import get_log, jmprint

log = get_log()


def sync_wallet(wallet, fast=False):
    """Wrapper function to choose fast syncing where it's
    both possible and requested.
    """
    if fast and (
        isinstance(jm_single().bc_interface, BitcoinCoreInterface) or isinstance(
                jm_single().bc_interface, RegtestBitcoinCoreInterface)):
        jm_single().bc_interface.sync_wallet(wallet, fast=True)
    else:
        jm_single().bc_interface.sync_wallet(wallet)

class BlockchainInterface(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self):
        pass

    def sync_wallet(self, wallet, restart_cb=None):
        """Default behaviour is for Core and similar interfaces.
	If address sync fails, flagged with wallet_synced value;
	do not attempt to sync_unspent in that case.
	"""
        self.sync_addresses(wallet, restart_cb)
        if self.wallet_synced:
            self.sync_unspent(wallet)

    @staticmethod
    def get_wallet_name(wallet):
        return 'joinmarket-wallet-' + wallet.get_wallet_id()

    @abc.abstractmethod
    def sync_addresses(self, wallet):
        """Finds which addresses have been used"""

    @abc.abstractmethod
    def sync_unspent(self, wallet):
        """Finds the unspent transaction outputs belonging to this wallet"""

    def is_address_imported(self, addr):
        try:
            return self.rpc('getaccount', [addr]) != ''
        except JsonRpcError:
            return len(self.rpc('getaddressinfo', [addr])['labels']) > 0

    def add_tx_notify(self, txd, unconfirmfun, confirmfun, notifyaddr,
                      wallet_name=None, timeoutfun=None, spentfun=None, txid_flag=True,
                      n=0, c=1, vb=None):
        """Given a deserialized transaction txd,
        callback functions for broadcast and confirmation of the transaction,
        an address to import, and a callback function for timeout, set up
        a polling loop to check for events on the transaction. Also optionally set
        to trigger "confirmed" callback on number of confirmations c. Also checks
        for spending (if spentfun is not None) of the outpoint n.
        If txid_flag is True, we create a watcher loop on the txid (hence only
        really usable in a segwit context, and only on fully formed transactions),
        else we create a watcher loop on the output set of the transaction (taken
        from the outs field of the txd).
        """
        if not vb:
            vb = get_p2pk_vbyte()
        if isinstance(self, BitcoinCoreInterface) or isinstance(self,
                                        RegtestBitcoinCoreInterface):
            #This code ensures that a walletnotify is triggered, by
            #ensuring that at least one of the output addresses is
            #imported into the wallet (note the sweep special case, where
            #none of the output addresses belong to me).
            one_addr_imported = False
            for outs in txd['outs']:
                addr = btc.script_to_address(outs['script'], vb)
                try:
                    if self.is_address_imported(addr):
                        one_addr_imported = True
                        break
                except JsonRpcError as e:
                    log.debug("Failed to getaccount for address: " + addr)
                    log.debug("This is normal for bech32 addresses.")
                    continue
            if not one_addr_imported:
                try:
                    self.rpc('importaddress', [notifyaddr, 'joinmarket-notify', False])
                except JsonRpcError as e:
                    #In edge case of address already controlled
                    #by another account, warn but do not quit in middle of tx.
                    #Can occur if destination is owned in Core wallet.
                    if e.code == -4 and e.message == "The wallet already " + \
                       "contains the private key for this address or script":
                        log.warn("WARNING: Failed to import address: " + notifyaddr)
                    #No other error should be possible
                    else:
                        raise

        #Warning! In case of txid_flag false, this is *not* a valid txid,
        #but only a hash of an incomplete transaction serialization.
        txid = btc.txhash(btc.serialize(txd))
        if not txid_flag:
            tx_output_set = set([(sv['script'], sv['value']) for sv in txd['outs']])
            loop = task.LoopingCall(self.outputs_watcher, wallet_name, notifyaddr,
                                    tx_output_set, unconfirmfun, confirmfun,
                                    timeoutfun)
            log.debug("Created watcher loop for address: " + notifyaddr)
            loopkey = notifyaddr
        else:
            loop = task.LoopingCall(self.tx_watcher, txd, unconfirmfun, confirmfun,
                                    spentfun, c, n)
            log.debug("Created watcher loop for txid: " + txid)
            loopkey = txid
        self.tx_watcher_loops[loopkey] = [loop, False, False, False]
        #Hardcoded polling interval, but in any case it can be very short.
        loop.start(5.0)
        #Give up on un-broadcast transactions and broadcast but not confirmed
        #transactions as per settings in the config.
        reactor.callLater(float(jm_single().config.get("TIMEOUT",
                    "unconfirm_timeout_sec")), self.tx_network_timeout, loopkey)
        confirm_timeout_sec = int(jm_single().config.get(
            "TIMEOUT", "confirm_timeout_hours")) * 3600
        reactor.callLater(confirm_timeout_sec, self.tx_timeout, txd, loopkey, timeoutfun)

    def tx_network_timeout(self, loopkey):
        """If unconfirm has not been called by the time this
	is triggered, we abandon monitoring, assuming the tx has
	not been broadcast.
	"""
        if not self.tx_watcher_loops[loopkey][1]:
            log.info("Abandoning monitoring of un-broadcast tx for: " + str(loopkey))
            if self.tx_watcher_loops[loopkey][0].running:
                self.tx_watcher_loops[loopkey][0].stop()

    def tx_timeout(self, txd, loopkey, timeoutfun):
        """Assuming we are watching for an already-broadcast
	transaction, give up once this triggers if confirmation has not occurred.
	"""
        if not loopkey in self.tx_watcher_loops:
            #Occurs if the tx has already confirmed before this
            return
        if not self.tx_watcher_loops[loopkey][2]:
            #Not confirmed after prescribed timeout in hours; give up
            log.info("Timed out waiting for confirmation of: " + str(loopkey))
            if self.tx_watcher_loops[loopkey][0].running:
                self.tx_watcher_loops[loopkey][0].stop()
            if timeoutfun:
                timeoutfun(txd, loopkey)

    @abc.abstractmethod
    def outputs_watcher(self, wallet_name, notifyaddr, tx_output_set,
                        unconfirmfun, confirmfun, timeoutfun):
        """Given a key for the watcher loop (notifyaddr), a wallet name (account),
        a set of outputs, and unconfirm, confirm and timeout callbacks,
        check to see if a transaction matching that output set has appeared in
        the wallet. Call the callbacks and update the watcher loop state.
        End the loop when the confirmation has been seen (no spent monitoring here).
        """

    @abc.abstractmethod
    def tx_watcher(self, txd, unconfirmfun, confirmfun, spentfun, c, n):
        """Called at a polling interval, checks if the given deserialized
        transaction (which must be fully signed) is (a) broadcast, (b) confirmed
        and (c) spent from at index n, and notifies confirmation if number
        of confs = c.
        TODO: Deal with conflicts correctly. Here just abandons monitoring.
        """

    @abc.abstractmethod
    def pushtx(self, txhex):
        """pushes tx to the network, returns False if failed"""

    @abc.abstractmethod
    def query_utxo_set(self, txouts, includeconf=False):
        """
        takes a utxo or a list of utxos
        returns None if they are spend or unconfirmed
        otherwise returns value in satoshis, address and output script
        optionally return the coin age in number of blocks
        """
        # address and output script contain the same information btw

    @abc.abstractmethod
    def estimate_fee_per_kb(self, N):
        '''Use the blockchain interface to 
        get an estimate of the transaction fee per kb
        required for inclusion in the next N blocks.
	'''

    def fee_per_kb_has_been_manually_set(self, N):
        '''if the 'block' target is higher than 144, interpret it
        as manually set fee/Kb.
    '''
        if N > 144:
            return True
        else:
            return False


class ElectrumWalletInterface(BlockchainInterface): #pragma: no cover
    """A pseudo-blockchain interface using the existing 
    Electrum server connection in an Electrum wallet.
    Usage requires calling set_wallet with a valid Electrum
    wallet instance.
    """

    def __init__(self, testnet=False):
        super(ElectrumWalletInterface, self).__init__()
        self.last_sync_unspent = 0

    def set_wallet(self, wallet):
        self.wallet = wallet

    def sync_addresses(self, wallet):
        log.debug("Dummy electrum interface, no sync address")

    def sync_unspent(self, wallet):
        log.debug("Dummy electrum interface, no sync unspent")

    def add_tx_notify(self, txd, unconfirmfun, confirmfun, notifyaddr):
        log.debug("Dummy electrum interface, no add tx notify")

    def outputs_watcher(self, wallet_name, notifyaddr,
                        tx_output_set, uf, cf, tf):
        log.debug("Dummy electrum interface, no outputs watcher")

    def tx_watcher(self, txd, ucf, cf, sf, c, n):
        log.debug("Dummy electrum interface, no tx watcher")

    def pushtx(self, txhex, timeout=10):
        #synchronous send
        from electrum.transaction import Transaction
        etx = Transaction(txhex)
        etx.deserialize()
        tx_hash = etx.hash()
        try:
            retval = self.wallet.network.synchronous_get(
                ('blockchain.transaction.broadcast', [str(etx)]), timeout)
        except:
            log.debug("Failed electrum push")
            return False
        if retval != tx_hash:
            log.debug("Pushtx over Electrum returned wrong value: " + str(
                retval))
            return False
        log.debug("Pushed via Electrum successfully, hash: " + tx_hash)
        return True

    def query_utxo_set(self, txout, includeconf=False):
        """Behaves as for Core; TODO make it faster if possible.
        Note in particular a failed connection should result in
        a result list containing at least one "None" which the
        caller can use as a flag for failure.
	"""
        self.current_height = self.wallet.network.blockchain.local_height
        if not isinstance(txout, list):
            txout = [txout]
        utxos = [[t[:64], int(t[65:])] for t in txout]
        result = []
        for ut in utxos:
            address = self.wallet.network.synchronous_get((
                'blockchain.utxo.get_address', ut))
            try:
                utxo_info = self.wallet.network.synchronous_get((
                    "blockchain.address.listunspent", [address]))
            except Exception as e:
                log.debug("Got exception calling listunspent: " + repr(e))
                raise
            utxo = None
            for u in utxo_info:
                if u['tx_hash'] == ut[0] and u['tx_pos'] == ut[1]:
                    utxo = u
            if utxo is None:
                result.append(None)
                continue
            r = {
                'value': u['value'],
                'address': address,
                'script': btc.address_to_script(address)
            }
            if includeconf:
                if int(u['height']) in [0, -1]:
                    #-1 means unconfirmed inputs
                    r['confirms'] = 0
                else:
                    #+1 because if current height = tx height, that's 1 conf
                    r['confirms'] = int(self.current_height) - int(u['height']) + 1
            result.append(r)
        return result

    def estimate_fee_per_kb(self, N):
        if super(ElectrumWalletInterface, self).fee_per_kb_has_been_manually_set(N):
            # use a floor of 1000 to not run into node relay problems
            return int(max(1000, random.uniform(N * float(0.8), N * float(1.2))))
        fee = self.wallet.network.synchronous_get(('blockchain.estimatefee', [N]
                                                  ))
        log.debug("Got fee: " + str(fee))
        fee_per_kb_sat = int(float(fee) * 100000000)
        return fee_per_kb_sat

class BitcoinCoreInterface(BlockchainInterface):

    def __init__(self, jsonRpc, network):
        super(BitcoinCoreInterface, self).__init__()
        self.jsonRpc = jsonRpc
        self.fast_sync_called = False
        blockchainInfo = self.jsonRpc.call("getblockchaininfo", [])
        actualNet = blockchainInfo['chain']

        netmap = {'main': 'mainnet', 'test': 'testnet', 'regtest': 'regtest'}
        if netmap[actualNet] != network:
            raise Exception('wrong network configured')

        self.txnotify_fun = []
        self.wallet_synced = False
        #task.LoopingCall objects that track transactions, keyed by txids.
        #Format: {"txid": (loop, unconfirmed true/false, confirmed true/false,
        #spent true/false), ..}
        self.tx_watcher_loops = {}

    def get_block(self, blockheight):
        """Returns full serialized block at a given height.
        """
        block_hash = self.rpc('getblockhash', [blockheight])
        block = self.rpc('getblock', [block_hash, False])
        if not block:
            return False
        return block

    def rpc(self, method, args):
        if method not in ['importaddress', 'walletpassphrase', 'getaccount',
                          'gettransaction', 'getrawtransaction', 'gettxout',
                          'importmulti']:
            log.debug('rpc: ' + method + " " + str(args))
        res = self.jsonRpc.call(method, args)
        return res

    def import_addresses(self, addr_list, wallet_name):
        """Imports addresses in a batch during initial sync.
        Refuses to proceed if keys are found to be under control
        of another account/label (see console output), and quits.
        Do NOT use for in-run imports, use rpc('importaddress',..) instead.
        """
        log.debug('importing ' + str(len(addr_list)) +
                  ' addresses with label ' + wallet_name)
        requests = []
        for addr in addr_list:
            requests.append({
                "scriptPubKey": {"address": addr},
                "timestamp": 0,
                "label": wallet_name,
                "watchonly": True
            })

        result = self.rpc('importmulti', [requests, {"rescan": False}])

        num_failed = 0
        for row in result:
            if row['success'] == False:
                num_failed += 1
                # don't try/catch, assume failure always has error message
                log.warn(row['error']['message'])
        if num_failed > 0:
            log.warn("Fatal sync error: import of {} address(es) failed for "
                     "some reason. To prevent coin or privacy loss, "
                     "Joinmarket will not load a wallet in this conflicted "
                     "state. Try using a new Bitcoin Core wallet to sync this "
                     "Joinmarket wallet, or use a new Joinmarket wallet."
                     "".format(num_failed))
            sys.exit(1)

    def add_watchonly_addresses(self, addr_list, wallet_name, restart_cb=None):
        """For backwards compatibility, this fn name is preserved
        as the case where we quit the program if a rescan is required;
        but in some cases a rescan is not required (if the address is known
        to be new/unused). For that case use import_addresses instead.
        """
        self.import_addresses(addr_list, wallet_name)
        if jm_single().config.get("BLOCKCHAIN",
                                  "blockchain_source") != 'regtest': #pragma: no cover
            #Exit conditions cannot be included in tests
            restart_msg = ("restart Bitcoin Core with -rescan if you're "
                           "recovering an existing wallet from backup seed\n"
                           "Otherwise just restart this joinmarket application.")
            if restart_cb:
                restart_cb(restart_msg)
            else:
                jmprint(restart_msg, "important")
                sys.exit(0)

    def sync_wallet(self, wallet, fast=False, restart_cb=None):
        #trigger fast sync if the index_cache is available
        #(and not specifically disabled).
        if fast:
            self.sync_wallet_fast(wallet)
            self.fast_sync_called = True
            return
        super(BitcoinCoreInterface, self).sync_wallet(wallet, restart_cb=restart_cb)
        self.fast_sync_called = False

    def sync_wallet_fast(self, wallet):
        """Exploits the fact that given an index_cache,
        all addresses necessary should be imported, so we
        can just list all used addresses to find the right
        index values.
        """
        self.get_address_usages(wallet)
        self.sync_unspent(wallet)

    def get_address_usages(self, wallet):
        """Use rpc `listaddressgroupings` to locate all used
        addresses in the account (whether spent or unspent outputs).
        This will not result in a full sync if working with a new
        Bitcoin Core instance, in which case "fast" should have been
        specifically disabled by the user.
        """
        wallet_name = self.get_wallet_name(wallet)
        agd = self.rpc('listaddressgroupings', [])
        #flatten all groups into a single list; then, remove duplicates
        fagd = (tuple(item) for sublist in agd for item in sublist)
        #"deduplicated flattened address grouping data" = dfagd
        dfagd = set(fagd)
        used_addresses = set()
        for addr_info in dfagd:
            if len(addr_info) < 3 or addr_info[2] != wallet_name:
                continue
            used_addresses.add(addr_info[0])

        #for a first run, import first chunk
        if not used_addresses:
            log.info("Detected new wallet, performing initial import")
            # delegate inital address import to sync_addresses
            # this should be fast because "getaddressesbyaccount" should return
            # an empty list in this case
            self.sync_addresses(wallet)
            self.wallet_synced = True
            return

        #Wallet has been used; scan forwards.
        log.debug("Fast sync in progress. Got this many used addresses: " + str(
            len(used_addresses)))
        #Need to have wallet.index point to the last used address
        #Algo:
        #    1. Scan batch 1 of each branch, record matched wallet addresses.
        #    2. Check if all addresses in 'used addresses' have been matched, if
        #       so, break.
        #    3. Repeat the above for batch 2, 3.. up to max 20 batches.
        #    4. If after all 20 batches not all used addresses were matched,
        #       quit with error.
        #    5. Calculate used indices.
        #    6. If all used addresses were matched, set wallet index to highest
        #       found index in each branch and mark wallet sync complete.
        #Rationale for this algo:
        #    Retrieving addresses is a non-zero computational load, so batching
        #    and then caching allows a small sync to complete *reasonably*
        #    quickly while a larger one is not really negatively affected.
        #    The downside is another free variable, batch size, but this need
        #    not be exposed to the user; it is not the same as gap limit, in fact,
        #    the concept of gap limit does not apply to this kind of sync, which
        #    *assumes* that the most recent usage of addresses is indeed recorded.
        remaining_used_addresses = used_addresses.copy()
        addresses, saved_indices = self._collect_addresses_init(wallet)
        for addr in addresses:
            remaining_used_addresses.discard(addr)

        BATCH_SIZE = 100
        MAX_ITERATIONS = 20
        current_indices = deepcopy(saved_indices)
        for j in range(MAX_ITERATIONS):
            if not remaining_used_addresses:
                break
            for addr in \
                    self._collect_addresses_gap(wallet, gap_limit=BATCH_SIZE):
                remaining_used_addresses.discard(addr)

            # increase wallet indices for next iteration
            for md in current_indices:
                current_indices[md][0] += BATCH_SIZE
                current_indices[md][1] += BATCH_SIZE
            self._rewind_wallet_indices(wallet, current_indices,
                                        current_indices)
        else:
            self._rewind_wallet_indices(wallet, saved_indices, saved_indices)
            raise Exception("Failed to sync in fast mode after 20 batches; "
                            "please re-try wallet sync without --fast flag.")

        # creating used_indices on-the-fly would be more efficient, but the
        # overall performance gain is probably negligible
        used_indices = self._get_used_indices(wallet, used_addresses)
        self._rewind_wallet_indices(wallet, used_indices, saved_indices)
        self.wallet_synced = True

    def sync_addresses(self, wallet, restart_cb=None):
        log.debug("requesting detailed wallet history")
        wallet_name = self.get_wallet_name(wallet)

        addresses, saved_indices = self._collect_addresses_init(wallet)
        try:
            imported_addresses = set(self.rpc('getaddressesbyaccount',
                [wallet_name]))
        except JsonRpcError:
            if wallet_name in self.rpc('listlabels', []):
                imported_addresses = set(self.rpc('getaddressesbylabel',
                    [wallet_name]).keys())
            else:
                imported_addresses = set()

        if not addresses.issubset(imported_addresses):
            self.add_watchonly_addresses(addresses - imported_addresses,
                                         wallet_name, restart_cb)
            return

        used_addresses_gen = (tx['address']
                              for tx in self._yield_transactions(wallet_name)
                              if tx['category'] == 'receive')

        used_indices = self._get_used_indices(wallet, used_addresses_gen)
        log.debug("got used indices: {}".format(used_indices))
        gap_limit_used = not self._check_gap_indices(wallet, used_indices)
        self._rewind_wallet_indices(wallet, used_indices, saved_indices)

        new_addresses = self._collect_addresses_gap(wallet)
        if not new_addresses.issubset(imported_addresses):
            log.debug("Syncing iteration finished, additional step required")
            self.add_watchonly_addresses(new_addresses - imported_addresses,
                                         wallet_name, restart_cb)
            self.wallet_synced = False
        elif gap_limit_used:
            log.debug("Syncing iteration finished, additional step required")
            self.wallet_synced = False
        else:
            log.debug("Wallet successfully synced")
            self._rewind_wallet_indices(wallet, used_indices, saved_indices)
            self.wallet_synced = True

    @staticmethod
    def _rewind_wallet_indices(wallet, used_indices, saved_indices):
        for md in used_indices:
            for int_type in (0, 1):
                index = max(used_indices[md][int_type],
                            saved_indices[md][int_type])
                wallet.set_next_index(md, int_type, index, force=True)

    @staticmethod
    def _get_used_indices(wallet, addr_gen):
        indices = {x: [0, 0] for x in range(wallet.max_mixdepth + 1)}

        for addr in addr_gen:
            if not wallet.is_known_addr(addr):
                continue
            md, internal, index = wallet.get_details(
                wallet.addr_to_path(addr))
            if internal not in (0, 1):
                assert internal == 'imported'
                continue
            indices[md][internal] = max(indices[md][internal], index + 1)

        return indices

    @staticmethod
    def _check_gap_indices(wallet, used_indices):
        for md in used_indices:
            for internal in (0, 1):
                if used_indices[md][internal] >\
                        max(wallet.get_next_unused_index(md, internal), 0):
                    return False
        return True

    @staticmethod
    def _collect_addresses_init(wallet):
        addresses = set()
        saved_indices = dict()

        for md in range(wallet.max_mixdepth + 1):
            saved_indices[md] = [0, 0]
            for internal in (0, 1):
                next_unused = wallet.get_next_unused_index(md, internal)
                for index in range(next_unused):
                    addresses.add(wallet.get_addr(md, internal, index))
                for index in range(wallet.gap_limit):
                    addresses.add(wallet.get_new_addr(md, internal))
                wallet.set_next_index(md, internal, next_unused)
                saved_indices[md][internal] = next_unused
            for path in wallet.yield_imported_paths(md):
                addresses.add(wallet.get_addr_path(path))

        return addresses, saved_indices

    @staticmethod
    def _collect_addresses_gap(wallet, gap_limit=None):
        gap_limit = gap_limit or wallet.gap_limit
        addresses = set()

        for md in range(wallet.max_mixdepth + 1):
            for internal in (True, False):
                old_next = wallet.get_next_unused_index(md, internal)
                for index in range(gap_limit):
                    addresses.add(wallet.get_new_addr(md, internal))
                wallet.set_next_index(md, internal, old_next)

        return addresses

    def _yield_transactions(self, wallet_name):
        batch_size = 1000
        iteration = 0
        while True:
            new = self.rpc(
                'listtransactions',
                ["*", batch_size, iteration * batch_size, True])
            for tx in new:
                yield tx
            if len(new) < batch_size:
                return
            iteration += 1

    def start_unspent_monitoring(self, wallet):
        self.unspent_monitoring_loop = task.LoopingCall(self.sync_unspent, wallet)
        self.unspent_monitoring_loop.start(1.0)

    def stop_unspent_monitoring(self):
        self.unspent_monitoring_loop.stop()

    def sync_unspent(self, wallet):
        st = time.time()
        wallet_name = self.get_wallet_name(wallet)
        wallet.reset_utxos()

        listunspent_args = []
        if 'listunspent_args' in jm_single().config.options('POLICY'):
            listunspent_args = ast.literal_eval(jm_single().config.get(
                'POLICY', 'listunspent_args'))

        unspent_list = self.rpc('listunspent', listunspent_args)
        for u in unspent_list:
            if not wallet.is_known_addr(u['address']):
                continue
            self._add_unspent_utxo(wallet, u)
        et = time.time()
        log.debug('bitcoind sync_unspent took ' + str((et - st)) + 'sec')
        self.wallet_synced = True

    @staticmethod
    def _add_unspent_utxo(wallet, utxo):
        """
        Add a UTXO as returned by rpc's listunspent call to the wallet.

        params:
            wallet: wallet
            utxo: single utxo dict as returned by listunspent
        """
        txid = binascii.unhexlify(utxo['txid'])
        script = binascii.unhexlify(utxo['scriptPubKey'])
        value = int(Decimal(str(utxo['amount'])) * Decimal('1e8'))

        wallet.add_utxo(txid, int(utxo['vout']), script, value)

    def get_deser_from_gettransaction(self, rpcretval):
        """Get full transaction deserialization from a call
        to `gettransaction`
        """
        if not "hex" in rpcretval:
            log.info("Malformed gettransaction output")
            return None
        #str cast for unicode
        hexval = str(rpcretval["hex"])
        return btc.deserialize(hexval)

    def outputs_watcher(self, wallet_name, notifyaddr, tx_output_set,
                        unconfirmfun, confirmfun, timeoutfun):
        """Given a key for the watcher loop (notifyaddr), a wallet name (label),
        a set of outputs, and unconfirm, confirm and timeout callbacks,
        check to see if a transaction matching that output set has appeared in
        the wallet. Call the callbacks and update the watcher loop state.
        End the loop when the confirmation has been seen (no spent monitoring here).
        """
        wl = self.tx_watcher_loops[notifyaddr]
        txlist = self.rpc("listtransactions", ["*", 100, 0, True])
        for tx in txlist[::-1]:
            #changed syntax in 0.14.0; allow both syntaxes
            try:
                res = self.rpc("gettransaction", [tx["txid"], True])
            except:
                try:
                    res = self.rpc("gettransaction", [tx["txid"], 1])
                except JsonRpcError as e:
                    #This should never happen (gettransaction is a wallet rpc).
                    log.warn("Failed gettransaction call; JsonRpcError")
                    res = None
                except Exception as e:
                    log.warn("Failed gettransaction call; unexpected error:")
                    log.warn(str(e))
                    res = None
            if not res:
                continue
            if "confirmations" not in res:
                log.debug("Malformed gettx result: " + str(res))
                return
            txd = self.get_deser_from_gettransaction(res)
            if txd is None:
                continue
            txos = set([(sv['script'], sv['value']) for sv in txd['outs']])
            if not txos == tx_output_set:
                continue
            #Here we have found a matching transaction in the wallet.
            real_txid = btc.txhash(btc.serialize(txd))
            if not wl[1] and res["confirmations"] == 0:
                log.debug("Tx: " + str(real_txid) + " seen on network.")
                unconfirmfun(txd, real_txid)
                wl[1] = True
                return
            if not wl[2] and res["confirmations"] > 0:
                log.debug("Tx: " + str(real_txid) + " has " + str(
                res["confirmations"]) + " confirmations.")
                confirmfun(txd, real_txid, res["confirmations"])
                wl[2] = True
                wl[0].stop()
                return
            if res["confirmations"] < 0:
                log.debug("Tx: " + str(real_txid) + " has a conflict. Abandoning.")
                wl[0].stop()
                return

    def tx_watcher(self, txd, unconfirmfun, confirmfun, spentfun, c, n):
        """Called at a polling interval, checks if the given deserialized
        transaction (which must be fully signed) is (a) broadcast, (b) confirmed
        and (c) spent from at index n, and notifies confirmation if number
        of confs = c.
        TODO: Deal with conflicts correctly. Here just abandons monitoring.
        """
        txid = btc.txhash(btc.serialize(txd))
        wl = self.tx_watcher_loops[txid]
        try:
            res = self.rpc('gettransaction', [txid, True])
        except JsonRpcError as e:
            return
        if not res:
            return
        if "confirmations" not in res:
            log.debug("Malformed gettx result: " + str(res))
            return
        if not wl[1] and res["confirmations"] == 0:
            log.debug("Tx: " + str(txid) + " seen on network.")
            unconfirmfun(txd, txid)
            wl[1] = True
            return
        if not wl[2] and res["confirmations"] > 0:
            log.debug("Tx: " + str(txid) + " has " + str(
                res["confirmations"]) + " confirmations.")
            confirmfun(txd, txid, res["confirmations"])
            if c <= res["confirmations"]:
                wl[2] = True
                #Note we do not stop the monitoring loop when
                #confirmations occur, since we are also monitoring for spending.
            return
        if res["confirmations"] < 0:
            log.debug("Tx: " + str(txid) + " has a conflict. Abandoning.")
            wl[0].stop()
            return
        if not spentfun or wl[3]:
            return
        #To trigger the spent callback, we check if this utxo outpoint appears in
        #listunspent output with 0 or more confirmations. Note that this requires
        #we have added the destination address to the watch-only wallet, otherwise
        #that outpoint will not be returned by listunspent.
        res2 = self.rpc('listunspent', [0, 999999])
        if not res2:
            return
        txunspent = False
        for r in res2:
            if "txid" not in r:
                continue
            if txid == r["txid"] and n == r["vout"]:
                txunspent = True
                break
        if not txunspent:
            #We need to find the transaction which spent this one;
            #assuming the address was added to the wallet, then this
            #transaction must be in the recent list retrieved via listunspent.
            #For each one, use gettransaction to check its inputs.
            #This is a bit expensive, but should only occur once.
            txlist = self.rpc("listtransactions", ["*", 1000, 0, True])
            for tx in txlist[::-1]:
                #changed syntax in 0.14.0; allow both syntaxes
                try:
                    res = self.rpc("gettransaction", [tx["txid"], True])
                except:
                    try:
                        res = self.rpc("gettransaction", [tx["txid"], 1])
                    except:
                        #This should never happen (gettransaction is a wallet rpc).
                        log.info("Failed any gettransaction call")
                        res = None
                if not res:
                    continue
                deser = self.get_deser_from_gettransaction(res)
                if deser is None:
                    continue
                for vin in deser["ins"]:
                    if not "outpoint" in vin:
                        #coinbases
                        continue
                    if vin["outpoint"]["hash"] == txid and vin["outpoint"]["index"] == n:
                        #recover the deserialized form of the spending transaction.
                        log.info("We found a spending transaction: " + \
                                   btc.txhash(binascii.unhexlify(res["hex"])))
                        res2 = self.rpc("gettransaction", [tx["txid"], True])
                        spending_deser = self.get_deser_from_gettransaction(res2)
                        if not spending_deser:
                            log.info("ERROR: could not deserialize spending tx.")
                            #Should never happen, it's a parsing bug.
                            #No point continuing to monitor, we just hope we
                            #can extract the secret by scanning blocks.
                            wl[3] = True
                            return
                        spentfun(spending_deser, vin["outpoint"]["hash"])
                        wl[3] = True
                        return

    def pushtx(self, txhex):
        try:
            txid = self.rpc('sendrawtransaction', [txhex])
        except JsonRpcConnectionError as e:
            log.debug('error pushing = ' + repr(e))
            return False
        except JsonRpcError as e:
            log.debug('error pushing = ' + str(e.code) + " " + str(e.message))
            return False
        return True

    def query_utxo_set(self, txout, includeconf=False, includeunconf=False):
        """If txout is either (a) a single string in hex encoded txid:n form,
        or a list of the same, returns, as a list for each txout item,
        the result of gettxout from the bitcoind rpc for those utxs;
        if any utxo is invalid, None is returned.
        includeconf: if this is True, the current number of confirmations
        of the prescribed utxo is included in the returned result dict.
        includeunconf: if True, utxos which currently have zero confirmations
        are included in the result set.
        If the utxo is of a non-standard type such that there is no address,
        the address field in the dict is None.
        """
        if not isinstance(txout, list):
            txout = [txout]
        result = []
        for txo in txout:
            if len(txo) < 66:
                result.append(None)
                continue
            try:
                txo_idx = int(txo[65:])
            except ValueError:
                log.warn("Invalid utxo format, ignoring: {}".format(txo))
                result.append(None)
                continue
            ret = self.rpc('gettxout', [txo[:64], txo_idx, includeunconf])
            if ret is None:
                result.append(None)
            else:
                if ret['scriptPubKey'].get('addresses'):
                    address = ret['scriptPubKey']['addresses'][0]
                else:
                    address = None
                result_dict = {'value': int(Decimal(str(ret['value'])) *
                                            Decimal('1e8')),
                               'address': address,
                               'script': ret['scriptPubKey']['hex']}
                if includeconf:
                    result_dict['confirms'] = int(ret['confirmations'])
                result.append(result_dict)
        return result

    def estimate_fee_per_kb(self, N):
        if super(BitcoinCoreInterface, self).fee_per_kb_has_been_manually_set(N):
            # use the local bitcoin core relay fee as floor to avoid relay problems
            btc_relayfee = -1
            rpc_result = self.rpc('getnetworkinfo', None)
            btc_relayfee = rpc_result.get('relayfee', btc_relayfee)
            if btc_relayfee > 0:
                relayfee_in_sat = int(Decimal(1e8) * Decimal(btc_relayfee))
                log.debug("Using this min relay fee as tx fee floor: " + str(relayfee_in_sat))
                return int(max(relayfee_in_sat, random.uniform(N * float(0.8), N * float(1.2))))
            else:   # cannot get valid relayfee: fall back to 1000 sat/kbyte
                log.debug("Using this min relay fee as tx fee floor (fallback): 1000")
                return int(max(1000, random.uniform(N * float(0.8), N * float(1.2))))

        # Special bitcoin core case: sometimes the highest priority
        # cannot be estimated in that case the 2nd highest priority
        # should be used instead of falling back to hardcoded values
        tries = 2 if N == 1 else 1

        estimate = -1
        for i in range(tries):
            rpc_result = self.rpc('estimatesmartfee', [N + i])
            estimate = rpc_result.get('feerate', estimate)
            if estimate > 0:
                break
        else:  # estimate <= 0
            return 10000
        return int(Decimal(1e8) * Decimal(estimate))


# class for regtest chain access
# running on local daemon. Only
# to be instantiated after network is up
# with > 100 blocks.
class RegtestBitcoinCoreInterface(BitcoinCoreInterface): #pragma: no cover

    def __init__(self, jsonRpc):
        super(RegtestBitcoinCoreInterface, self).__init__(jsonRpc, 'regtest')
        self.pushtx_failure_prob = 0
        self.tick_forward_chain_interval = -1
        self.absurd_fees = False
        self.simulating = False
        self.shutdown_signal = False
        self.destn_addr = self.rpc("getnewaddress", [])

    def estimate_fee_per_kb(self, N):
        if not self.absurd_fees:
            return super(RegtestBitcoinCoreInterface,
                         self).estimate_fee_per_kb(N)
        else:
            return jm_single().config.getint("POLICY",
                                             "absurd_fee_per_kb") + 100

    def tickchain(self):
        if self.tick_forward_chain_interval < 0:
            log.debug('not ticking forward chain')
            self.tickchainloop.stop()
            return
        if self.shutdown_signal:
            self.tickchainloop.stop()
            return
        self.tick_forward_chain(1)

    def simulate_blocks(self):
        self.tickchainloop = task.LoopingCall(self.tickchain)
        self.tickchainloop.start(self.tick_forward_chain_interval)
        self.simulating = True

    def pushtx(self, txhex):
        if self.pushtx_failure_prob != 0 and random.random() <\
                self.pushtx_failure_prob:
            log.debug('randomly not broadcasting %0.1f%% of the time' %
                      (self.pushtx_failure_prob * 100))
            return True

        ret = super(RegtestBitcoinCoreInterface, self).pushtx(txhex)
        if not self.simulating and self.tick_forward_chain_interval > 0:
            log.debug('will call tfc after ' + str(self.tick_forward_chain_interval) + ' seconds.')
            reactor.callLater(self.tick_forward_chain_interval,
                              self.tick_forward_chain, 1)
        return ret

    def tick_forward_chain(self, n):
        """
        Special method for regtest only;
        instruct to mine n blocks.
        """
        try:
            self.rpc('generatetoaddress', [n, self.destn_addr])
        except JsonRpcConnectionError:
            #can happen if the blockchain is shut down
            #automatically at the end of tests; this shouldn't
            #trigger an error
            log.debug(
                "Failed to generate blocks, looks like the bitcoin daemon \
	    has been shut down. Ignoring.")

    def grab_coins(self, receiving_addr, amt=50):
        """
        NOTE! amt is passed in Coins, not Satoshis!
        Special method for regtest only:
        take coins from bitcoind's own wallet
        and put them in the receiving addr.
        Return the txid.
        """
        if amt > 500:
            raise Exception("too greedy")
        """
        if amt > self.current_balance:
        #mine enough to get to the reqd amt
        reqd = int(amt - self.current_balance)
        reqd_blocks = int(reqd/50) +1
        if self.rpc('setgenerate', [True, reqd_blocks]):
        raise Exception("Something went wrong")
        """
        # now we do a custom create transaction and push to the receiver
        txid = self.rpc('sendtoaddress', [receiving_addr, amt])
        if not txid:
            raise Exception("Failed to broadcast transaction")
        # confirm
        self.tick_forward_chain(1)
        return txid

    def get_received_by_addr(self, addresses, query_params):
        # NB This will NOT return coinbase coins (but wont matter in our use
        # case). allow importaddress to fail in case the address is already
        # in the wallet
        res = []
        for address in addresses:
            #self.rpc('importaddress', [address, 'watchonly'])
            res.append({'address': address,
                        'balance': int(Decimal(1e8) * self.rpc(
                            'getreceivedbyaddress', [address, 0]))})
        return {'data': res}
