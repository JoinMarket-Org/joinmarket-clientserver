from __future__ import print_function

import BaseHTTPServer
import abc
import ast
import json
import os
import pprint
import random
import re
import sys
import time
import traceback
from decimal import Decimal
from twisted.internet import reactor, task

import btc

from jmclient.jsonrpc import JsonRpcConnectionError, JsonRpcError
from jmclient.configure import get_p2pk_vbyte, jm_single
from jmbase.support import get_log, chunks

log = get_log()

def is_index_ahead_of_cache(wallet, mix_depth, forchange):
    if mix_depth >= len(wallet.index_cache):
        return True
    return wallet.index[mix_depth][forchange] >= wallet.index_cache[mix_depth][
        forchange]

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

    def sync_wallet(self, wallet):
        self.sync_addresses(wallet)
        self.sync_unspent(wallet)

    @abc.abstractmethod
    def sync_addresses(self, wallet):
        """Finds which addresses have been used and sets
        wallet.index appropriately"""

    @abc.abstractmethod
    def sync_unspent(self, wallet):
        """Finds the unspent transaction outputs belonging to this wallet,
        sets wallet.unspent """

    @abc.abstractmethod
    def add_tx_notify(self,
                      txd,
                      unconfirmfun,
                      confirmfun,
                      notifyaddr,
                      timeoutfun=None,
                      vb=None):
        """
        Invokes unconfirmfun and confirmfun when tx is seen on the network
        If timeoutfun not None, called with boolean argument that tells
            whether this is the timeout for unconfirmed or confirmed
            timeout for uncontirmed = False
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
            return N
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

    @staticmethod
    def get_wallet_name(wallet):
        return 'joinmarket-wallet-' + btc.dbl_sha256(wallet.keys[0][0])[:6]

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
                          'gettransaction', 'getrawtransaction', 'gettxout']:
            log.debug('rpc: ' + method + " " + str(args))
        res = self.jsonRpc.call(method, args)
        if isinstance(res, unicode):
            res = str(res)
        return res

    def import_addresses(self, addr_list, wallet_name):
        log.debug('importing ' + str(len(addr_list)) +
                  ' addresses into account ' + wallet_name)
        for addr in addr_list:
            self.rpc('importaddress', [addr, wallet_name, False])

    def add_watchonly_addresses(self, addr_list, wallet_name):
        """For backwards compatibility, this fn name is preserved
        as the case where we quit the program if a rescan is required;
        but in some cases a rescan is not required (if the address is known
        to be new/unused). For that case use import_addresses instead.
        """
        self.import_addresses(addr_list, wallet_name)
        if jm_single().config.get("BLOCKCHAIN",
                                  "blockchain_source") != 'regtest': #pragma: no cover
            #Exit conditions cannot be included in tests
            print('restart Bitcoin Core with -rescan if you\'re '
                  'recovering an existing wallet from backup seed')
            print(' otherwise just restart this joinmarket script')
            sys.exit(0)

    def sync_wallet(self, wallet, fast=False):
        #trigger fast sync if the index_cache is available
        #(and not specifically disabled).
        if fast:
            self.sync_wallet_fast(wallet)
            self.fast_sync_called = True
            return
        super(BitcoinCoreInterface, self).sync_wallet(wallet)
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
        from jmclient.wallet import BitcoinCoreWallet
        if isinstance(wallet, BitcoinCoreWallet):
            return
        wallet_name = self.get_wallet_name(wallet)
        agd = self.rpc('listaddressgroupings', [])
        #flatten all groups into a single list; then, remove duplicates
        fagd = [tuple(item) for sublist in agd for item in sublist]
        #"deduplicated flattened address grouping data" = dfagd
        dfagd = list(set(fagd))
        #for lookup, want dict of form {"address": amount}
        used_address_dict = {}
        for addr_info in dfagd:
            if len(addr_info) < 3 or addr_info[2] != wallet_name:
                continue
            used_address_dict[addr_info[0]] = (addr_info[1], addr_info[2])

        log.debug("Fast sync in progress. Got this many used addresses: " + str(
            len(used_address_dict)))
        #Need to have wallet.index point to the last used address
        #and fill addr_cache.
        #Algo:
        #    1. Scan batch 1 of each branch, accumulate wallet addresses into dict.
        #    2. Find matches between that dict and used addresses, add those to
        #        used_indices dict and add to address cache.
        #    3. Check if all addresses in 'used addresses' have been matched, if
        #       so, break.
        #    4. Repeat the above for batch 2, 3.. up to max 20 batches.
        #    5. If after all 20 batches not all used addresses were matched,
        #       quit with error.
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
        used_indices = {}
        local_addr_cache = {}
        found_addresses = []
        BATCH_SIZE = 100
        for j in range(20):
            for md in range(wallet.max_mix_depth):
                if md not in used_indices:
                    used_indices[md] = {}
                for fc in [0, 1]:
                    if fc not in used_indices[md]:
                        used_indices[md][fc] = []
                    for i in range(j*BATCH_SIZE, (j+1)*BATCH_SIZE):
                        local_addr_cache[(md, fc, i)] = wallet.get_addr(md, fc, i)
            batch_found_addresses = [x for x in local_addr_cache.iteritems(
                ) if x[1] in used_address_dict.keys()]
            for x in batch_found_addresses:
                md, fc, i = x[0]
                addr = x[1]
                used_indices[md][fc].append(i)
                wallet.addr_cache[addr] = (md, fc, i)
            found_addresses.extend(batch_found_addresses)
            if len(found_addresses) == len(used_address_dict.keys()):
                break
        if j == 19:
            raise Exception("Failed to sync in fast mode after 20 batches; "
                            "please re-try wallet sync without --fast flag.")
        #Find the highest index in each branch and set the wallet index
        for md in range(wallet.max_mix_depth):
            for fc in [0, 1]:
                if len(used_indices[md][fc]):
                    used_indices[md][fc].sort()
                    wallet.index[md][fc] = used_indices[md][fc][-1] + 1
                else:
                    wallet.index[md][fc] = 0
                if not is_index_ahead_of_cache(wallet, md, fc):
                    wallet.index[md][fc] = wallet.index_cache[md][fc]
        self.wallet_synced = True


    def sync_addresses(self, wallet):
        from jmclient.wallet import BitcoinCoreWallet

        if isinstance(wallet, BitcoinCoreWallet):
            return
        log.debug('requesting detailed wallet history')
        wallet_name = self.get_wallet_name(wallet)
        #TODO It is worth considering making this user configurable:
        addr_req_count = 20
        wallet_addr_list = []
        for mix_depth in range(wallet.max_mix_depth):
            for forchange in [0, 1]:
                #If we have an index-cache available, we can use it
                #to decide how much to import (note that this list
                #*always* starts from index 0 on each branch).
                #In cases where the Bitcoin Core instance is fresh,
                #this will allow the entire import+rescan to occur
                #in 2 steps only.
                if wallet.index_cache != [[0, 0]] * wallet.max_mix_depth:
                    #Need to request N*addr_req_count where N is least s.t.
                    #N*addr_req_count > index_cache val. This is so that the batching
                    #process in the main loop *always* has already imported enough
                    #addresses to complete.
                    req_count = int(wallet.index_cache[mix_depth][forchange] /
                                    addr_req_count) + 1
                    req_count *= addr_req_count
                else:
                    #If we have *nothing* - no index_cache, and no info
                    #in Core wallet (imports), we revert to a batching mode
                    #with a default size.
                    #In this scenario it could require several restarts *and*
                    #rescans; perhaps user should set addr_req_count high
                    #(see above TODO)
                    req_count = addr_req_count
                wallet_addr_list += [wallet.get_new_addr(mix_depth, forchange)
                                     for _ in range(req_count)]
                #Indices are reset here so that the next algorithm step starts
                #from the beginning of each branch
                wallet.index[mix_depth][forchange] = 0
        # makes more sense to add these in an account called "joinmarket-imported" but its much
        # simpler to add to the same account here
        for privkey_list in wallet.imported_privkeys.values():
            for privkey in privkey_list:
                imported_addr = btc.privtoaddr(privkey,
                                               magicbyte=get_p2pk_vbyte())
                wallet_addr_list.append(imported_addr)
        imported_addr_list = self.rpc('getaddressesbyaccount', [wallet_name])
        if not set(wallet_addr_list).issubset(set(imported_addr_list)):
            self.add_watchonly_addresses(wallet_addr_list, wallet_name)
            return

        buf = self.rpc('listtransactions', [wallet_name, 1000, 0, True])
        txs = buf
        # If the buffer's full, check for more, until it ain't
        while len(buf) == 1000:
            buf = self.rpc('listtransactions', [wallet_name, 1000, len(txs),
                                                True])
            txs += buf
        # TODO check whether used_addr_list can be a set, may be faster (if
        # its a hashset) and allows using issubset() here and setdiff() for
        # finding which addresses need importing

        # TODO also check the fastest way to build up python lists, i suspect
        #  using += is slow
        used_addr_list = [tx['address']
                          for tx in txs if tx['category'] == 'receive']
        too_few_addr_mix_change = []
        for mix_depth in range(wallet.max_mix_depth):
            for forchange in [0, 1]:
                unused_addr_count = 0
                last_used_addr = ''
                breakloop = False
                while not breakloop:
                    if unused_addr_count >= wallet.gaplimit and \
                            is_index_ahead_of_cache(wallet, mix_depth,
                                                    forchange):
                        break
                    mix_change_addrs = [
                        wallet.get_new_addr(mix_depth, forchange)
                        for _ in range(addr_req_count)
                    ]
                    for mc_addr in mix_change_addrs:
                        if mc_addr not in imported_addr_list:
                            too_few_addr_mix_change.append((mix_depth, forchange
                                                           ))
                            breakloop = True
                            break
                        if mc_addr in used_addr_list:
                            last_used_addr = mc_addr
                            unused_addr_count = 0
                        else:
                            unused_addr_count += 1
#index setting here depends on whether we broke out of the loop
#early; if we did, it means we need to prepare the index
#at the level of the last used address or zero so as to not
#miss any imports in add_watchonly_addresses.
#If we didn't, we need to respect the index_cache to avoid
#potential address reuse.
                if breakloop:
                    if last_used_addr == '':
                        wallet.index[mix_depth][forchange] = 0
                    else:
                        wallet.index[mix_depth][forchange] = \
                            wallet.addr_cache[last_used_addr][2] + 1
                else:
                    if last_used_addr == '':
                        next_avail_idx = max([wallet.index_cache[mix_depth][
                            forchange], 0])
                    else:
                        next_avail_idx = max([wallet.addr_cache[last_used_addr][
                            2] + 1, wallet.index_cache[mix_depth][forchange]])
                    wallet.index[mix_depth][forchange] = next_avail_idx

        wallet_addr_list = []
        if len(too_few_addr_mix_change) > 0:
            indices = [wallet.index[mc[0]][mc[1]]
                       for mc in too_few_addr_mix_change]
            log.debug('too few addresses in ' + str(too_few_addr_mix_change) +
                      ' at ' + str(indices))
            for mix_depth, forchange in too_few_addr_mix_change:
                wallet_addr_list += [
                    wallet.get_new_addr(mix_depth, forchange)
                    for _ in range(addr_req_count * 3)
                ]

            self.add_watchonly_addresses(wallet_addr_list, wallet_name)
            return

        self.wallet_synced = True

    def start_unspent_monitoring(self, wallet):
        self.unspent_monitoring_loop = task.LoopingCall(self.sync_unspent, wallet)
        self.unspent_monitoring_loop.start(1.0)

    def stop_unspent_monitoring(self):
        self.unspent_monitoring_loop.stop()

    def sync_unspent(self, wallet):
        from jmclient.wallet import BitcoinCoreWallet

        if isinstance(wallet, BitcoinCoreWallet):
            return
        st = time.time()
        wallet_name = self.get_wallet_name(wallet)
        wallet.unspent = {}

        listunspent_args = []
        if 'listunspent_args' in jm_single().config.options('POLICY'):
            listunspent_args = ast.literal_eval(jm_single().config.get(
                'POLICY', 'listunspent_args'))

        unspent_list = self.rpc('listunspent', listunspent_args)
        for u in unspent_list:
            if 'account' not in u:
                continue
            if u['account'] != wallet_name:
                continue
            if u['address'] not in wallet.addr_cache:
                continue
            wallet.unspent[u['txid'] + ':' + str(u['vout'])] = {
                'address': u['address'],
                'value': int(Decimal(str(u['amount'])) * Decimal('1e8'))
            }
        et = time.time()
        log.debug('bitcoind sync_unspent took ' + str((et - st)) + 'sec')

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
        one_addr_imported = False
        for outs in txd['outs']:
            addr = btc.script_to_address(outs['script'], vb)
            if self.rpc('getaccount', [addr]) != '':
                one_addr_imported = True
                break
        if not one_addr_imported:
            self.rpc('importaddress', [notifyaddr, 'joinmarket-notify', False])

        #Warning! In case of txid_flag false, this is *not* a valid txid,
        #but only a hash of an incomplete transaction serialization; but,
        #it still suffices as a unique key for tracking, in this case.
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
        #TODO Hardcoded very long timeout interval
        reactor.callLater(7200, self.tx_timeout, txd, loopkey, timeoutfun)

    def tx_timeout(self, txd, loopkey, timeoutfun):
        #TODO: 'loopkey' is an address not a txid for Makers, handle that.
        if not timeoutfun:
            return
        if not txid in self.tx_watcher_loops:
            return
        if not self.tx_watcher_loops[loopkey][1]:
            #Not confirmed after 2 hours; give up
            log.info("Timed out waiting for confirmation of: " + str(loopkey))
            self.tx_watcher_loops[loopkey][0].stop()
            timeoutfun(txd, loopkey)

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
        """Given a key for the watcher loop (notifyaddr), a wallet name (account),
        a set of outputs, and unconfirm, confirm and timeout callbacks,
        check to see if a transaction matching that output set has appeared in
        the wallet. Call the callbacks and update the watcher loop state.
        End the loop when the confirmation has been seen (no spent monitoring here).
        """
        wl = self.tx_watcher_loops[notifyaddr]
        account_name = wallet_name if wallet_name else "*"
        txlist = self.rpc("listtransactions", [wallet_name, 100, 0, True])
        for tx in txlist[::-1]:
            #changed syntax in 0.14.0; allow both syntaxes
            try:
                res = self.rpc("gettransaction", [tx["txid"], True])
            except:
                try:
                    res = self.rpc("gettransaction", [tx["txid"], 1])
                except JsonRpcError as e:
                    #This should never happen (gettransaction is a wallet rpc).
                    log.info("Failed any gettransaction call")
                    res = None
                except Exception as e:
                    log.info(str(e))
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

    def query_utxo_set(self, txout, includeconf=False):
        if not isinstance(txout, list):
            txout = [txout]
        result = []
        for txo in txout:
            ret = self.rpc('gettxout', [txo[:64], int(txo[65:]), False])
            if ret is None:
                result.append(None)
            else:
                result_dict = {'value': int(Decimal(str(ret['value'])) *
                                            Decimal('1e8')),
                               'address': ret['scriptPubKey']['addresses'][0],
                               'script': ret['scriptPubKey']['hex']}
                if includeconf:
                    result_dict['confirms'] = int(ret['confirmations'])
                result.append(result_dict)
        return result

    def estimate_fee_per_kb(self, N):
        if super(BitcoinCoreInterface, self).fee_per_kb_has_been_manually_set(N):
            return N
        estimate = int(Decimal(1e8) * Decimal(self.rpc('estimatefee', [N])))
        if (N == 1) and (estimate < 0):
            # Special bitcoin core case: sometimes the highest priority
            # cannot be estimated in that case the 2nd highest priority
            # should be used instead of falling back to hardcoded values
            estimate = Decimal(1e8) * Decimal(self.rpc('estimatefee', [N+1]))
        if estimate < 0:
            # This occurs when Core has insufficient data to estimate.
            return 100000
        else:
            return estimate

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
            print('will call tfc after ' + str(self.tick_forward_chain_interval) + ' seconds.')
            reactor.callLater(self.tick_forward_chain_interval,
                              self.tick_forward_chain, 1)
        return ret

    def tick_forward_chain(self, n):
        """
        Special method for regtest only;
        instruct to mine n blocks.
        """
        try:
            self.rpc('generate', [n])
        except JsonRpcConnectionError:
            #can happen if the blockchain is shut down
            #automatically at the end of tests; this shouldn't
            #trigger an error
            log.debug(
                "Failed to generate blocks, looks like the bitcoin daemon \
	    has been shut down. Ignoring.")
            pass

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
            self.rpc('importaddress', [address, 'watchonly'])
            res.append({'address': address,
                        'balance': int(round(Decimal(1e8) * Decimal(self.rpc(
                            'getreceivedbyaddress', [address]))))})
        return {'data': res}
