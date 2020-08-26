#! /usr/bin/env python

import collections
import time
import ast
import sys
from decimal import Decimal
from copy import deepcopy
from twisted.internet import reactor
from twisted.internet import task
from twisted.application.service import Service
from numbers import Integral
from jmclient.configure import jm_single, get_log
from jmclient.output import fmt_tx_data
from jmclient.blockchaininterface import (INF_HEIGHT, BitcoinCoreInterface,
    BitcoinCoreNoHistoryInterface)
from jmclient.wallet import FidelityBondMixin
from jmbase.support import jmprint, EXIT_SUCCESS, utxo_to_utxostr, hextobin


"""Wallet service

The purpose of this independent service is to allow
running applications to keep an up to date, asynchronous
view of the current state of its wallet, deferring any
polling mechanisms needed against the backend blockchain
interface here.
"""

jlog = get_log()

class WalletService(Service):
    EXTERNAL_WALLET_LABEL = "joinmarket-notify"

    def __init__(self, wallet):
        # The two principal member variables
        # are the blockchaininterface instance,
        # which is currently global in JM but
        # could be more flexible in future, and
        # the JM wallet object.
        self.bci = jm_single().bc_interface

        # main loop used to check for transactions, instantiated
        # after wallet is synced:
        self.monitor_loop = None
        self.wallet = wallet
        self.synced = False

        # keep track of the quasi-real-time blockheight
        # (updated in main monitor loop)
        self.current_blockheight = None
        if self.bci is not None:
            if not self.update_blockheight():
                # this accounts for the unusual case
                # where the application started up with
                # a functioning blockchain interface, but
                # that bci is now failing when we are starting
                # the wallet service.
                raise Exception("WalletService failed to start "
                                "due to inability to query block height.")
        else:
            jlog.warning("No blockchain source available, " +
                "wallet tools will not show correct balances.")

        # Dicts of registered callbacks, by type
        # and then by txinfo, for events
        # on transactions.
        self.callbacks = {}
        self.callbacks["all"] = []
        self.callbacks["unconfirmed"] = {}
        self.callbacks["confirmed"] = {}

        self.restart_callback = None

        # transactions we are actively monitoring,
        # i.e. they are not new but we want to track:
        self.active_txids = []
        # to ensure transactions are only processed once:
        self.processed_txids = []

        self.set_autofreeze_warning_cb()

    def update_blockheight(self):
        """ Can be called manually (on startup, or for tests)
        but will be called as part of main monitoring
        loop to ensure new transactions are added at
        the right height.
        Any failure of the RPC call must result in this returning
        False, otherwise return True (means self.current_blockheight
        has been correctly updated).
        """

        def critical_error():
            jlog.error("Failure to get blockheight from Bitcoin Core.")
            self.stopService()
            return False

        if self.current_blockheight:
            old_blockheight = self.current_blockheight
        else:
            old_blockheight = -1
        try:
            self.current_blockheight = self.bci.get_current_block_height()
        except Exception as e:
            # This should never happen now, as we are catching every
            # possible Exception in jsonrpc or bci.rpc:
            return critical_error()
        if not self.current_blockheight:
            return critical_error()

        # We have received a new blockheight from Core, sanity check it:
        assert isinstance(self.current_blockheight, Integral)
        assert self.current_blockheight >= 0
        if self.current_blockheight < old_blockheight:
            jlog.warn("Bitcoin Core is reporting a lower blockheight, "
                      "possibly a reorg.")
        return True

    def startService(self):
        """ Encapsulates start up actions.
        Here wallet sync.
        """
        super().startService()
        self.request_sync_wallet()

    def stopService(self):
        """ Encapsulates shut down actions.
        Note that after the service is stopped, it
        should *not* be restarted, instead a new
        WalletService instance should be created.
        """
        if self.monitor_loop:
            self.monitor_loop.stop()
        self.wallet.close()
        super().stopService()

    def isRunning(self):
        if self.running == 1:
            return True
        return False

    def add_restart_callback(self, callback):
        """ Sets the function that will be
        called in the event that the wallet
        sync completes with a restart warning.
        The only argument is a message string,
        which the calling function displays to
        the user before quitting gracefully.
        """
        self.restart_callback = callback

    def request_sync_wallet(self):
        """ Ensures wallet sync is complete
        before the main event loop starts.
        """
        if self.bci is not None:
            d = task.deferLater(reactor, 0.0, self.sync_wallet)
            d.addCallback(self.start_wallet_monitoring)

    def register_callbacks(self, callbacks, txinfo, cb_type="all"):
        """ Register callbacks that will be called by the
        transaction monitor loop, on transactions stored under
        our wallet label (see WalletService.get_wallet_name()).
        Callback arguments are currently (txd, txid) and return
        is boolean, except "confirmed" callbacks which have
        arguments (txd, txid, confirmations).
        Note that callbacks MUST correctly return True if they
        recognized the transaction and processed it, and False
        if not. The True return value will be used to remove
        the callback from the list.
        Arguments:
        `callbacks` - a list of functions with signature as above
        and return type boolean.
        `txinfo` - either a txid expected for the transaction, if
        known, or a tuple of the ordered output set, of the form
        ((CScript, int), ..). This is be constructed from the
        CMutableTransaction vout list.
        See WalletService.transaction_monitor().
        `cb_type` - must be one of "all", "unconfirmed", "confirmed";
        the first type will be called back once for every new
        transaction, the second only once when the number of
        confirmations is 0, and the third only once when the number
        of confirmations is > 0.
        """
        if cb_type == "all":
            # note that in this case, txid is ignored.
            self.callbacks["all"].extend(callbacks)
        elif cb_type in ["unconfirmed", "confirmed"]:
            if txinfo not in self.callbacks[cb_type]:
                self.callbacks[cb_type][txinfo] = []
            self.callbacks[cb_type][txinfo].extend(callbacks)
        else:
            assert False, "Invalid argument: " + cb_type


    def start_wallet_monitoring(self, syncresult):
        """ Once the initialization of the service
        (currently, means: wallet sync) is complete,
        we start the main monitoring jobs of the
        wallet service (currently, means: monitoring
        all new transactions on the blockchain that
        are recognised as belonging to the Bitcoin
        Core wallet with the JM wallet's label).
        """
        if not syncresult:
            jlog.error("Failed to sync the bitcoin wallet. Shutting down.")
            self.stopService()
            if reactor.running:
                reactor.stop()
            return
        jlog.info("Starting transaction monitor in walletservice")
        self.monitor_loop = task.LoopingCall(
            self.transaction_monitor)
        self.monitor_loop.start(5.0)

    def import_non_wallet_address(self, address):
        """ Used for keeping track of transactions which
        have no in-wallet destinations. External wallet
        label is used to avoid breaking fast sync (which
        assumes label => wallet)
        """
        if not self.bci.is_address_imported(address):
            self.bci.import_addresses([address], self.EXTERNAL_WALLET_LABEL,
                                  restart_cb=self.restart_callback)

    def default_autofreeze_warning_cb(self, utxo):
        success, utxostr = utxo_to_utxostr(utxo)
        assert success, "Autofreeze warning cb called with invalid utxo."
        jlog.warning("WARNING: new utxo has been automatically "
             "frozen to prevent forced address reuse: ")
        jlog.warning(utxostr)
        jlog.warning("You can unfreeze this utxo with the method "
                 "'freeze' of wallet-tool.py or the Coins tab "
                 "of Joinmarket-Qt.")

    def set_autofreeze_warning_cb(self, cb=None):
        """ This callback takes a single argument, the
        string representation of a utxo in form txid:index,
        and informs the user that the utxo has been frozen.
        It returns nothing (the user is not deciding in this case,
        as the decision was already taken by the configuration).
        """
        if cb is None:
            self.autofreeze_warning_cb = self.default_autofreeze_warning_cb
        else:
            self.autofreeze_warning_cb = cb

    def check_for_reuse(self, added_utxos):
        """ (a) Check if addresses in new utxos are already in
        used address list, (b) record new addresses as now used
        (c) disable the new utxo if it returned as true for (a),
        and it passes the filter set in the configuration.
        """
        to_be_frozen = set()
        for au in added_utxos:
            if self.has_address_been_used(added_utxos[au]["address"]):
                to_be_frozen.add(au)
        # any utxos actually added must have their destination address
        # added to the used address list for this program run:
        for au in added_utxos.values():
            self.used_addresses.add(au["address"])

        # disable those that passed the first check, before the addition,
        # if they satisfy configured logic
        for utxo in to_be_frozen:
            freeze_threshold = jm_single().config.getint("POLICY",
                                        "max_sats_freeze_reuse")
            if freeze_threshold == -1 or added_utxos[
                utxo]["value"] <= freeze_threshold:
                # freezing of coins must be communicated to user:
                self.autofreeze_warning_cb(utxo)
                self.disable_utxo(*utxo)

    def transaction_monitor(self):
        """Keeps track of any changes in the wallet (new transactions).
        Intended to be run as a twisted task.LoopingCall so that this
        Service is constantly in near-realtime sync with the blockchain.
        """

        if not self.update_blockheight():
            return

        txlist = self.bci.list_transactions(100)
        if not txlist:
            return

        new_txs = []
        for x in txlist:
            # process either (a) a completely new tx or
            # (b) a tx that reached unconf status but we are still
            # waiting for conf (active_txids)
            if "txid" not in x:
                continue
            if x['txid'] in self.active_txids or x['txid'] not in self.old_txs:
                new_txs.append(x)
        # reset for next polling event:
        self.old_txs = [x['txid'] for x in txlist if "txid" in x]

        for tx in new_txs:
            txid = tx["txid"]
            res = self.bci.get_transaction(hextobin(txid))
            if not res:
                continue
            confs = res["confirmations"]
            if not isinstance(confs, Integral):
                jlog.warning("Malformed gettx result: " + str(res))
                continue
            if confs < 0:
                jlog.info(
                    "Transaction: " + txid + " has a conflict, abandoning.")
                continue
            if confs == 0:
                height = None
            else:
                height = self.current_blockheight - confs + 1

            txd = self.bci.get_deser_from_gettransaction(res)
            if txd is None:
                continue
            removed_utxos, added_utxos = self.wallet.process_new_tx(txd, height)
            if txid not in self.processed_txids:
                # apply checks to disable/freeze utxos to reused addrs if needed:
                self.check_for_reuse(added_utxos)
                # TODO note that this log message will be missed if confirmation
                # is absurdly fast, this is considered acceptable compared with
                # additional complexity.
                self.log_new_tx(removed_utxos, added_utxos, txid)
                self.processed_txids.append(txid)

            # first fire 'all' type callbacks, irrespective of if the
            # transaction pertains to anything known (but must
            # have correct label per above); filter on this Joinmarket wallet label,
            # or the external monitoring label:
            if (self.bci.is_address_labeled(tx, self.get_wallet_name()) or
                self.bci.is_address_labeled(tx, self.EXTERNAL_WALLET_LABEL)):
                for f in self.callbacks["all"]:
                    # note we need no return value as we will never
                    # remove these from the list
                    f(txd, txid)

            # The tuple given as the second possible key for the dict
            # is such because txid is not always available
            # at the time of callback registration).
            possible_keys = [txid, tuple((x.scriptPubKey, x.nValue) for x in txd.vout)]

            # note that len(added_utxos) > 0 is not a sufficient condition for
            # the tx being new, since wallet.add_new_utxos will happily re-add
            # a utxo that already exists; but this does not cause re-firing
            # of callbacks since we in these cases delete the callback after being
            # called once.
            # Note also that it's entirely possible that there are only removals,
            # not additions, to the utxo set, specifically in sweeps to external
            # addresses. In this case, since removal can by definition only
            # happen once, we must allow entries in self.active_txids through the
            # filter.
            if len(added_utxos) > 0 or len(removed_utxos) > 0 \
               or txid in self.active_txids:
                if confs == 0:
                    for k in possible_keys:
                        if k in self.callbacks["unconfirmed"]:
                            for f in self.callbacks["unconfirmed"][k]:
                                # True implies success, implies removal:
                                if f(txd, txid):
                                    self.callbacks["unconfirmed"][k].remove(f)
                                    # keep monitoring for conf > 0:
                                    self.active_txids.append(txid)
                elif confs > 0:
                    for k in possible_keys:
                        if k in self.callbacks["confirmed"]:
                            for f in self.callbacks["confirmed"][k]:
                                if f(txd, txid, confs):
                                    self.callbacks["confirmed"][k].remove(f)
                                    if txid in self.active_txids:
                                        self.active_txids.remove(txid)

    def check_callback_called(self, txinfo, callback, cbtype, msg):
        """ Intended to be a deferred Task to be scheduled some
        set time after the callback was registered. "all" type
        callbacks do not expire and are not included.
        If the callback was previously called, return True, otherwise False.
        """
        assert cbtype in ["unconfirmed", "confirmed"]
        if txinfo in self.callbacks[cbtype]:
            if callback in self.callbacks[cbtype][txinfo]:
                # the callback was not called, drop it and warn
                self.callbacks[cbtype][txinfo].remove(callback)
                # TODO - dangling txids in self.active_txids will
                # be caused by this, but could also happen for
                # other reasons; possibly add logic to ensure that
                # this never occurs, although their presence should
                # not cause a functional error.
                jlog.info("Timed out: " + msg)
                return False
            # if callback is not in the list, it was already
            # processed and so do nothing.
        return True

    def log_new_tx(self, removed_utxos, added_utxos, txid):
        """ Changes to the wallet are logged at INFO level by
        the WalletService.
        """
        def report_changed(x, utxos):
            if len(utxos.keys()) > 0:
                jlog.info(x + ' utxos=\n{}'.format('\n'.join(
                    '{} - {}'.format(utxo_to_utxostr(u)[1],
                        fmt_tx_data(tx_data, self)) for u,
                    tx_data in utxos.items())))

        report_changed("Removed", removed_utxos)
        report_changed("Added", added_utxos)


        """ Wallet syncing code
        """

    def sync_wallet(self, fast=True):
        """ Syncs wallet; note that if slow sync
        requires multiple rounds this must be called
        until self.synced is True.
        Before starting the event loop, we cache
        the current most recent transactions as
        reported by the blockchain interface, since
        we are interested in deltas.
        """
        # If this is called when syncing already complete:
        if self.synced:
            return True
        if fast:
            self.sync_wallet_fast()
        else:
            self.sync_addresses()
            self.sync_unspent()
        # Don't attempt updates on transactions that existed
        # before startup
        self.old_txs = [x['txid'] for x in self.bci.list_transactions(100)
            if "txid" in x]
        if isinstance(self.bci, BitcoinCoreNoHistoryInterface):
            self.bci.set_wallet_no_history(self.wallet)
        return self.synced

    def resync_wallet(self, fast=True):
        """ The self.synced state is generally
        updated to True, once, at the start of
        a run of a particular program. Here we
        can manually force re-sync.
        """
        self.synced = False
        self.sync_wallet(fast=fast)

    def sync_wallet_fast(self):
        """Exploits the fact that given an index_cache,
        all addresses necessary should be imported, so we
        can just list all used addresses to find the right
        index values.
        """
        self.sync_addresses_fast()
        self.sync_unspent()

    def has_address_been_used(self, address):
        """ Once wallet has been synced, the set of used
        addresses includes those identified at sync time,
        plus any used during operation. This is stored in
        the WalletService object as self.used_addresses.
        """
        return address in self.used_addresses

    def get_address_usages(self):
        """ sets, at time of sync, the list of addresses that
        have been used in our Core wallet with the specific label
        for our JM wallet. This operation is generally immediate.
        """
        agd = self.bci.rpc('listaddressgroupings', [])
        # flatten all groups into a single list; then, remove duplicates
        fagd = (tuple(item) for sublist in agd for item in sublist)
        # "deduplicated flattened address grouping data" = dfagd
        dfagd = set(fagd)
        used_addresses = set()
        for addr_info in dfagd:
            if len(addr_info) < 3 or addr_info[2] != self.get_wallet_name():
                continue
            used_addresses.add(addr_info[0])
        self.used_addresses = used_addresses

    def sync_addresses_fast(self):
        """Locates all used addresses in the account (whether spent or
        unspent outputs), and then, assuming that all such usages must be
        related to our wallet, calculates the correct wallet indices and
        does any needed imports.

        This will not result in a full sync if working with a new
        Bitcoin Core instance, in which case "recoversync" should have
        been specifically chosen by the user.
        """
        self.get_address_usages()
        # for a first run, import first chunk
        if not self.used_addresses:
            jlog.info("Detected new wallet, performing initial import")
            # delegate inital address import to sync_addresses
            # this should be fast because "getaddressesbyaccount" should return
            # an empty list in this case
            self.sync_addresses()
            self.synced = True
            return

        # Wallet has been used; scan forwards.
        jlog.debug("Fast sync in progress. Got this many used addresses: " + str(
            len(self.used_addresses)))
        # Need to have wallet.index point to the last used address
        # Algo:
        #    1. Scan batch 1 of each branch, record matched wallet addresses.
        #    2. Check if all addresses in 'used addresses' have been matched, if
        #       so, break.
        #    3. Repeat the above for batch 2, 3.. up to max 20 batches.
        #    4. If after all 20 batches not all used addresses were matched,
        #       quit with error.
        #    5. Calculate used indices.
        #    6. If all used addresses were matched, set wallet index to highest
        #       found index in each branch and mark wallet sync complete.
        # Rationale for this algo:
        #    Retrieving addresses is a non-zero computational load, so batching
        #    and then caching allows a small sync to complete *reasonably*
        #    quickly while a larger one is not really negatively affected.
        #    The downside is another free variable, batch size, but this need
        #    not be exposed to the user; it is not the same as gap limit.
        #    The assumption is that usage of addresses occurs only if already
        #    imported, either through in-app usage during coinjoins, or because
        #    deposit by user will be based on wallet_display() which is only
        #    showing imported addresses. Hence the gap-limit import at the end
        #    to ensure this is always true.
        remaining_used_addresses = self.used_addresses.copy()
        addresses, saved_indices = self.collect_addresses_init()
        for addr in addresses:
            remaining_used_addresses.discard(addr)

        BATCH_SIZE = 100
        MAX_ITERATIONS = 20
        current_indices = deepcopy(saved_indices)
        for j in range(MAX_ITERATIONS):
            if not remaining_used_addresses:
                break
            gap_addrs = self.collect_addresses_gap(gap_limit=BATCH_SIZE)
            # note: gap addresses *not* imported here; we are still trying
            # to find the highest-index used address, and assume that imports
            # are up to that index (at least) - see above main rationale.
            for addr in gap_addrs:
                remaining_used_addresses.discard(addr)

            # increase wallet indices for next iteration
            for md in current_indices:
                current_indices[md][0] += BATCH_SIZE
                current_indices[md][1] += BATCH_SIZE
            self.rewind_wallet_indices(current_indices, current_indices)
        else:
            self.rewind_wallet_indices(saved_indices, saved_indices)
            raise Exception("Failed to sync in fast mode after 20 batches; "
                            "please re-try wallet sync with --recoversync flag.")

        # creating used_indices on-the-fly would be more efficient, but the
        # overall performance gain is probably negligible
        used_indices = self.get_used_indices(self.used_addresses)
        self.rewind_wallet_indices(used_indices, saved_indices)
        # at this point we have the correct up to date index at each branch;
        # we ensure that all addresses that will be displayed (see wallet_utils.py,
        # function wallet_display()) are imported by importing gap limit beyond current
        # index:
        self.bci.import_addresses(self.collect_addresses_gap(), self.get_wallet_name(),
                                  self.restart_callback)

        if isinstance(self.wallet, FidelityBondMixin):
            mixdepth = FidelityBondMixin.FIDELITY_BOND_MIXDEPTH
            address_type = FidelityBondMixin.BIP32_BURN_ID

            burner_outputs = self.wallet.get_burner_outputs()
            max_index = 0
            for path_repr in burner_outputs:
                index = self.wallet.path_repr_to_path(path_repr.decode())[-1]
                max_index = max(index+1, max_index)
            self.wallet.set_next_index(mixdepth, address_type, max_index,
                force=True)

        self.synced = True

    def display_rescan_message_and_system_exit(self, restart_cb):
        #TODO using system exit here should be avoided as it makes the code
        # harder to understand and reason about
        #theres also a sys.exit() in BitcoinCoreInterface.import_addresses()
        #perhaps have sys.exit() placed inside the restart_cb that only
        # CLI scripts will use
        if self.bci.__class__ == BitcoinCoreInterface:
            #Exit conditions cannot be included in tests
            restart_msg = ("restart Bitcoin Core with -rescan or use "
                           "`bitcoin-cli rescanblockchain` if you're "
                           "recovering an existing wallet from backup seed\n"
                           "Otherwise just restart this joinmarket application.")
            if restart_cb:
                restart_cb(restart_msg)
            else:
                jmprint(restart_msg, "important")
                sys.exit(EXIT_SUCCESS)

    def sync_burner_outputs(self, burner_txes):
        mixdepth = FidelityBondMixin.FIDELITY_BOND_MIXDEPTH
        address_type = FidelityBondMixin.BIP32_BURN_ID
        self.wallet.set_next_index(mixdepth, address_type, self.wallet.gap_limit,
            force=True)
        highest_used_index = 0
        known_burner_outputs = self.wallet.get_burner_outputs()

        index = -1
        while index - highest_used_index < self.wallet.gap_limit:
            index += 1
            self.wallet.set_next_index(mixdepth, address_type, index, force=True)
            path = self.wallet.get_path(mixdepth, address_type, index)
            path_privkey, engine = self.wallet._get_key_from_path(path)
            path_pubkey = engine.privkey_to_pubkey(path_privkey)
            path_pubkeyhash = btc.bin_hash160(path_pubkey)
            for burner_tx in burner_txes:
                burner_pubkeyhash, gettx = burner_tx
                if burner_pubkeyhash != path_pubkeyhash:
                    continue
                highest_used_index = index
                path_repr = self.wallet.get_path_repr(path)
                if path_repr.encode() in known_burner_outputs:
                    continue
                txid = gettx["txid"]
                jlog.info("Found a burner transaction txid=" + txid + " path = "
                    + path_repr)
                try:
                    merkle_branch = self.bci.get_tx_merkle_branch(txid, gettx["blockhash"])
                except ValueError as e:
                    jlog.warning(repr(e))
                    jlog.warning("Merkle branch likely not available, use "
                        + "wallet-tool `addtxoutproof`")
                    merkle_branch = None
                block_height = self.bci.rpc("getblockheader", [gettx["blockhash"]])["height"]
                if merkle_branch:
                    assert self.bci.verify_tx_merkle_branch(txid, block_height, merkle_branch)
                self.wallet.add_burner_output(path_repr, gettx["hex"], block_height,
                    merkle_branch, gettx["blockindex"])

        self.wallet.set_next_index(mixdepth, address_type, highest_used_index + 1)

    def sync_addresses(self):
        """ Triggered by use of --recoversync option in scripts,
        attempts a full scan of the blockchain without assuming
        anything about past usages of addresses (does not use
        wallet.index_cache as hint).
        """
        jlog.debug("requesting detailed wallet history")
        wallet_name = self.get_wallet_name()
        addresses, saved_indices = self.collect_addresses_init()

        import_needed = self.bci.import_addresses_if_needed(addresses,
            wallet_name)
        if import_needed:
            self.display_rescan_message_and_system_exit(self.restart_callback)
            return

        if isinstance(self.wallet, FidelityBondMixin):
            tx_receive = []
            burner_txes = []
            for tx in self.bci._yield_transactions(wallet_name):
                if tx['category'] == 'receive':
                    tx_receive.append(tx)
                elif tx["category"] == "send":
                    gettx = self.bci.get_transaction(tx["txid"])
                    txd = self.bci.get_deser_from_gettransaction(gettx)
                    if len(txd["outs"]) > 1:
                        continue
                    #must be mined into a block to sync
                    #otherwise there's no merkleproof or block index
                    if gettx["confirmations"] < 1:
                        continue
                    script = binascii.unhexlify(txd["outs"][0]["script"])
                    if script[0] != 0x6a: #OP_RETURN
                        continue
                    pubkeyhash = script[2:]
                    burner_txes.append((pubkeyhash, gettx))

            self.sync_burner_outputs(burner_txes)
            used_addresses_gen = (tx["address"] for tx in tx_receive)
        else:
            #not fidelity bond wallet, significantly faster sync
            used_addresses_gen = (tx['address']
                                  for tx in self.bci._yield_transactions(wallet_name)
                                  if tx['category'] == 'receive')

        used_indices = self.get_used_indices(used_addresses_gen)
        jlog.debug("got used indices: {}".format(used_indices))
        gap_limit_used = not self.check_gap_indices(used_indices)
        self.rewind_wallet_indices(used_indices, saved_indices)

        new_addresses = self.collect_addresses_gap()
        if self.bci.import_addresses_if_needed(new_addresses, wallet_name):
            jlog.debug("Syncing iteration finished, additional step required (more address import required)")
            self.synced = False
            self.display_rescan_message_and_system_exit(self.restart_callback)
        elif gap_limit_used:
            jlog.debug("Syncing iteration finished, additional step required (gap limit used)")
            self.synced = False
        else:
            jlog.debug("Wallet successfully synced")
            self.rewind_wallet_indices(used_indices, saved_indices)
            self.synced = True

    def sync_unspent(self):
        st = time.time()
        # block height needs to be real time for addition to our utxos:
        current_blockheight = self.bci.get_current_block_height()
        wallet_name = self.get_wallet_name()
        self.reset_utxos()

        listunspent_args = []
        if 'listunspent_args' in jm_single().config.options('POLICY'):
            listunspent_args = ast.literal_eval(jm_single().config.get(
                'POLICY', 'listunspent_args'))

        unspent_list = self.bci.rpc('listunspent', listunspent_args)
        # filter on label, but note (a) in certain circumstances (in-
        # wallet transfer) it is possible for the utxo to be labeled
        # with the external label, and (b) the wallet will know if it
        # belongs or not anyway (is_known_addr):
        our_unspent_list = [x for x in unspent_list if (
            self.bci.is_address_labeled(x, wallet_name) or
            self.bci.is_address_labeled(x, self.EXTERNAL_WALLET_LABEL))]
        for utxo in our_unspent_list:
            if not self.is_known_addr(utxo['address']):
                continue
            # The result of bitcoin core's listunspent RPC call does not have
            # a "height" field, only "confirmations".
            # But the result of scantxoutset used in no-history sync does
            # have "height".
            if "height" in utxo:
                height = utxo["height"]
            else:
                height = None
                # wallet's utxo database needs to store an absolute rather
                # than relative height measure:
                confs = int(utxo['confirmations'])
                if confs < 0:
                    jlog.warning("Utxo not added, has a conflict: " + str(utxo))
                    continue
                if confs >= 1:
                    height = current_blockheight - confs + 1
            self._add_unspent_txo(utxo, height)
        et = time.time()
        jlog.debug('bitcoind sync_unspent took ' + str((et - st)) + 'sec')

    def _add_unspent_txo(self, utxo, height):
        """
        Add a UTXO as returned by rpc's listunspent call to the wallet.
        Note that these are returned as little endian outpoint txids, so
        are converted.
        params:
            utxo: single utxo dict as returned by listunspent
            current_blockheight: blockheight as integer, used to
            set the block in which a confirmed utxo is included.
        """
        txid = hextobin(utxo['txid'])
        script = hextobin(utxo['scriptPubKey'])
        value = int(Decimal(str(utxo['amount'])) * Decimal('1e8'))
        self.add_utxo(txid, int(utxo['vout']), script, value, height)


    """ The following functions mostly are not pure
    pass through to the underlying wallet, so declared
    here; the remainder are covered by the __getattr__
    fallback.
    """

    def save_wallet(self):
        self.wallet.save()

    def get_utxos_by_mixdepth(self, include_disabled=False,
                              verbose=False, includeconfs=False):
        """ Returns utxos by mixdepth in a dict, optionally including
        information about how many confirmations each utxo has.
        """
        def height_to_confs(x):
            # convert height entries to confirmations:
            ubym_conv = collections.defaultdict(dict)
            for m, i in x.items():
                for u, d in i.items():
                    ubym_conv[m][u] = d
                    h = ubym_conv[m][u].pop("height")
                    if h == INF_HEIGHT:
                        confs = 0
                    else:
                        confs = self.current_blockheight - h + 1
                    ubym_conv[m][u]["confs"] = confs
            return ubym_conv
        ubym = self.wallet.get_utxos_by_mixdepth(
            include_disabled=include_disabled, includeheight=includeconfs)
        if not includeconfs:
            return ubym
        else:
            return height_to_confs(ubym)

    def minconfs_to_maxheight(self, minconfs):
        if minconfs is None:
            return None
        else:
            return self.current_blockheight - minconfs + 1

    def select_utxos(self, mixdepth, amount, utxo_filter=None, select_fn=None,
                     minconfs=None, includeaddr=False):
        """ Request utxos from the wallet in a particular mixdepth to satisfy
        a certain total amount, optionally set the selector function (or use
        the currently configured function set by the wallet, and optionally
        require a minimum of minconfs confirmations (default none means
        unconfirmed are allowed).
        """
        return self.wallet.select_utxos(mixdepth, amount, utxo_filter=utxo_filter,
                select_fn=select_fn, maxheight=self.minconfs_to_maxheight(minconfs),
                includeaddr=includeaddr)

    def get_balance_by_mixdepth(self, verbose=True,
                                include_disabled=False,
                                minconfs=None):
        if minconfs is None:
            maxheight = None
        else:
            maxheight = self.current_blockheight - minconfs + 1
        return self.wallet.get_balance_by_mixdepth(verbose=verbose,
                                                   include_disabled=include_disabled,
                                                   maxheight=maxheight)

    def get_internal_addr(self, mixdepth):
        if self.bci is not None and hasattr(self.bci, 'import_addresses'):
            addr = self.wallet.get_internal_addr(mixdepth)
            self.bci.import_addresses([addr],
                                      self.wallet.get_wallet_name())
        return addr

    def collect_addresses_init(self):
        """ Collects the "current" set of addresses,
        as defined by the indices recorded in the wallet's
        index cache (persisted in the wallet file usually).
        Note that it collects up to the current indices plus
        the gap limit.
        """
        addresses = set()
        saved_indices = dict()

        for md in range(self.max_mixdepth + 1):
            saved_indices[md] = [0, 0]
            for address_type in (0, 1):
                next_unused = self.get_next_unused_index(md, address_type)
                for index in range(next_unused):
                    addresses.add(self.get_addr(md, address_type, index))
                for index in range(self.gap_limit):
                    addresses.add(self.get_new_addr(md, address_type))
                # reset the indices to the value we had before the
                # new address calls:
                self.set_next_index(md, address_type, next_unused)
                saved_indices[md][address_type] = next_unused
            # include any imported addresses
            for path in self.yield_imported_paths(md):
                addresses.add(self.get_address_from_path(path))

        if isinstance(self.wallet, FidelityBondMixin):
            md = FidelityBondMixin.FIDELITY_BOND_MIXDEPTH
            address_type = FidelityBondMixin.BIP32_TIMELOCK_ID
            saved_indices[md] += [0]
            next_unused = self.get_next_unused_index(md, address_type)
            for index in range(next_unused):
                for timenumber in range(FidelityBondMixin.TIMENUMBERS_PER_PUBKEY):
                    addresses.add(self.get_addr(md, address_type, index, timenumber))
            for index in range(self.gap_limit // FidelityBondMixin.TIMELOCK_GAP_LIMIT_REDUCTION_FACTOR):
                index += next_unused
                assert self.wallet.get_index_cache_and_increment(md, address_type) == index
                for timenumber in range(FidelityBondMixin.TIMENUMBERS_PER_PUBKEY):
                    self.wallet.get_script_and_update_map(md, address_type, index, timenumber)
                    addresses.add(self.get_addr(md, address_type, index, timenumber))
            self.wallet.set_next_index(md, address_type, next_unused)

        return addresses, saved_indices

    def collect_addresses_gap(self, gap_limit=None):
        gap_limit = gap_limit or self.gap_limit
        addresses = set()

        for md in range(self.max_mixdepth + 1):
            for address_type in (1, 0):
                old_next = self.get_next_unused_index(md, address_type)
                for index in range(gap_limit):
                    addresses.add(self.get_new_addr(md, address_type))
                self.set_next_index(md, address_type, old_next)

        if isinstance(self.wallet, FidelityBondMixin):
            md = FidelityBondMixin.FIDELITY_BOND_MIXDEPTH
            address_type = FidelityBondMixin.BIP32_TIMELOCK_ID
            old_next = self.get_next_unused_index(md, address_type)
            for ii in range(gap_limit // FidelityBondMixin.TIMELOCK_GAP_LIMIT_REDUCTION_FACTOR):
                index = self.wallet.get_index_cache_and_increment(md, address_type)
                for timenumber in range(FidelityBondMixin.TIMENUMBERS_PER_PUBKEY):
                    self.wallet.get_script_and_update_map(md, address_type, index, timenumber)
                    addresses.add(self.get_addr(md, address_type, index, timenumber))
            self.set_next_index(md, address_type, old_next)

        return addresses

    def get_external_addr(self, mixdepth):
        if self.bci is not None and hasattr(self.bci, 'import_addresses'):
            addr = self.wallet.get_external_addr(mixdepth)
            self.bci.import_addresses([addr],
                                      self.wallet.get_wallet_name())
        return addr

    def __getattr__(self, attr):
        # any method not present here is passed
        # to the wallet:
        return getattr(self.wallet, attr)
