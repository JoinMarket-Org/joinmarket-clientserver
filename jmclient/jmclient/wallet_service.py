#! /usr/bin/env python
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

import collections
import time
import ast
import binascii
from decimal import Decimal
from copy import deepcopy
from twisted.internet import reactor
from twisted.internet import task
from twisted.application.service import Service
from numbers import Integral
from jmclient.configure import jm_single, get_log
from jmclient.output import fmt_tx_data
from jmclient.jsonrpc import JsonRpcError
from jmclient.blockchaininterface import INF_HEIGHT
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
        # keep track of the quasi-real-time blockheight
        # (updated in main monitor loop)
        self.update_blockheight()
        self.wallet = wallet
        self.synced = False

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
        # to ensure transactions are only logged once:
        self.logged_txids = []

    def update_blockheight(self):
        """ Can be called manually (on startup, or for tests)
        but will be called as part of main monitoring
        loop to ensure new transactions are added at
        the right height.
        """
        try:
            self.current_blockheight = self.bci.rpc("getblockcount", [])
            assert isinstance(self.current_blockheight, Integral)
        except Exception as e:
            jlog.error("Failure to get blockheight from Bitcoin Core:")
            jlog.error(repr(e))
            return

    def startService(self):
        """ Encapsulates start up actions.
        Here wallet sync.
        """
        super(WalletService, self).startService()
        self.request_sync_wallet()

    def stopService(self):
        """ Encapsulates shut down actions.
        Here shut down main tx monitoring loop.
        """
        self.monitor_loop.stop()
        super(WalletService, self).stopService()

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
        (('script': script), ('value': value), ..). This can be
        constructed from jmbitcoin.deserialize output, key "outs",
        using tuple(). See WalletService.transaction_monitor().
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

    def transaction_monitor(self):
        """Keeps track of any changes in the wallet (new transactions).
        Intended to be run as a twisted task.LoopingCall so that this
        Service is constantly in near-realtime sync with the blockchain.
        """

        self.update_blockheight()

        txlist = self.bci.list_transactions(100)
        new_txs = []
        for x in txlist:
            # process either (a) a completely new tx or
            # (b) a tx that reached unconf status but we are still
            # waiting for conf (active_txids)
            if x['txid'] in self.active_txids or x['txid'] not in self.old_txs:
                new_txs.append(x)
        # reset for next polling event:
        self.old_txs = [x['txid'] for x in txlist]

        for tx in new_txs:
            txid = tx["txid"]
            res = self.bci.get_transaction(txid)
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
            removed_utxos, added_utxos = self.wallet.process_new_tx(txd, txid, height)
            # TODO note that this log message will be missed if confirmation
            # is absurdly fast, this is considered acceptable compared with
            # additional complexity.
            if txid not in self.logged_txids:
                self.log_new_tx(removed_utxos, added_utxos, txid)
                self.logged_txids.append(txid)

            # first fire 'all' type callbacks, irrespective of if the
            # transaction pertains to anything known (but must
            # have correct label per above); filter on this Joinmarket wallet label,
            # or the external monitoring label:
            if "label" in tx and tx["label"] in [
                self.EXTERNAL_WALLET_LABEL, self.get_wallet_name()]:
                for f in self.callbacks["all"]:
                    # note we need no return value as we will never
                    # remove these from the list
                    f(txd, txid)

            # The tuple given as the second possible key for the dict
            # is such because dict keys must be hashable types, so a simple
            # replication of the entries in the list tx["outs"], where tx
            # was generated via jmbitcoin.deserialize, is unacceptable to
            # Python, since they are dicts. However their keyset is deterministic
            # so it is sufficient to convert these dicts to tuples with fixed
            # ordering, thus it can be used as a key into the self.callbacks
            # dicts. (This is needed because txid is not always available
            # at the time of callback registration).
            possible_keys = [txid, tuple(
                    (x["script"], x["value"]) for x in txd["outs"])]

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
                # if callback is not in the list, it was already
                # processed and so do nothing.

    def log_new_tx(self, removed_utxos, added_utxos, txid):
        """ Changes to the wallet are logged at INFO level by
        the WalletService.
        """
        def report_changed(x, utxos):
            if len(utxos.keys()) > 0:
                jlog.info(x + ' utxos=\n{}'.format('\n'.join(
                    '{} - {}'.format(u, fmt_tx_data(tx_data, self))
                    for u, tx_data in utxos.items())))

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
        self.old_txs = [x['txid'] for x in self.bci.list_transactions(100)]
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
        self.get_address_usages()
        self.sync_unspent()

    def get_address_usages(self):
        """Use rpc `listaddressgroupings` to locate all used
        addresses in the account (whether spent or unspent outputs).
        This will not result in a full sync if working with a new
        Bitcoin Core instance, in which case "fast" should have been
        specifically disabled by the user.
        """
        wallet_name = self.get_wallet_name()
        agd = self.bci.rpc('listaddressgroupings', [])
        # flatten all groups into a single list; then, remove duplicates
        fagd = (tuple(item) for sublist in agd for item in sublist)
        # "deduplicated flattened address grouping data" = dfagd
        dfagd = set(fagd)
        used_addresses = set()
        for addr_info in dfagd:
            if len(addr_info) < 3 or addr_info[2] != wallet_name:
                continue
            used_addresses.add(addr_info[0])

        # for a first run, import first chunk
        if not used_addresses:
            jlog.info("Detected new wallet, performing initial import")
            # delegate inital address import to sync_addresses
            # this should be fast because "getaddressesbyaccount" should return
            # an empty list in this case
            self.sync_addresses()
            self.synced = True
            return

        # Wallet has been used; scan forwards.
        jlog.debug("Fast sync in progress. Got this many used addresses: " + str(
            len(used_addresses)))
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
        #    not be exposed to the user; it is not the same as gap limit, in fact,
        #    the concept of gap limit does not apply to this kind of sync, which
        #    *assumes* that the most recent usage of addresses is indeed recorded.
        remaining_used_addresses = used_addresses.copy()
        addresses, saved_indices = self.collect_addresses_init()
        for addr in addresses:
            remaining_used_addresses.discard(addr)

        BATCH_SIZE = 100
        MAX_ITERATIONS = 20
        current_indices = deepcopy(saved_indices)
        for j in range(MAX_ITERATIONS):
            if not remaining_used_addresses:
                break
            for addr in \
                self.collect_addresses_gap(gap_limit=BATCH_SIZE):
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
        used_indices = self.get_used_indices(used_addresses)
        self.rewind_wallet_indices(used_indices, saved_indices)
        self.synced = True

    def sync_addresses(self):
        """ Triggered by use of --recoversync option in scripts,
        attempts a full scan of the blockchain without assuming
        anything about past usages of addresses (does not use
        wallet.index_cache as hint).
        """
        jlog.debug("requesting detailed wallet history")
        wallet_name = self.get_wallet_name()
        addresses, saved_indices = self.collect_addresses_init()
        try:
            imported_addresses = set(self.bci.rpc('getaddressesbyaccount',
                                                  [wallet_name]))
        except JsonRpcError:
            if wallet_name in self.bci.rpc('listlabels', []):
                imported_addresses = set(self.bci.rpc('getaddressesbylabel',
                                                      [wallet_name]).keys())
            else:
                imported_addresses = set()

        if not addresses.issubset(imported_addresses):
            self.bci.add_watchonly_addresses(addresses - imported_addresses,
                                             wallet_name, self.restart_callback)
            return

        used_addresses_gen = (tx['address']
                              for tx in self.bci._yield_transactions(wallet_name)
                              if tx['category'] == 'receive')
        used_indices = self.get_used_indices(used_addresses_gen)
        jlog.debug("got used indices: {}".format(used_indices))
        gap_limit_used = not self.check_gap_indices(used_indices)
        self.rewind_wallet_indices(used_indices, saved_indices)

        new_addresses = self.collect_addresses_gap()
        if not new_addresses.issubset(imported_addresses):
            jlog.debug("Syncing iteration finished, additional step required")
            self.bci.add_watchonly_addresses(new_addresses - imported_addresses,
                                             wallet_name, self.restart_callback)
            self.synced = False
        elif gap_limit_used:
            jlog.debug("Syncing iteration finished, additional step required")
            self.synced = False
        else:
            jlog.debug("Wallet successfully synced")
            self.rewind_wallet_indices(used_indices, saved_indices)
            self.synced = True

    def sync_unspent(self):
        st = time.time()
        # block height needs to be real time for addition to our utxos:
        current_blockheight = self.bci.rpc("getblockcount", [])
        wallet_name = self.get_wallet_name()
        self.reset_utxos()

        listunspent_args = []
        if 'listunspent_args' in jm_single().config.options('POLICY'):
            listunspent_args = ast.literal_eval(jm_single().config.get(
                'POLICY', 'listunspent_args'))

        unspent_list = self.bci.rpc('listunspent', listunspent_args)
        unspent_list = [x for x in unspent_list if "label" in x]
        # filter on label, but note (a) in certain circumstances (in-
        # wallet transfer) it is possible for the utxo to be labeled
        # with the external label, and (b) the wallet will know if it
        # belongs or not anyway (is_known_addr):
        our_unspent_list = [x for x in unspent_list if x["label"] in [
            wallet_name, self.EXTERNAL_WALLET_LABEL]]
        for u in our_unspent_list:
            if not self.is_known_addr(u['address']):
                continue
            self._add_unspent_utxo(u, current_blockheight)
        et = time.time()
        jlog.debug('bitcoind sync_unspent took ' + str((et - st)) + 'sec')

    def _add_unspent_utxo(self, utxo, current_blockheight):
        """
        Add a UTXO as returned by rpc's listunspent call to the wallet.

        params:
            utxo: single utxo dict as returned by listunspent
            current_blockheight: blockheight as integer, used to
            set the block in which a confirmed utxo is included.
        """
        txid = binascii.unhexlify(utxo['txid'])
        script = binascii.unhexlify(utxo['scriptPubKey'])
        value = int(Decimal(str(utxo['amount'])) * Decimal('1e8'))
        confs = int(utxo['confirmations'])
        # wallet's utxo database needs to store an absolute rather
        # than relative height measure:
        height = None
        if confs < 0:
            jlog.warning("Utxo not added, has a conflict: " + str(utxo))
            return
        if confs >=1 :
            height = current_blockheight - confs + 1
        self.add_utxo(txid, int(utxo['vout']), script, value, height)


    """ The following functions mostly are not pure
    pass through to the underlying wallet, so declared
    here; the remainder are covered by the __getattr__
    fallback.
    """

    def save_wallet(self):
        self.wallet.save()

    def get_utxos_by_mixdepth(self, include_disabled=False,
                              verbose=False, hexfmt=True, includeconfs=False):
        """ Returns utxos by mixdepth in a dict, optionally including
        information about how many confirmations each utxo has.
        TODO clean up underlying wallet.get_utxos_by_mixdepth (including verbosity
        and formatting options) to make this less confusing.
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

        if hexfmt:
            ubym = self.wallet.get_utxos_by_mixdepth(verbose=verbose,
                                                     includeheight=includeconfs)
            if not includeconfs:
                return ubym
            else:
                return height_to_confs(ubym)
        else:
            ubym = self.wallet.get_utxos_by_mixdepth_(
            include_disabled=include_disabled, includeheight=includeconfs)
            if not includeconfs:
                return ubym
            else:
                return height_to_confs(ubym)

    def select_utxos(self, mixdepth, amount, utxo_filter=None, select_fn=None,
                     minconfs=None):
        """ Request utxos from the wallet in a particular mixdepth to satisfy
        a certain total amount, optionally set the selector function (or use
        the currently configured function set by the wallet, and optionally
        require a minimum of minconfs confirmations (default none means
        unconfirmed are allowed).
        """
        if minconfs is None:
            maxheight = None
        else:
            maxheight = self.current_blockheight - minconfs + 1
        return self.wallet.select_utxos(mixdepth, amount, utxo_filter=utxo_filter,
                                    select_fn=select_fn, maxheight=maxheight)

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
            for internal in (0, 1):
                next_unused = self.get_next_unused_index(md, internal)
                for index in range(next_unused):
                    addresses.add(self.get_addr(md, internal, index))
                for index in range(self.gap_limit):
                    addresses.add(self.get_new_addr(md, internal))
                # reset the indices to the value we had before the
                # new address calls:
                self.set_next_index(md, internal, next_unused)
                saved_indices[md][internal] = next_unused
            # include any imported addresses
            for path in self.yield_imported_paths(md):
                addresses.add(self.get_addr_path(path))

        return addresses, saved_indices

    def collect_addresses_gap(self, gap_limit=None):
        gap_limit = gap_limit or self.gap_limit
        addresses = set()

        for md in range(self.max_mixdepth + 1):
            for internal in (True, False):
                old_next = self.get_next_unused_index(md, internal)
                for index in range(gap_limit):
                    addresses.add(self.get_new_addr(md, internal))
                self.set_next_index(md, internal, old_next)

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
