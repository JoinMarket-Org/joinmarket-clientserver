import ast
import binascii
import random
import sys
import time
from abc import ABC, abstractmethod
from decimal import Decimal
from typing import *

from twisted.internet import reactor, task

import jmbitcoin as btc
from jmbase import bintohex, hextobin, stop_reactor
from jmbase.support import get_log, jmprint, EXIT_FAILURE
from jmclient.configure import jm_single
from jmclient.jsonrpc import JsonRpc, JsonRpcConnectionError, JsonRpcError


# an inaccessible blockheight; consider rewriting in 1900 years
INF_HEIGHT = 10**8

log = get_log()

class BlockchainInterface(ABC):

    def __init__(self) -> None:
        pass

    @abstractmethod
    def is_address_imported(self, addr: str) -> bool:
        """checks that address is already imported"""

    @abstractmethod
    def is_address_labeled(self, utxo: dict, walletname: str) -> bool:
        """checks that UTXO belongs to the JM wallet"""

    @abstractmethod
    def pushtx(self, txbin: bytes) -> bool:
        """ Given a binary serialized valid bitcoin transaction,
        broadcasts it to the network.
        """

    @abstractmethod
    def query_utxo_set(self,
                       txouts: Union[Tuple[bytes, int], List[Tuple[bytes, int]]],
                       includeconfs: bool = False,
                       include_mempool: bool = True) -> List[Optional[dict]]:
        """If txout is either (a) a single utxo in (txidbin, n) form,
        or a list of the same, returns, as a list for each txout item,
        the result of gettxout from the bitcoind rpc for those utxos;
        if any utxo is invalid, None is returned.
        includeconfs: if this is True, the current number of confirmations
        of the prescribed utxo is included in the returned result dict.
        include_mempool: if True, the contents of the mempool are included;
        this *both* means that utxos that are spent in in-mempool transactions
        are *not* returned, *and* means that utxos that are created in the
        mempool but have zero confirmations *are* returned.
        If the utxo is of a non-standard type such that there is no address,
        the address field in the dict is None.
        """

    @abstractmethod
    def get_wallet_rescan_status(self) -> Tuple[bool, Optional[Decimal]]:
        """Returns pair of True/False is wallet currently rescanning and
        Optional[Decimal] with current rescan progress status."""

    @abstractmethod
    def rescanblockchain(self, start_height: int, end_height: Optional[int] = None) -> None:
        """Rescan the local blockchain for wallet related transactions.
        """

    @abstractmethod
    def import_addresses_if_needed(self, addresses: Set[str], wallet_name: str) -> bool:
        """import addresses to the underlying blockchain interface if needed
        returns True if the sync call needs to do a system exit"""

    @abstractmethod
    def import_addresses(self, addr_list: Iterable[str], wallet_name: str,
                         restart_cb: Optional[Callable[[str], None]] = None) -> None:
        """Imports addresses in a batch during initial sync.
        Refuses to proceed if keys are found to be under control
        of another account/label (see console output), and quits.
        """

    @abstractmethod
    def list_transactions(self, num: int, skip: int = 0) -> List[dict]:
        """ Return a list of the last `num` transactions seen
        in the wallet (under any label/account), optionally
        skipping some.
        """

    @abstractmethod
    def get_deser_from_gettransaction(self, rpcretval: dict) -> Optional[btc.CMutableTransaction]:
        """Get full transaction deserialization from a call
        to get_transaction().
        """

    @abstractmethod
    def get_transaction(self, txid: bytes) -> Optional[dict]:
        """ Argument txid is passed in binary.
        Returns a serialized transaction for txid txid,
        in hex as returned by Bitcoin Core rpc, or None
        if no transaction can be retrieved. Works also for
        watch-only wallets.
        """

    @abstractmethod
    def get_block(self, blockheight: int) -> str:
        """Returns full hex serialized block at a given height.
        """

    @abstractmethod
    def get_current_block_height(self) -> int:
        """Returns the height of the most-work fully-validated chain.
        """

    @abstractmethod
    def get_best_block_hash(self) -> str:
        """Returns the hash of the best (tip) block in the most-work
        fully-validated chain.
        """

    @abstractmethod
    def get_best_block_median_time(self) -> int:
        """Returns median time for the current best block.
        """

    @abstractmethod
    def get_block_height(self, blockhash: str) -> int:
        """Returns the block height for a specific block hash.
        """

    @abstractmethod
    def get_block_time(self, blockhash: str) -> int:
        """Returns the block time expressed in UNIX epoch time for a specific
        block hash.
        """

    @abstractmethod
    def get_block_hash(self, height: int) -> str:
        """Returns hash of block in best-block-chain at height provided.
        """

    @abstractmethod
    def get_tx_merkle_branch(self, txid: str,
                             blockhash: Optional[str] = None) -> bytes:
        """TODO: describe method.
        """

    @abstractmethod
    def verify_tx_merkle_branch(self, txid: str, block_height: int,
                                merkle_branch: bytes) -> bool:
        """TODO: describe method.
        """

    @abstractmethod
    def listaddressgroupings(self) -> list:
        """Lists groups of addresses which have had their common ownership
        made public by common use as inputs or as the resulting change
        in past transactions.
        """

    @abstractmethod
    def listunspent(self, minconf: Optional[int] = None) -> List[dict]:
        """Returns list of unspent transaction output info dicts,
        optionally filtering by minimum confirmations.
        """

    @abstractmethod
    def testmempoolaccept(self, rawtx: str) -> bool:
        """Checks that raw transaction would be accepted by mempool.
        """

    @abstractmethod
    def mempoolfullrbf(self) -> bool:
        """Whether mempool full-RBF is enabled.
        """

    @abstractmethod
    def _get_mempool_min_fee(self) -> Optional[int]:
        """Returns minimum mempool fee as a floor to avoid relay problems
        or None in case of error.
        """

    @abstractmethod
    def _estimate_fee_basic(self,
                            conf_target: int) -> Optional[Tuple[int, int]]:
        """Returns basic fee estimation for confirmation target in blocks.
        Additional JoinMarket fee logic is added on top, see
        `estimate_fee_per_kb` for details. Returns tuple of feerate in sats
        per kvB and actual used conf_target or None in case of error.
        """

    def yield_transactions(self) -> Generator[dict, None, None]:
        """ Generates a lazily fetched sequence of transactions seen in the
        wallet (under any label/account), yielded in newest-first order. Care
        is taken to avoid yielding duplicates even when new transactions are
        actively being added to the wallet while the iteration is ongoing.
        """
        num, skip = 1, 0
        txs = self.list_transactions(num, skip)
        if not txs:
            return
        yielded_tx = txs[0]
        yield yielded_tx
        while True:
            num *= 2
            txs = self.list_transactions(num, skip)
            if not txs:
                return
            try:
                idx = [(tx['txid'], tx['vout'], tx['category']) for tx in txs
                        ].index((yielded_tx['txid'], yielded_tx['vout'],
                        yielded_tx['category']))
            except ValueError:
                skip += num
                continue
            for tx in reversed(txs[:idx]):
                yielded_tx = tx  # inefficient but more obvious
                yield yielded_tx
            if len(txs) < num:
                return
            skip += num - 1

    def get_unspent_indices(self, transaction: btc.CTransaction) -> List[int]:
        """ Given a CTransaction object, identify the list of
        indices of outputs which are unspent (returned as list of ints).
        """
        bintxid = transaction.GetTxid()[::-1]
        res = self.query_utxo_set([(bintxid, i) for i in range(
            len(transaction.vout))])
        # QUS returns 'None' for spent outputs, so filter them out
        # and return the indices of the others:
        return [i for i, val in enumerate(res) if val]

    def fee_per_kb_has_been_manually_set(self, tx_fees: int) -> bool:
        """If the block target (tx_fees) is higher than 1000, interpret it
        as manually set fee sats/kvB.
        """
        return tx_fees > 1000

    def estimate_fee_per_kb(self, tx_fees: int) -> int:
        """ The argument tx_fees may be either a number of blocks target,
        for estimation of feerate by Core, or a number of satoshis
        per kilo-vbyte (see `fee_per_kb_has_been_manually_set` for
        how this is distinguished).
        In both cases it is prevented from falling below the current
        minimum feerate for tx to be accepted into node's mempool.
        In case of failure to connect, source a specific minimum fee relay
        rate (which is used to sanity check user's chosen fee rate), or
        failure to source a feerate estimate for targeted number of blocks,
        a default of 20000 is returned.
        """

        # default to use if fees cannot be estimated
        fallback_fee = 20000

        tx_fees_factor = abs(jm_single().config.getfloat('POLICY', 'tx_fees_factor'))

        mempoolminfee_in_sat = self._get_mempool_min_fee()
        # in case of error
        if mempoolminfee_in_sat is None:
            mempoolminfee_in_sat = fallback_fee
        mempoolminfee_in_sat_randomized = random.uniform(
            mempoolminfee_in_sat, mempoolminfee_in_sat * float(1 + tx_fees_factor))

        if self.fee_per_kb_has_been_manually_set(tx_fees):
            N_res = random.uniform(tx_fees, tx_fees * float(1 + tx_fees_factor))
            if N_res < mempoolminfee_in_sat:
                msg = "Using this mempool min fee as tx feerate"
                if tx_fees_factor != 0:
                    msg = msg + " (randomized for privacy)"
                log.info(msg + ": " + btc.fee_per_kb_to_str(
                    mempoolminfee_in_sat_randomized) + ".")
                return int(mempoolminfee_in_sat_randomized)
            else:
                msg = "Using this manually set tx feerate"
                if tx_fees_factor != 0:
                    msg = msg + " (randomized for privacy)"
                log.info(msg + ": " + btc.fee_per_kb_to_str(N_res) + ".")
                return int(N_res)

        retval = self._estimate_fee_basic(tx_fees)
        if retval is None:
            msg = "Fee estimation for " + str(tx_fees) + \
                " block confirmation target failed. " + \
                "Falling back to default"
            if tx_fees_factor != 0:
                msg = msg + " (randomized for privacy)"
            fallback_fee_randomized = random.uniform(
                fallback_fee, fallback_fee * float(1 + tx_fees_factor))
            log.warn(msg + ": " +
                btc.fee_per_kb_to_str(fallback_fee_randomized) + ".")
            return int(fallback_fee_randomized)

        feerate, blocks = retval
        # 1 block difference is tolerated with intent, Core will often return
        # 2 block target for `estimatesmartfee 1`.
        if tx_fees - blocks > 1:
            log.warning(
                f"Fee estimation for {tx_fees} block confirmation target "
                f"was requested, but {blocks} block target was provided by "
                "blockchain source. Tx fee may be higher then expected.")

        feerate = random.uniform(feerate, feerate * float(1 + tx_fees_factor))

        if feerate < mempoolminfee_in_sat:
            msg = "Using this mempool min fee as tx feerate"
            if tx_fees_factor != 0:
                msg = msg + " (randomized for privacy)"
            log.info(msg + ": " + btc.fee_per_kb_to_str(
                mempoolminfee_in_sat_randomized) + ".")
            return int(mempoolminfee_in_sat_randomized)
        else:
            msg = "Using bitcoin network feerate for " + str(tx_fees) + \
                " block confirmation target"
            if tx_fees_factor != 0:
                msg = msg + " (randomized for privacy)"
            log.info(msg + ": " + btc.fee_per_kb_to_str(feerate))
            return int(feerate)

    def core_proof_to_merkle_branch(self, core_proof: str) -> bytes:
        core_proof = binascii.unhexlify(core_proof)
        #first 80 bytes of a proof given by core are just a block header
        #so we can save space by replacing it with a 4-byte block height
        return core_proof[80:]


class BitcoinCoreInterface(BlockchainInterface):

    def __init__(self, jsonRpc: JsonRpc, network: str, wallet_name: str) -> None:
        super().__init__()
        self.jsonRpc = jsonRpc
        blockchainInfo = self._rpc("getblockchaininfo", [])
        if not blockchainInfo:
            # see note in BitcoinCoreInterface._rpc() - here
            # we have to create this object before reactor start,
            # so reactor is not stopped, so we override the 'swallowing'
            # of the Exception that happened in self._rpc():
            raise JsonRpcConnectionError("RPC connection to Bitcoin Core "
                                         "was not established successfully.")
        actualNet = blockchainInfo['chain']

        netmap = {'main': 'mainnet', 'test': 'testnet', 'regtest': 'regtest',
            'signet': 'signet', 'testnet4': 'testnet4'}
        if netmap[actualNet] != network and \
                (not (actualNet == "regtest" and network == "testnet")):
            #special case of regtest and testnet having the same addr format
            raise Exception('wrong network configured')

        if wallet_name:
            self.jsonRpc.setURL("/wallet/" + wallet_name)
            # Check that RPC wallet is loaded. If not, try to load it.
            loaded_wallets = self._rpc("listwallets", [])
            if not wallet_name in loaded_wallets:
                log.info("Loading Bitcoin RPC wallet " + wallet_name + "...")
                self._rpc("loadwallet", [wallet_name])
                log.info("Done.")
            # We need to know is this legacy or descriptors wallet because there
            # will be different RPC calls needed for address import.
            wallet_info = self._getwalletinfo()
            self.descriptors = ("descriptors" in wallet_info and
                wallet_info["descriptors"])

    def is_address_imported(self, addr: str) -> bool:
        return len(self._rpc('getaddressinfo', [addr])['labels']) > 0

    def get_block(self, blockheight: int) -> str:
        """Returns full serialized block at a given height.
        """
        block_hash = self.get_block_hash(blockheight)
        return self._rpc('getblock', [block_hash, 0])

    def rescanblockchain(self, start_height: int, end_height: Optional[int] = None) -> None:
        # Threading is not used in Joinmarket but due to blocking
        # nature of this very slow RPC call, we need to fire and forget.
        from threading import Thread
        Thread(target=self._rescan_in_thread, args=(start_height,),
               daemon=True).start()

    def _rescan_in_thread(self, start_height: int) -> None:
        """ In order to not conflict with the existing main
        JsonRPC connection in the main thread, this rescanning
        thread creates a distinct JsonRPC object, just to make
        this one RPC call `rescanblockchain <height>`, using the
        same credentials.
        """
        from jmclient.jsonrpc import JsonRpc
        authstr = self.jsonRpc.authstr
        user, password = authstr.split(":")
        newjsonRpc = JsonRpc(self.jsonRpc.host,
                             self.jsonRpc.port,
                             user, password,
                             url=self.jsonRpc.url)
        try:
            newjsonRpc.call('rescanblockchain', [start_height])
        except JsonRpcConnectionError:
            log.error("Failure of RPC connection to Bitcoin Core. "
                      "Rescanning process not started.")

    def _getwalletinfo(self) -> dict:
        """ Returns detailed about currently loaded (see `loadwallet`
        call in __init__) Bitcoin Core wallet.
        """
        return self._rpc("getwalletinfo", [])

    def get_wallet_rescan_status(self) -> Tuple[bool, Optional[Decimal]]:
        winfo = self._getwalletinfo()
        if "scanning" in winfo and winfo["scanning"]:
            # If not 'false', it contains info that looks like:
            # {'duration': 1, 'progress': Decimal('0.04665404082350701')}
            return True, winfo["scanning"]["progress"]
        else:
            return False, None

    def _rpc(self, method: str, args: Union[dict, list] = []) -> Any:
        """ Returns the result of an rpc call to the Bitcoin Core RPC API.
        If the connection is permanently or unrecognizably broken, None
        is returned *and the reactor is shutdown* (because we consider this
        condition unsafe - TODO possibly create a "freeze" mode that could
        restart when the connection is healed, but that is tricky).
        Should not be called directly from outside code.
        """
        # TODO: flip the logic of this. We almost never want to print these
        # out even to debug as they are noisy.
        if method not in ['importaddress', 'walletpassphrase', 'getaccount',
                          'gettransaction', 'getrawtransaction', 'gettxout',
                          'importmulti', 'listtransactions', 'getblockcount',
                          'scantxoutset', 'getblock', 'getblockhash',
                          'importdescriptors']:
            log.debug('rpc: ' + method + " " + str(args))
        try:
            res = self.jsonRpc.call(method, args)
        except JsonRpcConnectionError as e:
            # note that we only raise this in case the connection error is
            # a refusal, or is unrecognized/unknown by our code. So this does
            # NOT happen in a reset or broken pipe scenario.
            # It is safest to simply shut down.
            # Why not sys.exit? sys.exit calls do *not* work inside delayedCalls
            # or deferreds in twisted, since a bare exception catch prevents
            # an actual system exit (i.e. SystemExit is caught as a
            # BareException type).
            log.error("Failure of RPC connection to Bitcoin Core. "
                      "Application cannot continue, shutting down.")
            stop_reactor()
            return None
        # note that JsonRpcError is not caught here; for some calls, we
        # have specific behaviour requirements depending on these errors,
        # so this is handled elsewhere in BitcoinCoreInterface.
        return res

    def is_address_labeled(self, utxo: dict, walletname: str) -> bool:
        return ("label" in utxo and utxo["label"] == walletname)

    def import_addresses(self, addr_list: Iterable[str], wallet_name: str,
                         restart_cb: Callable[[str], None] = None) -> None:
        requests = []
        if self.descriptors:
            for addr in addr_list:
                requests.append({
                    "desc": btc.get_address_descriptor(addr),
                    "timestamp": "now",
                    "label": wallet_name
                })
            result = self._rpc('importdescriptors', [requests])
        else:
            for addr in addr_list:
                requests.append({
                    "scriptPubKey": {"address": addr},
                    "timestamp": 0,
                    "label": wallet_name,
                    "watchonly": True
                })
            result = self._rpc('importmulti', [requests, {"rescan": False}])

        num_failed = 0
        for row in result:
            if row['success'] == False:
                num_failed += 1
                # don't try/catch, assume failure always has error message
                log.warn(row['error']['message'])
        if num_failed > 0:
            fatal_msg = ("Fatal sync error: import of {} address(es) failed for "
                         "some reason. To prevent coin or privacy loss, "
                         "Joinmarket will not load a wallet in this conflicted "
                         "state. Try using a new Bitcoin Core wallet to sync this "
                         "Joinmarket wallet, or use a new Joinmarket wallet."
                         "".format(num_failed))
            if restart_cb:
                restart_cb(fatal_msg)
            else:
                jmprint(fatal_msg, "important")
            sys.exit(EXIT_FAILURE)

    def import_addresses_if_needed(self, addresses: Set[str], wallet_name: str) -> bool:
        if wallet_name in self._rpc('listlabels', []):
            imported_addresses = set(self._rpc('getaddressesbylabel',
                                                  [wallet_name]).keys())
        else:
            imported_addresses = set()
        import_needed = not addresses.issubset(imported_addresses)
        if import_needed:
            self.import_addresses(addresses - imported_addresses, wallet_name)
        return import_needed

    def get_deser_from_gettransaction(self, rpcretval: dict) -> Optional[btc.CMutableTransaction]:
        if not "hex" in rpcretval:
            log.info("Malformed gettransaction output")
            return None
        return btc.CMutableTransaction.deserialize(
            hextobin(rpcretval["hex"]))

    def list_transactions(self, num: int, skip: int = 0) -> List[dict]:
        return self._rpc("listtransactions", ["*", num, skip, True])

    def get_transaction(self, txid: bytes) -> Optional[dict]:
        htxid = bintohex(txid)
        try:
            res = self._rpc("gettransaction", [htxid, True])
        except JsonRpcError as e:
            #This should never happen (gettransaction is a wallet rpc).
            log.warn("Failed gettransaction call; JsonRpcError: " + repr(e))
            return None
        except Exception as e:
            log.warn("Failed gettransaction call; unexpected error:")
            log.warn(str(e))
            return None
        if res is None:
            # happens in case of rpc connection failure:
            return None
        if "confirmations" not in res:
            log.warning("Malformed gettransaction result: " + str(res))
            return None
        return res

    def pushtx(self, txbin: bytes) -> bool:
        """ Given a binary serialized valid bitcoin transaction,
        broadcasts it to the network.
        """
        txhex = bintohex(txbin)
        try:
            txid = self._rpc('sendrawtransaction', [txhex])
        except JsonRpcConnectionError as e:
            log.warning('error pushing = ' + repr(e))
            return False
        except JsonRpcError as e:
            log.warning('error pushing = ' + str(e.code) + " " + str(e.message))
            return False
        return True

    def query_utxo_set(self,
                       txouts: Union[Tuple[bytes, int], List[Tuple[bytes, int]]],
                       includeconfs: bool = False,
                       include_mempool: bool = True) -> List[Optional[dict]]:
        if not isinstance(txouts, list):
            txouts = [txouts]
        result = []
        for txo in txouts:
            txo_hex = bintohex(txo[0])
            if len(txo_hex) != 64:
                log.warn("Invalid utxo format, ignoring: {}".format(txo))
                result.append(None)
                continue
            try:
                txo_idx = int(txo[1])
            except ValueError:
                log.warn("Invalid utxo format, ignoring: {}".format(txo))
                result.append(None)
                continue
            ret = self._rpc('gettxout', [txo_hex, txo_idx, include_mempool])
            if ret is None:
                result.append(None)
            else:
                result_dict = {'value': int(Decimal(str(ret['value'])) *
                                            Decimal('1e8')),
                               'script': hextobin(ret['scriptPubKey']['hex'])}
                if includeconfs:
                    result_dict['confirms'] = int(ret['confirmations'])
                result.append(result_dict)
        return result

    def _getmempoolinfo(self) -> Optional[dict]:
        return self._rpc('getmempoolinfo')

    def _get_mempool_min_fee(self) -> Optional[int]:
        rpc_result = self._getmempoolinfo()
        if not rpc_result:
            # in case of connection error:
            return None
        return btc.btc_to_sat(rpc_result['mempoolminfee'])

    def mempoolfullrbf(self) -> bool:
        rpc_result = self._getmempoolinfo()
        return 'fullrbf' in rpc_result and rpc_result['fullrbf']

    def _estimate_fee_basic(self,
                            conf_target: int) -> Optional[Tuple[int, int]]:
        # Special bitcoin core case: sometimes the highest priority
        # cannot be estimated in that case the 2nd highest priority
        # should be used instead of falling back to hardcoded values
        tries = 2 if conf_target == 1 else 1
        rpc_result = None
        for i in range(tries):
            try:
                rpc_result = self._rpc('estimatesmartfee', [conf_target + i])
            except JsonRpcError:
                continue
            if not rpc_result:
                # in case of connection error:
                return None
            estimate = rpc_result.get('feerate')
            # `estimatesmartfee` will currently return in the format
            # `{'errors': ['Insufficient data or no feerate found'], 'blocks': N}`
            # if it is not able to make an estimate. We insist that
            # the 'feerate' key is found and contains a positive value:
            if estimate and estimate > 0:
                return (btc.btc_to_sat(estimate), rpc_result.get('blocks'))
        # cannot get a valid estimate after `tries` tries:
        log.warn("Could not source a fee estimate from Core")
        return None

    def get_current_block_height(self) -> int:
        try:
            return self._rpc("getblockcount", [])
        except JsonRpcError as e:
            raise RuntimeError("Getblockcount RPC failed with: %i, %s" % (
                e.code, e.message))

    def get_best_block_hash(self) -> str:
        return self._rpc('getbestblockhash', [])

    def get_best_block_median_time(self) -> int:
        return self._rpc('getblockchaininfo', [])['mediantime']

    def _get_block_header_data(self, blockhash: str, key: str) -> Any:
        return self._rpc('getblockheader', [blockhash])[key]

    def get_block_height(self, blockhash: str) -> int:
        return self._get_block_header_data(blockhash, 'height')

    def get_block_time(self, blockhash: str) -> int:
        return self._get_block_header_data(blockhash, 'time')

    def get_block_hash(self, height: int) -> str:
        return self._rpc("getblockhash", [height])

    def get_tx_merkle_branch(self, txid: str,
                             blockhash: Optional[str] = None) -> bytes:
        if not blockhash:
            tx = self._rpc("gettransaction", [txid])
            if tx["confirmations"] < 1:
                raise ValueError("Transaction not in block")
            blockhash = tx["blockhash"]
        try:
            core_proof = self._rpc("gettxoutproof", [[txid], blockhash])
        except JsonRpcError:
            raise ValueError("Block containing transaction is pruned")
        return self.core_proof_to_merkle_branch(core_proof)

    def verify_tx_merkle_branch(self, txid: str, block_height: int,
                                merkle_branch: bytes) -> bool:
        block_hash = self.get_block_hash(block_height)
        core_proof = self._rpc("getblockheader", [block_hash, False]) + \
            binascii.hexlify(merkle_branch).decode()
        ret = self._rpc("verifytxoutproof", [core_proof])
        return len(ret) == 1 and ret[0] == txid

    def listaddressgroupings(self) -> list:
        return self._rpc('listaddressgroupings', [])

    def listunspent(self, minconf: Optional[int] = None) -> List[dict]:
        listunspent_args = []
        if 'listunspent_args' in jm_single().config.options('POLICY'):
            listunspent_args = ast.literal_eval(jm_single().config.get(
                'POLICY', 'listunspent_args'))
        if minconf is not None:
            listunspent_args[0] = minconf
        return self._rpc('listunspent', listunspent_args)

    def testmempoolaccept(self, rawtx: str) -> bool:
        res = self._rpc('testmempoolaccept', [[rawtx]])
        return res[0]["allowed"]


class RegtestBitcoinCoreMixin():
    """
    This Mixin provides helper functions that are used in Interface classes
    requiring some functionality only useful on the regtest network.
    """
    def tick_forward_chain(self, n: int) -> None:
        """
        Special method for regtest only;
        instruct to mine n blocks.
        """
        try:
            self._rpc('generatetoaddress', [n, self.destn_addr])
        except JsonRpcConnectionError:
            #can happen if the blockchain is shut down
            #automatically at the end of tests; this shouldn't
            #trigger an error
            log.debug(
                "Failed to generate blocks, looks like the bitcoin daemon \
	    has been shut down. Ignoring.")

    def grab_coins(self, receiving_addr: str, amt: int = 50) -> str:
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
        if self._rpc('setgenerate', [True, reqd_blocks]):
        raise Exception("Something went wrong")
        """
        # now we do a custom create transaction and push to the receiver
        txid = self._rpc('sendtoaddress', [receiving_addr, amt])
        if not txid:
            raise Exception("Failed to broadcast transaction")
        # confirm
        self.tick_forward_chain(1)
        return txid


class BitcoinCoreNoHistoryInterface(BitcoinCoreInterface, RegtestBitcoinCoreMixin):

    def __init__(self, jsonRpc: JsonRpc, network: str, wallet_name: str) -> None:
        super().__init__(jsonRpc, network, wallet_name)
        self.import_addresses_call_count = 0
        self.wallet_name = None
        self.scan_result = None

    def import_addresses_if_needed(self, addresses: Set[str], wallet_name: str) -> bool:
        self.import_addresses_call_count += 1
        if self.import_addresses_call_count == 1:
            self.wallet_name = wallet_name
            addr_list = [btc.get_address_descriptor(a) for a in addresses]
            log.debug("Starting scan of UTXO set")
            st = time.time()
            self._rpc("scantxoutset", ["abort", []])
            self.scan_result = self._rpc("scantxoutset", ["start",
                addr_list])
            et = time.time()
            log.debug("UTXO set scan took " + str(et - st) + "sec")
        elif self.import_addresses_call_count > 4:
            #called twice for the first call of sync_addresses(), then two
            # more times for the second call. the second call happens because
            # sync_addresses() re-runs in order to have gap_limit new addresses
            assert False
        return False

    def yield_transactions(self) -> Generator[dict, None, None]:
        for u in self.scan_result["unspents"]:
            tx = {"category": "receive", "address":
                btc.get_address_from_descriptor(u["desc"])}
            yield tx

    def list_transactions(self, num: int, skip: int = 0) -> List[dict]:
        return []

    def listaddressgroupings(self) -> list:
        raise RuntimeError("default sync not supported by bitcoin-rpc-nohistory, use --recoversync")

    def listunspent(self, minconf: Optional[int] = None) -> List[dict]:
        if minconf == 0:
            log.warning(
                "Unconfirmed transactions are not seen by "
                "bitcoin-rpc-nohistory.")
        return [{
            "address": btc.get_address_from_descriptor(u["desc"]),
            "label": self.wallet_name,
            "height": u["height"],
            "txid": u["txid"],
            "vout": u["vout"],
            "scriptPubKey": u["scriptPubKey"],
            "amount": u["amount"]
        } for u in self.scan_result["unspents"]]

    def set_wallet_no_history(self, wallet) -> None:
        #make wallet-tool not display any new addresses
        #because no-history cant tell if an address is used and empty
        #so this is necessary to avoid address reuse
        wallet.gap_limit = 0
        #disable generating change addresses, also because cant guarantee
        # avoidance of address reuse
        wallet.disable_new_scripts = True

    def tick_forward_chain(self, n: int) -> None:
        self.destn_addr = self._rpc("getnewaddress", [])
        super().tick_forward_chain(n)


# class for regtest chain access
# running on local daemon. Only
# to be instantiated after network is up
# with > 100 blocks.
class RegtestBitcoinCoreInterface(BitcoinCoreInterface, RegtestBitcoinCoreMixin): #pragma: no cover

    def __init__(self, jsonRpc: JsonRpc, wallet_name: str) -> None:
        super().__init__(jsonRpc, 'regtest', wallet_name)
        self.pushtx_failure_prob = 0
        self.tick_forward_chain_interval = -1
        self.absurd_fees = False
        self.simulating = False
        self.shutdown_signal = False
        self.destn_addr = self._rpc("getnewaddress", [])

    def estimate_fee_per_kb(self, tx_fees: int) -> int:
        if not self.absurd_fees:
            return super().estimate_fee_per_kb(tx_fees)
        else:
            return jm_single().config.getint("POLICY",
                                             "absurd_fee_per_kb") + 100

    def tickchain(self) -> None:
        if self.tick_forward_chain_interval < 0:
            log.debug('not ticking forward chain')
            self.tickchainloop.stop()
            return
        if self.shutdown_signal:
            self.tickchainloop.stop()
            return
        self.tick_forward_chain(1)

    def simulate_blocks(self) -> None:
        self.tickchainloop = task.LoopingCall(self.tickchain)
        self.tickchainloop.start(self.tick_forward_chain_interval)
        self.simulating = True

    def pushtx(self, txbin: bytes) -> bool:
        if self.pushtx_failure_prob != 0 and random.random() <\
                self.pushtx_failure_prob:
            log.debug('randomly not broadcasting %0.1f%% of the time' %
                      (self.pushtx_failure_prob * 100))
            return True

        ret = super().pushtx(txbin)
        if not self.simulating and self.tick_forward_chain_interval > 0:
            log.debug('will call tfc after ' + str(self.tick_forward_chain_interval) + ' seconds.')
            reactor.callLater(self.tick_forward_chain_interval,
                              self.tick_forward_chain, 1)
        return ret

    def get_received_by_addr(self, addresses: List[str]) -> dict:
        # NB This will NOT return coinbase coins (but wont matter in our use
        # case). allow importaddress to fail in case the address is already
        # in the wallet
        res = []
        for address in addresses:
            #self._rpc('importaddress', [address, 'watchonly'])
            res.append({'address': address,
                        'balance': int(Decimal(1e8) * self._rpc(
                            'getreceivedbyaddress', [address, 0]))})
        return {'data': res}
