
import abc
import random
import sys
import time
from decimal import Decimal
import binascii
from twisted.internet import reactor, task
from jmbase import bintohex, hextobin
import jmbitcoin as btc

from jmclient.jsonrpc import JsonRpcConnectionError, JsonRpcError
from jmclient.configure import jm_single
from jmbase.support import get_log, jmprint, EXIT_FAILURE


# an inaccessible blockheight; consider rewriting in 1900 years
INF_HEIGHT = 10**8

log = get_log()

class BlockchainInterface(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self):
        pass

    def is_address_imported(self, addr):
        try:
            return self.rpc('getaccount', [addr]) != ''
        except JsonRpcError:
            return len(self.rpc('getaddressinfo', [addr])['labels']) > 0

    def is_address_labeled(self, utxo, walletname):
        """checks that UTXO belongs to the JM wallet"""

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

    def import_addresses_if_needed(self, addresses, wallet_name):
        """import addresses to the underlying blockchain interface if needed
        returns True if the sync call needs to do a system exit"""

    def fee_per_kb_has_been_manually_set(self, N):
        '''if the 'block' target is higher than 1000, interpret it
        as manually set fee/Kb.
    '''
        if N > 1000:
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
        super().__init__()
        self.last_sync_unspent = 0

    def set_wallet(self, wallet):
        self.wallet = wallet

    def sync_addresses(self, wallet):
        log.debug("Dummy electrum interface, no sync address")

    def sync_unspent(self, wallet):
        log.debug("Dummy electrum interface, no sync unspent")

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
        if super().fee_per_kb_has_been_manually_set(N):
            # use a floor of 1000 to not run into node relay problems
            return int(max(1000, random.uniform(N * float(0.8), N * float(1.2))))
        fee = self.wallet.network.synchronous_get(('blockchain.estimatefee', [N]
                                                  ))
        fee_per_kb_sat = int(float(fee) * 100000000)
        log.info("Got fee: " + btc.fee_per_kb_to_str(fee_per_kb_sat))
        return fee_per_kb_sat

class BitcoinCoreInterface(BlockchainInterface):

    def __init__(self, jsonRpc, network):
        super().__init__()
        self.jsonRpc = jsonRpc
        blockchainInfo = self.rpc("getblockchaininfo", [])
        if not blockchainInfo:
            # see note in BitcoinCoreInterface.rpc - here
            # we have to create this object before reactor start,
            # so reactor is not stopped, so we override the 'swallowing'
            # of the Exception that happened in self.rpc():
            raise JsonRpcConnectionError("RPC connection to Bitcoin Core "
                                         "was not established successfully.")
        actualNet = blockchainInfo['chain']

        netmap = {'main': 'mainnet', 'test': 'testnet', 'regtest': 'regtest'}
        if netmap[actualNet] != network and \
                (not (actualNet == "regtest" and network == "testnet")):
            #special case of regtest and testnet having the same addr format
            raise Exception('wrong network configured')

    def get_block(self, blockheight):
        """Returns full serialized block at a given height.
        """
        block_hash = self.rpc('getblockhash', [blockheight])
        block = self.rpc('getblock', [block_hash, False])
        if not block:
            return False
        return block

    def rpc(self, method, args):
        """ Returns the result of an rpc call to the Bitcoin Core RPC API.
        If the connection is permanently or unrecognizably broken, None
        is returned *and the reactor is shutdown* (because we consider this
        condition unsafe - TODO possibly create a "freeze" mode that could
        restart when the connection is healed, but that is tricky).
        """
        if method not in ['importaddress', 'walletpassphrase', 'getaccount',
                          'gettransaction', 'getrawtransaction', 'gettxout',
                          'importmulti', 'listtransactions', 'getblockcount',
                          'scantxoutset']:
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
            if reactor.running:
                reactor.stop()
            return None
        return res

    def is_address_labeled(self, utxo, walletname):
        # Bitcoin Core before 0.17 used accounts, new versions has labels
        return (
            ("label" in utxo and utxo["label"] == walletname) or
            ("account" in utxo and utxo["account"] == walletname)
        )

    def import_addresses(self, addr_list, wallet_name, restart_cb=None):
        """Imports addresses in a batch during initial sync.
        Refuses to proceed if keys are found to be under control
        of another account/label (see console output), and quits.
        Do NOT use for in-run imports, use rpc('importaddress',..) instead.
        """
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

    def import_addresses_if_needed(self, addresses, wallet_name):
        try:
            imported_addresses = set(self.rpc('getaddressesbyaccount',
                                                  [wallet_name]))
        except JsonRpcError:
            if wallet_name in self.rpc('listlabels', []):
                imported_addresses = set(self.rpc('getaddressesbylabel',
                                                      [wallet_name]).keys())
            else:
                imported_addresses = set()
        import_needed = not addresses.issubset(imported_addresses)
        if import_needed:
            self.import_addresses(addresses - imported_addresses, wallet_name)
        return import_needed

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

    def get_deser_from_gettransaction(self, rpcretval):
        """Get full transaction deserialization from a call
        to `gettransaction`
        """
        if not "hex" in rpcretval:
            log.info("Malformed gettransaction output")
            return None
        return btc.CMutableTransaction.deserialize(
            hextobin(rpcretval["hex"]))

    def list_transactions(self, num, skip=0):
        """ Return a list of the last `num` transactions seen
        in the wallet (under any label/account), optionally
        skipping some.
        """
        return self.rpc("listtransactions", ["*", num, skip, True])

    def get_transaction(self, txid):
        """ Argument txid is passed in binary.
        Returns a serialized transaction for txid txid,
        in hex as returned by Bitcoin Core rpc, or None
        if no transaction can be retrieved. Works also for
        watch-only wallets.
        """
        htxid = bintohex(txid)
        #changed syntax in 0.14.0; allow both syntaxes
        try:
            res = self.rpc("gettransaction", [htxid, True])
        except Exception as e:
            try:
                res = self.rpc("gettransaction", [htxid, 1])
            except JsonRpcError as e:
                #This should never happen (gettransaction is a wallet rpc).
                log.warn("Failed gettransaction call; JsonRpcError: " + repr(e))
                return None
            except Exception as e:
                log.warn("Failed gettransaction call; unexpected error:")
                log.warn(str(e))
                return None
        if "confirmations" not in res:
            log.warning("Malformed gettx result: " + str(res))
            return None
        return res

    def pushtx(self, txbin):
        """ Given a binary serialized valid bitcoin transaction,
        broadcasts it to the network.
        """
        txhex = bintohex(txbin)
        try:
            txid = self.rpc('sendrawtransaction', [txhex])
        except JsonRpcConnectionError as e:
            log.warning('error pushing = ' + repr(e))
            return False
        except JsonRpcError as e:
            log.warning('error pushing = ' + str(e.code) + " " + str(e.message))
            return False
        return True

    def query_utxo_set(self, txout, includeconf=False, includeunconf=False):
        """If txout is either (a) a single utxo in (txidbin, n) form,
        or a list of the same, returns, as a list for each txout item,
        the result of gettxout from the bitcoind rpc for those utxos;
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
            ret = self.rpc('gettxout', [txo_hex, txo_idx, includeunconf])
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
                               'script': hextobin(ret['scriptPubKey']['hex'])}
                if includeconf:
                    result_dict['confirms'] = int(ret['confirmations'])
                result.append(result_dict)
        return result

    def estimate_fee_per_kb(self, N):
        if super().fee_per_kb_has_been_manually_set(N):
            # use the local bitcoin core relay fee as floor to avoid relay problems
            btc_relayfee = -1
            rpc_result = self.rpc('getnetworkinfo', None)
            btc_relayfee = rpc_result.get('relayfee', btc_relayfee)
            if btc_relayfee > 0:
                relayfee_in_sat = int(Decimal(1e8) * Decimal(btc_relayfee))
                log.info("Using this min relay fee as tx fee floor: " +
                    btc.fee_per_kb_to_str(relayfee_in_sat))
                return int(max(relayfee_in_sat, random.uniform(N * float(0.8), N * float(1.2))))
            else:   # cannot get valid relayfee: fall back to 1000 sat/kbyte
                log.info("Using this min relay fee as tx fee floor " +
                    "(fallback): " + btc.fee_per_kb_to_str(1000))
                return int(max(1000, random.uniform(N * float(0.8), N * float(1.2))))

        # Special bitcoin core case: sometimes the highest priority
        # cannot be estimated in that case the 2nd highest priority
        # should be used instead of falling back to hardcoded values
        tries = 2 if N == 1 else 1

        estimate = -1
        retval = -1
        for i in range(tries):
            rpc_result = self.rpc('estimatesmartfee', [N + i])
            estimate = rpc_result.get('feerate', estimate)
            if estimate > 0:
                break
        else:  # estimate <= 0
            retval = 10000

        if retval == -1:
            retval = int(Decimal(1e8) * Decimal(estimate))
        log.info("Using tx fee: " + btc.fee_per_kb_to_str(retval))
        return retval

    def get_current_block_height(self):
        return self.rpc("getblockcount", [])

    def get_best_block_hash(self):
        return self.rpc('getbestblockhash', [])

    def get_block_time(self, blockhash):
        try:
            # works with pruning enabled, but only after v0.12
            return self.rpc('getblockheader', [blockhash])['time']
        except JsonRpcError:
            return self.rpc('getblock', [blockhash])['time']

    def get_tx_merkle_branch(self, txid, blockhash=None):
        if not blockhash:
            tx = self.rpc("gettransaction", [txid])
            if tx["confirmations"] < 1:
                raise ValueError("Transaction not in block")
            blockhash = tx["blockhash"]
        try:
            core_proof = self.rpc("gettxoutproof", [[txid], blockhash])
        except JsonRpcError:
            raise ValueError("Block containing transaction is pruned")
        return self.core_proof_to_merkle_branch(core_proof)

    def core_proof_to_merkle_branch(self, core_proof):
        core_proof = binascii.unhexlify(core_proof)
        #first 80 bytes of a proof given by core are just a block header
        #so we can save space by replacing it with a 4-byte block height
        return core_proof[80:]

    def verify_tx_merkle_branch(self, txid, block_height, merkle_branch):
        block_hash = self.rpc("getblockhash", [block_height])
        core_proof = self.rpc("getblockheader", [block_hash, False]) + \
            binascii.hexlify(merkle_branch).decode()
        ret = self.rpc("verifytxoutproof", [core_proof])
        return len(ret) == 1 and ret[0] == txid

class RegtestBitcoinCoreMixin():
    """
    This Mixin provides helper functions that are used in Interface classes
    requiring some functionality only useful on the regtest network.
    """
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

class BitcoinCoreNoHistoryInterface(BitcoinCoreInterface, RegtestBitcoinCoreMixin):

    def __init__(self, jsonRpc, network):
        super().__init__(jsonRpc, network)
        self.import_addresses_call_count = 0
        self.wallet_name = None
        self.scan_result = None

    def import_addresses_if_needed(self, addresses, wallet_name):
        self.import_addresses_call_count += 1
        if self.import_addresses_call_count == 1:
            self.wallet_name = wallet_name
            addr_list = ["addr(" + a + ")" for a in addresses]
            log.debug("Starting scan of UTXO set")
            st = time.time()
            try:
                self.rpc("scantxoutset", ["abort", []])
                self.scan_result = self.rpc("scantxoutset", ["start",
                    addr_list])
            except JsonRpcError as e:
                raise RuntimeError("Bitcoin Core 0.17.0 or higher required "
                    + "for no-history sync (" + repr(e) + ")")
            et = time.time()
            log.debug("UTXO set scan took " + str(et - st) + "sec")
        elif self.import_addresses_call_count > 4:
            #called twice for the first call of sync_addresses(), then two
            # more times for the second call. the second call happens because
            # sync_addresses() re-runs in order to have gap_limit new addresses
            assert False
        return False

    def _get_addr_from_desc(self, desc_str):
        #example
        #'desc': 'addr(2MvAfRVvRAeBS18NT7mKVc1gFim169GkFC5)#h5yn9eq4',
        assert desc_str.startswith("addr(")
        return desc_str[5:desc_str.find(")")]

    def _yield_transactions(self, wallet_name):
        for u in self.scan_result["unspents"]:
            tx = {"category": "receive", "address":
                self._get_addr_from_desc(u["desc"])}
            yield tx

    def list_transactions(self, num):
        return []

    def rpc(self, method, args):
        if method == "listaddressgroupings":
            raise RuntimeError("default sync not supported by bitcoin-rpc-nohistory, use --recoversync")
        elif method == "listunspent":
            minconf = 0 if len(args) < 1 else args[0]
            maxconf = 9999999 if len(args) < 2 else args[1]
            return [{
                "address": self._get_addr_from_desc(u["desc"]),
                "label": self.wallet_name,
                "height": u["height"],
                "txid": u["txid"],
                "vout": u["vout"],
                "scriptPubKey": u["scriptPubKey"],
                "amount": u["amount"]
                } for u in self.scan_result["unspents"]]
        else:
            return super().rpc(method, args)

    def set_wallet_no_history(self, wallet):
        #make wallet-tool not display any new addresses
        #because no-history cant tell if an address is used and empty
        #so this is necessary to avoid address reuse
        wallet.gap_limit = 0
        #disable generating change addresses, also because cant guarantee
        # avoidance of address reuse
        wallet.disable_new_scripts = True

    def tick_forward_chain(self, n):
        self.destn_addr = self.rpc("getnewaddress", [])
        super().tick_forward_chain(n)

# class for regtest chain access
# running on local daemon. Only
# to be instantiated after network is up
# with > 100 blocks.
class RegtestBitcoinCoreInterface(BitcoinCoreInterface, RegtestBitcoinCoreMixin): #pragma: no cover

    def __init__(self, jsonRpc):
        super().__init__(jsonRpc, 'regtest')
        self.pushtx_failure_prob = 0
        self.tick_forward_chain_interval = -1
        self.absurd_fees = False
        self.simulating = False
        self.shutdown_signal = False
        self.destn_addr = self.rpc("getnewaddress", [])

    def estimate_fee_per_kb(self, N):
        if not self.absurd_fees:
            return super().estimate_fee_per_kb(N)
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

        ret = super().pushtx(txhex)
        if not self.simulating and self.tick_forward_chain_interval > 0:
            log.debug('will call tfc after ' + str(self.tick_forward_chain_interval) + ' seconds.')
            reactor.callLater(self.tick_forward_chain_interval,
                              self.tick_forward_chain, 1)
        return ret

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
