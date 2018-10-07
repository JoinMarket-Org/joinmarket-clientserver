import btc
import json
import Queue
import os
import pprint
import random
import socket
import threading
import ssl
import binascii
from twisted.internet.protocol import ClientFactory
from twisted.internet.ssl import ClientContextFactory
from twisted.protocols.basic import LineReceiver
from twisted.internet import reactor, task, defer
from .blockchaininterface import BlockchainInterface
from .configure import get_p2sh_vbyte
from .support import get_log
from .electrum_data import get_default_servers, set_electrum_testnet,\
    DEFAULT_PROTO

log = get_log()

class ElectrumConnectionError(Exception):
    pass

class TxElectrumClientProtocol(LineReceiver):
    #map deferreds to msgids to correctly link response with request
    deferreds = {}
    delimiter = "\n"

    def __init__(self, factory):
        self.factory = factory

    def connectionMade(self):
        log.debug('connection to Electrum succesful')
        self.msg_id = 0
        if self.factory.bci.wallet:
            #Use connectionMade as a trigger to start wallet sync,
            #if the reactor start happened after the call to wallet sync
            #(in Qt, the reactor starts before wallet sync, so we make
            #this call manually instead).
            self.factory.bci.sync_addresses(self.factory.bci.wallet)
        #these server calls must always be done to keep the connection open
        self.start_ping()
        self.call_server_method('blockchain.numblocks.subscribe')

    def start_ping(self):
        pingloop = task.LoopingCall(self.ping)
        pingloop.start(60.0)

    def ping(self):
        #We dont bother tracking response to this;
        #just for keeping connection active
        self.call_server_method('server.version')

    def send_json(self, json_data):
        data = json.dumps(json_data).encode()
        self.sendLine(data)

    def call_server_method(self, method, params=[]):
        self.msg_id = self.msg_id + 1
        current_id = self.msg_id
        self.deferreds[current_id] = defer.Deferred()
        method_dict = {
            'id': current_id,
            'method': method,
            'params': params
        }
        self.send_json(method_dict)
        return self.deferreds[current_id]

    def lineReceived(self, line):
        try:
            parsed = json.loads(line)
            msgid = parsed['id']
            linked_deferred = self.deferreds[msgid]
        except:
            log.debug("Ignored response from Electrum server: " + str(line))
            return
        linked_deferred.callback(parsed)

class TxElectrumClientProtocolFactory(ClientFactory):

    def __init__(self, bci):
        self.bci = bci
    def buildProtocol(self,addr):
        self.client = TxElectrumClientProtocol(self)
        return self.client

    def clientConnectionLost(self, connector, reason):
        log.debug('Electrum connection lost, reason: ' + str(reason))
        self.bci.start_electrum_proto(None)

    def clientConnectionFailed(self, connector, reason):
        print('connection failed')
        self.bci.start_electrum_proto(None)

class ElectrumConn(threading.Thread):

    def __init__(self, server, port, proto):
        threading.Thread.__init__(self)
        self.daemon = True
        self.msg_id = 0
        self.RetQueue = Queue.Queue()
        try:
            if proto == 't':
                self.s = socket.create_connection((server,int(port)))
            elif proto == 's':
                self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                #reads are sometimes quite slow, so conservative, but we must
                #time out a completely hanging connection.
                self.raw_socket.settimeout(60)
                self.raw_socket.connect((server, int(port)))
                self.s = ssl.wrap_socket(self.raw_socket)
            else:
                #Wrong proto is not accepted for restarts
                log.error("Failure to connect to Electrum, "
                                "protocol must be TCP or SSL.")
                os._exit(1)
        except Exception as e:
            log.error("Error connecting to electrum server; trying again.")
            raise ElectrumConnectionError
        self.ping()

    def run(self):
        while True:
            all_data = None
            while True:
                data = self.s.recv(1024)
                if data is None:
                    continue
                if all_data is None:
                    all_data = data
                else:
                    all_data = all_data + data
                if '\n' in all_data:
                    break
            data_json = json.loads(all_data[:-1].decode())
            self.RetQueue.put(data_json)

    def ping(self):
        log.debug('Sending Electrum server ping')
        self.send_json({'id':0,'method':'server.version','params':[]})
        t = threading.Timer(60, self.ping)
        t.daemon = True
        t.start()

    def send_json(self, json_data):
        data = json.dumps(json_data).encode()
        self.s.send(data + b'\n')

    def call_server_method(self, method, params=[]):
        self.msg_id = self.msg_id + 1
        current_id = self.msg_id
        method_dict = {
            'id': current_id,
            'method': method,
            'params': params
        }
        self.send_json(method_dict)
        while True:
            ret_data = self.RetQueue.get()
            if ret_data.get('id', None) == current_id:
                return ret_data
            else:
                log.debug(json.dumps(ret_data))

class ElectrumInterface(BlockchainInterface):
    BATCH_SIZE = 8
    def __init__(self, testnet=False, electrum_server=None):
        self.synctype = "sync-only"
        if testnet:
            set_electrum_testnet()
        self.start_electrum_proto()
        self.electrum_conn = None
        self.start_connection_thread()
        #task.LoopingCall objects that track transactions, keyed by txids.
        #Format: {"txid": (loop, unconfirmed true/false, confirmed true/false,
        #spent true/false), ..}
        self.tx_watcher_loops = {}
        self.wallet = None
        self.wallet_synced = False

    def start_electrum_proto(self, electrum_server=None):
        self.server, self.port = self.get_server(electrum_server)
        self.factory = TxElectrumClientProtocolFactory(self)
        if DEFAULT_PROTO == 's':
            ctx = ClientContextFactory()
            reactor.connectSSL(self.server, self.port, self.factory, ctx)
        elif DEFAULT_PROTO == 't':
            reactor.connectTCP(self.server, self.port, self.factory)
        else:
            raise Exception("Unrecognized connection protocol to Electrum, "
                            "should be one of 't' or 's' (TCP or SSL), "
                            "critical error, quitting.")

    def start_connection_thread(self):
        """Initiate a thread that serves blocking, single
        calls to an Electrum server. This won't usually be the
        same server that's used to do sync (which, confusingly,
        is asynchronous).
        """
        try:
            s, p = self.get_server(None)
            self.electrum_conn = ElectrumConn(s, p, DEFAULT_PROTO)
        except ElectrumConnectionError:
            reactor.callLater(1.0, self.start_connection_thread)
            return
        self.electrum_conn.start()
        #used to hold open server conn
        self.electrum_conn.call_server_method('blockchain.numblocks.subscribe')

    def sync_wallet(self, wallet, fast=False, restart_cb=False):
        """This triggers the start of syncing, wiping temporary state
        and starting the reactor for wallet-tool runs. The 'fast'
        and 'restart_cb' parameters are ignored and included only
        for compatibility; they are both only used by Core.
        """
        self.wallet = wallet
        #wipe the temporary cache of address histories
        self.temp_addr_history = {}
        #mark as not currently synced
        self.wallet_synced = False
        if self.synctype == "sync-only":
            reactor.run()

    def get_server(self, electrum_server):
        if not electrum_server:
            while True:
                electrum_server = random.choice(get_default_servers().keys())
                if DEFAULT_PROTO in get_default_servers()[electrum_server]:
                    break
        s = electrum_server
        p = int(get_default_servers()[electrum_server][DEFAULT_PROTO])
        log.debug('Trying to connect to Electrum server: ' + str(electrum_server))
        return (s, p)

    def get_from_electrum(self, method, params=[], blocking=False):
        params = [params] if type(params) is not list else params
        if blocking:
            return self.electrum_conn.call_server_method(method, params)
        else:
            return self.factory.client.call_server_method(method, params)

    def sync_addresses(self, wallet, restart_cb=None):
        if not self.electrum_conn:
            #wait until we have some connection up before starting
            reactor.callLater(0.2, self.sync_addresses, wallet, restart_cb)
            return
        log.debug("downloading wallet history from Electrum server ...")
        for mixdepth in range(wallet.max_mixdepth + 1):
            for forchange in [0, 1]:
                #start from a clean index
                wallet.set_next_index(mixdepth, forchange, 0)
                self.synchronize_batch(wallet, mixdepth, forchange, 0)

    def synchronize_batch(self, wallet, mixdepth, forchange, start_index):
        #for debugging only:
        #log.debug("Syncing address batch, m, fc, i: " + ",".join(
        #    [str(x) for x in [mixdepth, forchange, start_index]]))
        if mixdepth not in self.temp_addr_history:
            self.temp_addr_history[mixdepth] = {}
        if forchange not in self.temp_addr_history[mixdepth]:
            self.temp_addr_history[mixdepth][forchange] = {"finished": False}
        for i in range(start_index, start_index + self.BATCH_SIZE):
            #get_new_addr is OK here, as guaranteed to be sequential *on this branch*
            a = wallet.get_new_addr(mixdepth, forchange)
            d = self.get_from_electrum('blockchain.address.get_history', a)
            #makes sure entries in temporary address history are ready
            #to be accessed.
            if i not in self.temp_addr_history[mixdepth][forchange]:
                self.temp_addr_history[mixdepth][forchange][i] = {'synced': False,
                                                          'addr': a,
                                                          'used': False}
            d.addCallback(self.process_address_history, wallet,
                          mixdepth, forchange, i, a, start_index)

    def process_address_history(self, history, wallet, mixdepth, forchange, i,
                                addr, start_index):
        """Given the history data for an address from Electrum, update the current view
        of the wallet's usage at mixdepth mixdepth and account forchange, address addr at
        index i. Once all addresses from index start_index to start_index + self.BATCH_SIZE
        have been thus updated, trigger either continuation to the next batch, or, if
        conditions are fulfilled, end syncing for this (mixdepth, forchange) branch, and
        if all such branches are finished, proceed to the sync_unspent step.
        """
        tah = self.temp_addr_history[mixdepth][forchange]
        if len(history['result']) > 0:
            tah[i]['used'] = True
        tah[i]['synced'] = True
        #Having updated this specific record, check if the entire batch from start_index
        #has been synchronized
        if all([tah[j]['synced'] for j in range(start_index, start_index + self.BATCH_SIZE)]):
            #check if unused goes back as much as gaplimit *and* we are ahead of any
            #existing index_cache from the wallet file; if both true, end, else, continue
            #to next batch
            if all([tah[j]['used'] is False for j in range(
                start_index + self.BATCH_SIZE - wallet.gap_limit,
                start_index + self.BATCH_SIZE)]):
                last_used_addr = None
                #to find last used, note that it may be in the *previous* batch;
                #may as well just search from the start, since it takes no time.
                for j in range(start_index + self.BATCH_SIZE):
                    if tah[j]['used']:
                        last_used_addr = tah[j]['addr']
                if last_used_addr:
                    wallet.set_next_index(
                        mixdepth, forchange,
                        wallet.get_next_unused_index(mixdepth, forchange))
                else:
                    wallet.set_next_index(mixdepth, forchange, 0)
                tah["finished"] = True
                #check if all branches are finished to trigger next stage of sync.
                addr_sync_complete = True
                for m in range(wallet.max_mix_depth):
                    for fc in [0, 1]:
                        if not self.temp_addr_history[m][fc]["finished"]:
                            addr_sync_complete = False
                if addr_sync_complete:
                    self.sync_unspent(wallet)
            else:
                #continue search forwards on this branch
                self.synchronize_batch(wallet, mixdepth, forchange, start_index + self.BATCH_SIZE)

    def sync_unspent(self, wallet):
        # finds utxos in the wallet
        wallet.reset_utxos()
        #Prepare list of all used addresses
        addrs = set()
        for m in range(wallet.max_mixdepth):
            for fc in [0, 1]:
                branch_list = []
                for k, v in self.temp_addr_history[m][fc].iteritems():
                    if k == "finished":
                        continue
                    if v["used"]:
                        branch_list.append(v["addr"])
                addrs.update(branch_list)
        if len(addrs) == 0:
            log.debug('no tx used')
            self.wallet_synced = True
            if self.synctype == 'sync-only':
                reactor.stop()
            return
        #make sure to add any addresses during the run (a subset of those
        #added to the address cache)
        for md in range(wallet.max_mixdepth):
            for internal in (True, False):
                for index in range(wallet.get_next_unused_index(md, internal)):
                    addrs.add(wallet.get_addr(md, internal, index))
            for path in wallet.yield_imported_paths(md):
                addrs.add(wallet.get_addr_path(path))

        self.listunspent_calls = len(addrs)
        for a in addrs:
            # FIXME: update to protocol version 1.1 and use scripthash instead
            script = wallet.addr_to_script(a)
            d = self.get_from_electrum('blockchain.address.listunspent', a)
            d.addCallback(self.process_listunspent_data, wallet, script)

    def process_listunspent_data(self, unspent_info, wallet, script):
        res = unspent_info['result']
        for u in res:
            txid = binascii.unhexlify(u['tx_hash'])
            wallet.add_utxo(txid, int(u['tx_pos']), script, int(u['value']))

        self.listunspent_calls -= 1
        if self.listunspent_calls == 0:
            self.wallet_synced = True
            if self.synctype == "sync-only":
                reactor.stop()

    def pushtx(self, txhex):
        brcst_res = self.get_from_electrum('blockchain.transaction.broadcast',
                                           txhex, blocking=True)
        brcst_status = brcst_res['result']
        if isinstance(brcst_status, str) and len(brcst_status) == 64:
            return (True, brcst_status)
        log.debug(brcst_status)
        return (False, None)

    def query_utxo_set(self, txout, includeconf=False):
        self.current_height = self.get_from_electrum(
            "blockchain.numblocks.subscribe", blocking=True)['result']
        if not isinstance(txout, list):
            txout = [txout]
        utxos = [[t[:64],int(t[65:])] for t in txout]
        result = []
        for ut in utxos:
            address = self.get_from_electrum("blockchain.utxo.get_address",
                                             ut, blocking=True)['result']
            utxo_info = self.get_from_electrum("blockchain.address.listunspent",
                                               address, blocking=True)['result']
            utxo = None
            for u in utxo_info:
                if u['tx_hash'] == ut[0] and u['tx_pos'] == ut[1]:
                    utxo = u
            if utxo is None:
                result.append(None)
            else:
                r = {
                    'value': utxo['value'],
                    'address': address,
                    'script': btc.address_to_script(address)
                }
                if includeconf:
                    if int(utxo['height']) in [0, -1]:
                        #-1 means unconfirmed inputs
                        r['confirms'] = 0
                    else:
                        #+1 because if current height = tx height, that's 1 conf
                        r['confirms'] = int(self.current_height) - int(
                            utxo['height']) + 1
                result.append(r)
        return result

    def estimate_fee_per_kb(self, N):
        if super(ElectrumInterface, self).fee_per_kb_has_been_manually_set(N):
            return int(random.uniform(N * float(0.8), N * float(1.2)))
        fee_info = self.get_from_electrum('blockchain.estimatefee', N, blocking=True)
        print('got fee info result: ' + str(fee_info))
        fee = fee_info.get('result')
        fee_per_kb_sat = int(float(fee) * 100000000)
        return fee_per_kb_sat

    def outputs_watcher(self, wallet_name, notifyaddr, tx_output_set,
                        unconfirmfun, confirmfun, timeoutfun):
        """Given a key for the watcher loop (notifyaddr), a wallet name (account),
        a set of outputs, and unconfirm, confirm and timeout callbacks,
        check to see if a transaction matching that output set has appeared in
        the wallet. Call the callbacks and update the watcher loop state.
        End the loop when the confirmation has been seen (no spent monitoring here).
        """
        wl = self.tx_watcher_loops[notifyaddr]
        print('txoutset=' + pprint.pformat(tx_output_set))
        unconftx = self.get_from_electrum('blockchain.address.get_mempool',
                                          notifyaddr, blocking=True).get('result')
        unconftxs = set([str(t['tx_hash']) for t in unconftx])
        if len(unconftxs):
            txdatas = []
            for txid in unconftxs:
                txdatas.append({'id': txid,
                                'hex':str(self.get_from_electrum(
                                    'blockchain.transaction.get',txid,
                                    blocking=True).get('result'))})
            unconfirmed_txid = None
            for txdata in txdatas:
                txhex = txdata['hex']
                outs = set([(sv['script'], sv['value']) for sv in btc.deserialize(
                    txhex)['outs']])
                print('unconfirm query outs = ' + str(outs))
                if outs == tx_output_set:
                    unconfirmed_txid = txdata['id']
                    unconfirmed_txhex = txhex
                    break
            #call unconf callback if it was found in the mempool
            if unconfirmed_txid and not wl[1]:
                print("Tx: " + str(unconfirmed_txid) + " seen on network.")
                unconfirmfun(btc.deserialize(unconfirmed_txhex), unconfirmed_txid)
                wl[1] = True
                return

        conftx = self.get_from_electrum('blockchain.address.listunspent',
                                        notifyaddr, blocking=True).get('result')
        conftxs = set([str(t['tx_hash']) for t in conftx])
        if len(conftxs):
            txdatas = []
            for txid in conftxs:
                txdata = str(self.get_from_electrum('blockchain.transaction.get',
                                                    txid, blocking=True).get('result'))
                txdatas.append({'hex':txdata,'id':txid})
            confirmed_txid = None
            for txdata in txdatas:
                txhex = txdata['hex']
                outs = set([(sv['script'], sv['value']) for sv in btc.deserialize(
                    txhex)['outs']])
                print('confirm query outs = ' + str(outs))
                if outs == tx_output_set:
                    confirmed_txid = txdata['id']
                    confirmed_txhex = txhex
                    break
            if confirmed_txid and not wl[2]:
                confirmfun(btc.deserialize(confirmed_txhex), confirmed_txid, 1)
                wl[2] = True
                wl[0].stop()
                return

    def tx_watcher(self, txd, unconfirmfun, confirmfun, spentfun, c, n):
        """Called at a polling interval, checks if the given deserialized
        transaction (which must be fully signed) is (a) broadcast, (b) confirmed
        and (c) spent from. (c, n ignored in electrum version, just supports
        registering first confirmation).
        TODO: There is no handling of conflicts here.
        """
        txid = btc.txhash(btc.serialize(txd))
        wl = self.tx_watcher_loops[txid]
        #first check if in mempool (unconfirmed)
        #choose an output address for the query. Filter out
        #p2pkh addresses, assume p2sh (thus would fail to find tx on
        #some nonstandard script type)
        addr = None
        for i in range(len(txd['outs'])):
            if not btc.is_p2pkh_script(txd['outs'][i]['script']):
                addr = btc.script_to_address(txd['outs'][i]['script'], get_p2sh_vbyte())
                break
        if not addr:
            log.error("Failed to find any p2sh output, cannot be a standard "
                      "joinmarket transaction, fatal error!")
            reactor.stop()
            return
        unconftxs_res = self.get_from_electrum('blockchain.address.get_mempool',
                                              addr, blocking=True).get('result')
        unconftxs = [str(t['tx_hash']) for t in unconftxs_res]

        if not wl[1] and txid in unconftxs:
            print("Tx: " + str(txid) + " seen on network.")
            unconfirmfun(txd, txid)
            wl[1] = True
            return
        conftx = self.get_from_electrum('blockchain.address.listunspent',
                                        addr, blocking=True).get('result')
        conftxs = [str(t['tx_hash']) for t in conftx]
        if not wl[2] and len(conftxs) and txid in conftxs:
            print("Tx: " + str(txid) + " is confirmed.")
            confirmfun(txd, txid, 1)
            wl[2] = True
            #Note we do not stop the monitoring loop when
            #confirmations occur, since we are also monitoring for spending.
            return
        if not spentfun or wl[3]:
            return

