import btc
import json
import Queue
import os
import pprint
import random
import socket
import threading
import time
import sys
from twisted.python.log import startLogging
from twisted.internet.protocol import ClientFactory, Protocol
from twisted.protocols.basic import LineReceiver
from twisted.internet import reactor, task, defer
from .blockchaininterface import BlockchainInterface, is_index_ahead_of_cache
from .configure import get_p2sh_vbyte
from .support import get_log

log = get_log()

# Default server list from electrum client
# https://github.com/spesmilo/electrum, file https://github.com/spesmilo/electrum/blob/7dbd612d5dad13cd6f1c0df32534a578bad331ad/lib/servers.json
DEFAULT_PORTS = {'t':'50001', 's':'50002'}

DEFAULT_SERVERS = {
    "E-X.not.fyi": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "ELECTRUMX.not.fyi": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "ELEX01.blackpole.online": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "VPS.hsmiths.com": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "bitcoin.freedomnode.com": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "btc.smsys.me": {
        "pruning": "-",
        "s": "995",
        "version": "1.1"
    },
    "currentlane.lovebitco.in": {
        "pruning": "-",
        "t": "50001",
        "version": "1.1"
    },
    "daedalus.bauerj.eu": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "de01.hamster.science": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "ecdsa.net": {
        "pruning": "-",
        "s": "110",
        "t": "50001",
        "version": "1.1"
    },
    "elec.luggs.co": {
        "pruning": "-",
        "s": "443",
        "version": "1.1"
    },
    "electrum.akinbo.org": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrum.antumbra.se": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrum.be": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrum.coinucopia.io": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrum.cutie.ga": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrum.festivaldelhumor.org": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrum.hsmiths.com": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrum.qtornado.com": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrum.vom-stausee.de": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrum3.hachre.de": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrumx.bot.nu": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrumx.westeurope.cloudapp.azure.com": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "elx01.knas.systems": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "ex-btc.server-on.net": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "helicarrier.bauerj.eu": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "mooo.not.fyi": {
        "pruning": "-",
        "s": "50012",
        "t": "50011",
        "version": "1.1"
    },
    "ndnd.selfhost.eu": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "node.arihanc.com": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "node.xbt.eu": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "node1.volatilevictory.com": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "noserver4u.de": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "qmebr.spdns.org": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "raspi.hsmiths.com": {
        "pruning": "-",
        "s": "51002",
        "t": "51001",
        "version": "1.1"
    },
    "s2.noip.pl": {
        "pruning": "-",
        "s": "50102",
        "version": "1.1"
    },
    "s5.noip.pl": {
        "pruning": "-",
        "s": "50105",
        "version": "1.1"
    },
    "songbird.bauerj.eu": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "us.electrum.be": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "us01.hamster.science": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    }
}

def set_electrum_testnet():
    global DEFAULT_PORTS, DEFAULT_SERVERS
    DEFAULT_PORTS = {'t':'51001', 's':'51002'}
    DEFAULT_SERVERS = {
        'testnetnode.arihanc.com': {'t':'51001', 's':'51002'},
        'testnet1.bauerj.eu': {'t':'51001', 's':'51002'},
        '14.3.140.101': {'t':'51001', 's':'51002'},
        'testnet.hsmiths.com': {'t':'53011', 's':'53012'},
        'electrum.akinbo.org': {'t':'51001', 's':'51002'},
        'ELEX05.blackpole.online': {'t':'52011', 's':'52002'},}
        #Replace with for regtest:
        #'localhost': {'t': '50001', 's': '51002'},}

class TxElectrumClientProtocol(LineReceiver):
    #map deferreds to msgids to correctly link response with request
    deferreds = {}
    delimiter = "\n"

    def __init__(self, factory):
        self.factory = factory

    def connectionMade(self):
        print('connection to Electrum made')
        self.msg_id = 0
        self.factory.bci.sync_addresses(self.factory.bci.wallet)
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

    def clientConnectionLost(self,connector,reason):
        print('connection lost')

    def clientConnectionFailed(self,connector,reason):
        print('connection failed')

class ElectrumConn(threading.Thread):

    def __init__(self, server, port):
        threading.Thread.__init__(self)
        self.daemon = True
        self.msg_id = 0
        self.RetQueue = Queue.Queue()
        try:
            self.s = socket.create_connection((server,int(port)))
        except Exception as e:
            log.error("Error connecting to electrum server. "
                      "Try again to connect to a random server or set a "
                      "server in the config.")
            os._exit(1)
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
        self.server, self.port = self.get_server(electrum_server)
        self.factory = TxElectrumClientProtocolFactory(self)
        reactor.connectTCP(self.server, self.port, self.factory)
        #start the thread for blocking calls during execution
        self.electrum_conn = ElectrumConn(self.server, self.port)
        self.electrum_conn.start()
        #used to hold open server conn
        self.electrum_conn.call_server_method('blockchain.numblocks.subscribe')
        #task.LoopingCall objects that track transactions, keyed by txids.
        #Format: {"txid": (loop, unconfirmed true/false, confirmed true/false,
        #spent true/false), ..}
        self.tx_watcher_loops = {}
        self.wallet_synced = False

    def sync_wallet(self, wallet, restart_cb=False):
        self.wallet = wallet
        #wipe the temporary cache of address histories
        self.temp_addr_history = {}
        if self.synctype == "sync-only":
            startLogging(sys.stdout)
            reactor.run()

    def get_server(self, electrum_server):
        if not electrum_server:
            electrum_server = random.choice(DEFAULT_SERVERS.keys())
        s = electrum_server
        p = int(DEFAULT_SERVERS[electrum_server]['t'])
        print('Trying to connect to Electrum server: ' + str(electrum_server))
        return (s, p)

    def get_from_electrum(self, method, params=[], blocking=False):
        params = [params] if type(params) is not list else params
        if blocking:
            return self.electrum_conn.call_server_method(method, params)
        else:
            return self.factory.client.call_server_method(method, params)

    def sync_addresses(self, wallet, restart_cb=None):
        log.debug("downloading wallet history from Electrum server ...")
        for mixdepth in range(wallet.max_mix_depth):
            for forchange in [0, 1]:
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
            d.addCallback(self.process_address_history, wallet,
                          mixdepth, forchange, i, a, start_index)
            #makes sure entries in temporary address history are ready
            #to be accessed.
            if i not in self.temp_addr_history[mixdepth][forchange]:
                self.temp_addr_history[mixdepth][forchange][i] = {'synced': False,
                                                                  'addr': a,
                                                                  'used': False}

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
        if all([tah[i]['synced'] for i in range(start_index, start_index + self.BATCH_SIZE)]):
            #check if unused goes back as much as gaplimit; if so, end, else, continue
            #to next batch
            if all([tah[i]['used'] is False for i in range(
                start_index+self.BATCH_SIZE-wallet.gaplimit,
                start_index+self.BATCH_SIZE)]):
                last_used_addr = None
                #to find last used, note that it may be in the *previous* batch;
                #may as well just search from the start, since it takes no time.
                for i in range(start_index + self.BATCH_SIZE):
                    if tah[i]['used']:
                        last_used_addr = tah[i]['addr']
                if last_used_addr:
                    wallet.index[mixdepth][forchange] = wallet.addr_cache[last_used_addr][2] + 1
                else:
                    wallet.index[mixdepth][forchange] = 0
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
        wallet.unspent = {}
        #Prepare list of all used addresses
        addrs = []
        for m in range(wallet.max_mix_depth):
            for fc in [0, 1]:
                branch_list = []
                for k, v in self.temp_addr_history[m][fc].iteritems():
                    if k == "finished":
                        continue
                    if v["used"]:
                        branch_list.append(v["addr"])
                addrs.extend(branch_list)
        if len(addrs) == 0:
            log.debug('no tx used')
            if self.synctype == 'sync-only':
                reactor.stop()
            return
        #make sure to add any addresses during the run (a subset of those
        #added to the address cache)
        addrs = list(set(self.wallet.addr_cache.keys()).union(set(addrs)))
        self.listunspent_calls = 0
        for a in addrs:
            d = self.get_from_electrum('blockchain.address.listunspent', a)
            d.addCallback(self.process_listunspent_data, wallet, a, len(addrs))

    def process_listunspent_data(self, unspent_info, wallet, address, n):
        self.listunspent_calls += 1
        res = unspent_info['result']
        for u in res:
            wallet.unspent[str(u['tx_hash']) + ':' + str(
                u['tx_pos'])] = {'address': address, 'value': int(u['value'])}
        if self.listunspent_calls == n:
            for u in wallet.spent_utxos:
                wallet.unspent.pop(u, None)
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
                raise Exception("UTXO Not Found")
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
        print("N is: " + str(N))
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

