import btc
import json
import Queue
import os
import pprint
import random
import socket
import threading
import time
from .blockchaininterface import BlockchainInterface, is_index_ahead_of_cache
from .configure import get_p2pk_vbyte
from .support import get_log

log = get_log()

# Default server list from electrum client
# https://github.com/spesmilo/electrum/blob/753a28b452dca1023fbde548469c36a34555dc95/lib/network.py
DEFAULT_ELECTRUM_SERVER_LIST = [
    'erbium1.sytes.net:50001',
    'ecdsa.net:50001',
    'electrum0.electricnewyear.net:50001',
    'VPS.hsmiths.com:50001',
    'ELECTRUM.jdubya.info:50001',
    'electrum.no-ip.org:50001',
    'us.electrum.be:50001',
    'bitcoins.sk:50001',
    'electrum.petrkr.net:50001',
    'electrum.dragonzone.net:50001',
    'Electrum.hsmiths.com:8080',
    'electrum3.hachre.de:50001',
    'elec.luggs.co:80',
    'btc.smsys.me:110',
    'electrum.online:50001',
]

class ElectrumInterface(BlockchainInterface):

    class ElectrumConn(threading.Thread):

        def __init__(self, electrum_server):
            threading.Thread.__init__(self)
            self.daemon = True
            self.msg_id = 0
            self.RetQueue = Queue.Queue()
            try:
                self.s = socket.create_connection((electrum_server.split(':')[0],
                                            int(electrum_server.split(':')[1])))
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
            log.debug('sending server ping')
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

    def __init__(self, testnet=False, electrum_server=None):
        super(ElectrumInterface, self).__init__()

        if testnet:
            raise Exception(NotImplemented)
        if electrum_server is None:
            electrum_server = random.choice(DEFAULT_ELECTRUM_SERVER_LIST)
        self.server_domain = electrum_server.split(':')[0]
        self.last_sync_unspent = 0
        self.electrum_conn = self.ElectrumConn(electrum_server)
        self.electrum_conn.start()
        # used to hold open server conn
        self.electrum_conn.call_server_method('blockchain.numblocks.subscribe')

    def get_from_electrum(self, method, params=[]):
        params = [params] if type(params) is not list else params
        return self.electrum_conn.call_server_method(method, params)

    def sync_addresses(self, wallet):
        log.debug("downloading wallet history from electrum server")
        for mix_depth in range(wallet.max_mix_depth):
            for forchange in [0, 1]:
                unused_addr_count = 0
                last_used_addr = ''
                while (unused_addr_count < wallet.gaplimit or not is_index_ahead_of_cache(wallet, mix_depth, forchange)):
                    addr = wallet.get_new_addr(mix_depth, forchange)
                    addr_hist_info = self.get_from_electrum('blockchain.address.get_history', addr)
                    if len(addr_hist_info['result']) > 0:
                        last_used_addr = addr
                        unused_addr_count = 0
                    else:
                        unused_addr_count += 1
                if last_used_addr == '':
                    wallet.index[mix_depth][forchange] = 0
                else:
                    wallet.index[mix_depth][forchange] = wallet.addr_cache[last_used_addr][2] + 1

    def sync_unspent(self, wallet):
        # finds utxos in the wallet
        st = time.time()
        # dont refresh unspent dict more often than 5 minutes
        rate_limit_time = 5 * 60
        if st - self.last_sync_unspent < rate_limit_time:
            log.debug('electrum sync_unspent() happened too recently (%dsec), skipping' % (st - self.last_sync_unspent))
            return
        wallet.unspent = {}
        addrs = wallet.addr_cache.keys()
        if len(addrs) == 0:
            log.debug('no tx used')
            return
        for a in addrs:
            unspent_info = self.get_from_electrum('blockchain.address.listunspent', a)
            res = unspent_info['result']
            for u in res:
                wallet.unspent[str(u['tx_hash']) + ':' + str(u['tx_pos'])] = {'address': a, 'value': int(u['value'])}
        for u in wallet.spent_utxos:
            wallet.unspent.pop(u, None)
        self.last_sync_unspent = time.time()
        log.debug('electrum sync_unspent took ' + str((self.last_sync_unspent - st)) + 'sec')

    def add_tx_notify(self, txd, unconfirmfun, confirmfun, notifyaddr):
        unconfirm_timeout = 10 * 60  # seconds
        unconfirm_poll_period = 5
        confirm_timeout = 2 * 60 * 60
        confirm_poll_period = 5 * 60

        class NotifyThread(threading.Thread):

            def __init__(self, blockchaininterface, txd, unconfirmfun, confirmfun):
                threading.Thread.__init__(self)
                self.daemon = True
                self.blockchaininterface = blockchaininterface
                self.unconfirmfun = unconfirmfun
                self.confirmfun = confirmfun
                self.tx_output_set = set([(sv['script'], sv['value']) for sv in txd['outs']])
                self.output_addresses = [btc.script_to_address(scrval[0], get_p2pk_vbyte()) for scrval in self.tx_output_set]
                log.debug('txoutset=' + pprint.pformat(self.tx_output_set))
                log.debug('outaddrs=' + ','.join(self.output_addresses))

            def run(self):
                st = int(time.time())
                unconfirmed_txid = None
                unconfirmed_txhex = None
                while not unconfirmed_txid:
                    time.sleep(unconfirm_poll_period)
                    if int(time.time()) - st > unconfirm_timeout:
                        log.debug('checking for unconfirmed tx timed out')
                        return
                    shared_txid = None
                    for a in self.output_addresses:
                        unconftx = self.blockchaininterface.get_from_electrum('blockchain.address.get_mempool', a).get('result')
                        unconftxs = set([str(t['tx_hash']) for t in unconftx])
                        if not shared_txid:
                            shared_txid = unconftxs
                        else:
                            shared_txid = shared_txid.intersection(unconftxs)
                    log.debug('sharedtxid = ' + str(shared_txid))
                    if len(shared_txid) == 0:
                        continue
                    data = []
                    for txid in shared_txid:
                        txdata = str(self.blockchaininterface.get_from_electrum('blockchain.transaction.get', txid).get('result'))
                        data.append({'hex':txdata,'id':txid})
                    for txdata in data:
                        txhex = txdata['hex']
                        outs = set([(sv['script'], sv['value']) for sv in btc.deserialize(txhex)['outs']])
                        log.debug('unconfirm query outs = ' + str(outs))
                        if outs == self.tx_output_set:
                            unconfirmed_txid = txdata['id']
                            unconfirmed_txhex = txhex
                            break
                self.unconfirmfun(btc.deserialize(unconfirmed_txhex), unconfirmed_txid)
                st = int(time.time())
                confirmed_txid = None
                confirmed_txhex = None
                while not confirmed_txid:
                    time.sleep(confirm_poll_period)
                    if int(time.time()) - st > confirm_timeout:
                        log.debug('checking for confirmed tx timed out')
                        return
                    shared_txid = None
                    for a in self.output_addresses:
                        conftx = self.blockchaininterface.get_from_electrum('blockchain.address.listunspent', a).get('result')
                        conftxs = set([str(t['tx_hash']) for t in conftx])
                        if not shared_txid:
                            shared_txid = conftxs
                        else:
                            shared_txid = shared_txid.intersection(conftxs)
                    log.debug('sharedtxid = ' + str(shared_txid))
                    if len(shared_txid) == 0:
                        continue
                    data = []
                    for txid in shared_txid:
                        txdata = str(self.blockchaininterface.get_from_electrum('blockchain.transaction.get', txid).get('result'))
                        data.append({'hex':txdata,'id':txid})
                    for txdata in data:
                        txhex = txdata['hex']
                        outs = set([(sv['script'], sv['value']) for sv in btc.deserialize(txhex)['outs']])
                        log.debug('confirm query outs = ' + str(outs))
                        if outs == self.tx_output_set:
                            confirmed_txid = txdata['id']
                            confirmed_txhex = txhex
                            break
                self.confirmfun(btc.deserialize(confirmed_txhex), confirmed_txid, 1)

        NotifyThread(self, txd, unconfirmfun, confirmfun).start()

    def pushtx(self, txhex):
        brcst_res = self.get_from_electrum('blockchain.transaction.broadcast', txhex)
        brcst_status = brcst_res['result']
        if isinstance(brcst_status, str) and len(brcst_status) == 64:
            return (True, brcst_status)
        log.debug(brcst_status)
        return (False, None)

    def query_utxo_set(self, txout, includeconf=False):
        self.current_height = self.get_from_electrum(
            "blockchain.numblocks.subscribe")['result']
        if not isinstance(txout, list):
            txout = [txout]
        utxos = [[t[:64],int(t[65:])] for t in txout]
        result = []
        for ut in utxos:
            address = self.get_from_electrum("blockchain.utxo.get_address", ut)['result']
            utxo_info = self.get_from_electrum("blockchain.address.listunspent", address)['result']
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
        fee_info = self.get_from_electrum('blockchain.estimatefee', N)
        fee = fee_info.get('result')
        fee_per_kb_sat = int(float(fee) * 100000000)
        return fee_per_kb_sat

