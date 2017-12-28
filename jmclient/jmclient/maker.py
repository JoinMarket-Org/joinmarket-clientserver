#! /usr/bin/env python
from __future__ import print_function

import base64
import pprint
import random
import sys
import time
import copy

from jmclient import btc
from jmclient.configure import jm_single, get_p2pk_vbyte, get_p2sh_vbyte
from jmbase.support import get_log
from jmclient.support import (calc_cj_fee)
from jmclient.wallet import estimate_tx_fee
from jmclient.podle import (generate_podle, get_podle_commitments, verify_podle,
                                    PoDLE, PoDLEError, generate_podle_error_string)
from twisted.internet import task
jlog = get_log()

class Maker(object):
    def __init__(self, wallet):
        self.active_orders = {}
        self.wallet = wallet
        self.nextoid = -1
        self.offerlist = None
        self.sync_wait_loop = task.LoopingCall(self.try_to_create_my_orders)
        self.sync_wait_loop.start(2.0)
        self.aborted = False

    def try_to_create_my_orders(self):
        if not jm_single().bc_interface.wallet_synced:
            return
        self.offerlist = self.create_my_orders()
        self.sync_wait_loop.stop()
        if not self.offerlist:
            jlog.info("Failed to create offers, giving up.")
            sys.exit(0)

    def on_auth_received(self, nick, offer, commitment, cr, amount, kphex):
        """Receives data on proposed transaction offer from daemon, verifies
        commitment, returns necessary data to send ioauth message (utxos etc)
        """
        #deserialize the commitment revelation
        cr_dict = PoDLE.deserialize_revelation(cr)
        #check the validity of the proof of discrete log equivalence
        tries = jm_single().config.getint("POLICY", "taker_utxo_retries")
        def reject(msg):
            jlog.info("Counterparty commitment not accepted, reason: " + msg)
            return (False,)
        if not verify_podle(str(cr_dict['P']), str(cr_dict['P2']), str(cr_dict['sig']),
                                str(cr_dict['e']), str(commitment),
                                index_range=range(tries)):
            reason = "verify_podle failed"
            return reject(reason)
        #finally, check that the proffered utxo is real, old enough, large enough,
        #and corresponds to the pubkey
        res = jm_single().bc_interface.query_utxo_set([cr_dict['utxo']],
                                                      includeconf=True)
        if len(res) != 1 or not res[0]:
            reason = "authorizing utxo is not valid"
            return reject(reason)
        age = jm_single().config.getint("POLICY", "taker_utxo_age")
        if res[0]['confirms'] < age:
            reason = "commitment utxo not old enough: " + str(res[0]['confirms'])
            return reject(reason)
        reqd_amt = int(amount * jm_single().config.getint(
            "POLICY", "taker_utxo_amtpercent") / 100.0)
        if res[0]['value'] < reqd_amt:
            reason = "commitment utxo too small: " + str(res[0]['value'])
            return reject(reason)
        if res[0]['address'] != btc.pubkey_to_p2sh_p2wpkh_address(cr_dict['P'],
                                                      self.wallet.get_vbyte()):
            reason = "Invalid podle pubkey: " + str(cr_dict['P'])
            return reject(reason)

        # authorisation of taker passed
        #Find utxos for the transaction now:
        utxos, cj_addr, change_addr = self.oid_to_order(offer, amount)
        if not utxos:
            #could not find funds
            return (False,)
        self.wallet.update_cache_index()
        # Construct data for auth request back to taker.
        # Need to choose an input utxo pubkey to sign with
        # (no longer using the coinjoin pubkey from 0.2.0)
        # Just choose the first utxo in self.utxos and retrieve key from wallet.
        auth_address = utxos[list(utxos)[0]]['address']
        auth_key = self.wallet.get_key_from_addr(auth_address)
        auth_pub = btc.privtopub(auth_key)
        btc_sig = btc.ecdsa_sign(kphex, auth_key)
        return (True, utxos, auth_pub, cj_addr, change_addr, btc_sig)

    def on_tx_received(self, nick, txhex, offerinfo):
        try:
            tx = btc.deserialize(txhex)
        except IndexError as e:
            return (False, 'malformed txhex. ' + repr(e))
        jlog.info('obtained tx\n' + pprint.pformat(tx))
        goodtx, errmsg = self.verify_unsigned_tx(tx, offerinfo)
        if not goodtx:
            jlog.info('not a good tx, reason=' + errmsg)
            return (False, errmsg)
        jlog.info('goodtx')
        sigs = []
        utxos = offerinfo["utxos"]
        for index, ins in enumerate(tx['ins']):
            utxo = ins['outpoint']['hash'] + ':' + str(ins['outpoint']['index'])
            if utxo not in list(utxos):
                continue
            addr = utxos[utxo]['address']
            amount = utxos[utxo]["value"]
            txs = self.wallet.sign(txhex, index,
                                   self.wallet.get_key_from_addr(addr),
                                   amount=amount)
            sigmsg = btc.deserialize(txs)["ins"][index]["script"].decode("hex")
            if "txinwitness" in list(btc.deserialize(txs)["ins"][index]):
                #We prepend the witness data since we want (sig, pub, scriptCode);
                #also, the items in witness are not serialize_script-ed.
                sigmsg = "".join([btc.serialize_script_unit(
                    x.decode("hex")) for x in btc.deserialize(
                        txs)["ins"][index]["txinwitness"]]) + sigmsg
            sigs.append(base64.b64encode(sigmsg))
        return (True, sigs)

    def verify_unsigned_tx(self, txd, offerinfo):
        tx_utxo_set = set(ins['outpoint']['hash'] + ':' + str(
                ins['outpoint']['index']) for ins in txd['ins'])

        utxos = offerinfo["utxos"]
        cjaddr = offerinfo["cjaddr"]
        changeaddr = offerinfo["changeaddr"]
        amount = offerinfo["amount"]
        cjfee = offerinfo["offer"]["cjfee"]
        txfee = offerinfo["offer"]["txfee"]
        ordertype = offerinfo["offer"]["ordertype"]
        my_utxo_set = set(utxos.keys())
        if not tx_utxo_set.issuperset(my_utxo_set):
            return (False, 'my utxos are not contained')

        my_total_in = sum([va['value'] for va in utxos.values()])
        real_cjfee = calc_cj_fee(ordertype, cjfee, amount)
        expected_change_value = (my_total_in - amount - txfee + real_cjfee)
        jlog.info('potentially earned = {}'.format(real_cjfee - txfee))
        jlog.info('mycjaddr, mychange = {}, {}'.format(cjaddr, changeaddr))

        times_seen_cj_addr = 0
        times_seen_change_addr = 0
        for outs in txd['outs']:
            addr = btc.script_to_address(outs['script'], get_p2sh_vbyte())
            if addr == cjaddr:
                times_seen_cj_addr += 1
                if outs['value'] != amount:
                    return (False, 'Wrong cj_amount. I expect ' + str(amount))
            if addr == changeaddr:
                times_seen_change_addr += 1
                if outs['value'] != expected_change_value:
                    return (False, 'wrong change, i expect ' + str(
                        expected_change_value))
        if times_seen_cj_addr != 1 or times_seen_change_addr != 1:
            fmt = ('cj or change addr not in tx '
                   'outputs once, #cjaddr={}, #chaddr={}').format
            return (False, (fmt(times_seen_cj_addr, times_seen_change_addr)))
        return (True, None)

    def modify_orders(self, to_cancel, to_announce):
        jlog.info('modifying orders. to_cancel={}\nto_announce={}'.format(
                to_cancel, to_announce))
        for oid in to_cancel:
            order = [o for o in self.offerlist if o['oid'] == oid]
            if len(order) == 0:
                fmt = 'didnt cancel order which doesnt exist, oid={}'.format
                jlog.info(fmt(oid))
            self.offerlist.remove(order[0])
        if len(to_announce) > 0:
            for ann in to_announce:
                oldorder_s = [order for order in self.offerlist
                              if order['oid'] == ann['oid']]
                if len(oldorder_s) > 0:
                    self.offerlist.remove(oldorder_s[0])
            self.offerlist += to_announce
