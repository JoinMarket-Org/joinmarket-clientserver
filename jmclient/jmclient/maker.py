#! /usr/bin/env python
import base64
import pprint
import random
import sys
import abc

import jmbitcoin as btc
from jmbase import bintohex, hexbin, get_log, EXIT_SUCCESS, EXIT_FAILURE
from jmclient.wallet import estimate_tx_fee, compute_tx_locktime
from jmclient.wallet_service import WalletService
from jmclient.configure import jm_single
from jmclient.support import calc_cj_fee, select_one_utxo
from jmclient.podle import verify_podle, PoDLE, PoDLEError
from twisted.internet import task, reactor
from .cryptoengine import EngineError

jlog = get_log()

class Maker(object):
    def __init__(self, wallet_service):
        self.active_orders = {}
        assert isinstance(wallet_service, WalletService)
        self.wallet_service = wallet_service
        self.nextoid = -1
        self.offerlist = None
        self.sync_wait_loop = task.LoopingCall(self.try_to_create_my_orders)
        self.sync_wait_loop.start(2.0)
        self.aborted = False

    def try_to_create_my_orders(self):
        """Because wallet syncing is not synchronous(!),
        we cannot calculate our offers until we know the wallet
        contents, so poll until BlockchainInterface.wallet_synced
        is flagged as True. TODO: Use a deferred, probably.
        Note that create_my_orders() is defined by subclasses.
        """
        if not self.wallet_service.synced:
            return
        self.offerlist = self.create_my_orders()
        self.sync_wait_loop.stop()
        if not self.offerlist:
            jlog.info("Failed to create offers, giving up.")
            sys.exit(EXIT_FAILURE)
        jlog.info('offerlist={}'.format(self.offerlist))

    @hexbin
    def on_auth_received(self, nick, offer, commitment, cr, amount, kphex):
        """Receives data on proposed transaction offer from daemon, verifies
        commitment, returns necessary data to send ioauth message (utxos etc)
        """
        # special case due to cjfee passed as string: it can accidentally parse
        # as hex:
        if not isinstance(offer["cjfee"], str):
            offer["cjfee"] = bintohex(offer["cjfee"])
        #check the validity of the proof of discrete log equivalence
        tries = jm_single().config.getint("POLICY", "taker_utxo_retries")
        def reject(msg):
            jlog.info("Counterparty commitment not accepted, reason: " + msg)
            return (False,)

        # deserialize the commitment revelation
        try:
            cr_dict = PoDLE.deserialize_revelation(cr)
        except PoDLEError as e:
            reason = repr(e)
            return reject(reason)

        if not verify_podle(cr_dict['P'], cr_dict['P2'], cr_dict['sig'],
                                cr_dict['e'], commitment, index_range=range(tries)):
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

        try:
            if not self.wallet_service.pubkey_has_script(
                    cr_dict['P'], res[0]['script']):
                raise EngineError()
        except EngineError:
            reason = "Invalid podle pubkey: " + str(cr_dict['P'])
            return reject(reason)

        # authorisation of taker passed
        # Find utxos for the transaction now:
        utxos, cj_addr, change_addr = self.oid_to_order(offer, amount)
        if not utxos:
            #could not find funds
            return (False,)
        # for index update persistence:
        self.wallet_service.save_wallet()
        # Construct data for auth request back to taker.
        # Need to choose an input utxo pubkey to sign with
        # (no longer using the coinjoin pubkey from 0.2.0)
        # Just choose the first utxo in self.utxos and retrieve key from wallet.
        auth_address = utxos[list(utxos.keys())[0]]['address']
        auth_key = self.wallet_service.get_key_from_addr(auth_address)
        auth_pub = btc.privkey_to_pubkey(auth_key)
        # kphex was auto-converted by @hexbin but we actually need to sign the
        # hex version to comply with pre-existing JM protocol:
        btc_sig = btc.ecdsa_sign(bintohex(kphex), auth_key)
        return (True, utxos, auth_pub, cj_addr, change_addr, btc_sig)

    @hexbin
    def on_tx_received(self, nick, tx_from_taker, offerinfo):
        """Called when the counterparty has sent an unsigned
        transaction. Sigs are created and returned if and only
        if the transaction passes verification checks (see
        verify_unsigned_tx()).
        """
        # special case due to cjfee passed as string: it can accidentally parse
        # as hex:
        if not isinstance(offerinfo["offer"]["cjfee"], str):
            offerinfo["offer"]["cjfee"] = bintohex(offerinfo["offer"]["cjfee"])
        try:
            tx = btc.CMutableTransaction.deserialize(tx_from_taker)
        except Exception as e:
            return (False, 'malformed txhex. ' + repr(e))
        # if the above deserialization was successful, the human readable
        # parsing will be also:
        jlog.info('obtained tx\n' + btc.human_readable_transaction(tx))
        goodtx, errmsg = self.verify_unsigned_tx(tx, offerinfo)
        if not goodtx:
            jlog.info('not a good tx, reason=' + errmsg)
            return (False, errmsg)
        jlog.info('goodtx')
        sigs = []
        utxos = offerinfo["utxos"]

        our_inputs = {}
        for index, ins in enumerate(tx.vin):
            utxo = (ins.prevout.hash[::-1], ins.prevout.n)
            if utxo not in utxos:
                continue
            script = self.wallet_service.addr_to_script(utxos[utxo]['address'])
            amount = utxos[utxo]['value']
            our_inputs[index] = (script, amount)

        success, msg = self.wallet_service.sign_tx(tx, our_inputs)
        assert success, msg
        for index in our_inputs:
            sigmsg = tx.vin[index].scriptSig
            if tx.has_witness():
                # Note that this flag only implies that the transaction
                # *as a whole* is using segwit serialization; it doesn't
                # imply that this specific input is segwit type (to be
                # fully general, we allow that even our own wallet's
                # inputs might be of mixed type). So, we catch the EngineError
                # which is thrown by non-segwit types. This way the sigmsg
                # will only contain the scriptCode field if the wallet object
                # decides it's necessary/appropriate for this specific input
                # If it is segwit, we prepend the witness data since we want
                # (sig, pub, witnessprogram=scriptSig - note we could, better,
                # pass scriptCode here, but that is not backwards compatible,
                # as the taker uses this third field and inserts it into the
                # transaction scriptSig), else (non-sw) the !sig message remains
                # unchanged as (sig, pub).
                try:
                    sig, pub = [a for a in iter(tx.wit.vtxinwit[index].scriptWitness)]
                    scriptCode = btc.pubkey_to_p2wpkh_script(pub)
                    sigmsg = btc.CScript([sig]) + btc.CScript(pub) + scriptCode
                except Exception as e:
                    #the sigmsg was already set before the segwit check
                    pass
            sigs.append(base64.b64encode(sigmsg).decode('ascii'))
        return (True, sigs)

    def verify_unsigned_tx(self, tx, offerinfo):
        """This code is security-critical.
        Before signing the transaction the Maker must ensure
        that all details are as expected, and most importantly
        that it receives the exact number of coins to expected
        in total. The data is taken from the offerinfo dict and
        compared with the serialized txhex.
        """
        tx_utxo_set = set((x.prevout.hash[::-1], x.prevout.n) for x in tx.vin)

        utxos = offerinfo["utxos"]
        cjaddr = offerinfo["cjaddr"]
        cjaddr_script = btc.CCoinAddress(cjaddr).to_scriptPubKey()
        changeaddr = offerinfo["changeaddr"]
        changeaddr_script = btc.CCoinAddress(changeaddr).to_scriptPubKey()
        #Note: this value is under the control of the Taker,
        #see comment below.
        amount = offerinfo["amount"]
        cjfee = offerinfo["offer"]["cjfee"]
        txfee = offerinfo["offer"]["txfee"]
        ordertype = offerinfo["offer"]["ordertype"]
        my_utxo_set = set(utxos.keys())
        if not tx_utxo_set.issuperset(my_utxo_set):
            return (False, 'my utxos are not contained')

        #The three lines below ensure that the Maker receives
        #back what he puts in, minus his bitcointxfee contribution,
        #plus his expected fee. These values are fully under
        #Maker control so no combination of messages from the Taker
        #can change them.
        #(mathematically: amount + expected_change_value is independent
        #of amount); there is not a (known) way for an attacker to
        #alter the amount (note: !fill resubmissions *overwrite*
        #the active_orders[dict] entry in daemon), but this is an
        #extra layer of safety.
        my_total_in = sum([va['value'] for va in utxos.values()])
        real_cjfee = calc_cj_fee(ordertype, cjfee, amount)
        expected_change_value = (my_total_in - amount - txfee + real_cjfee)
        jlog.info('potentially earned = {}'.format(real_cjfee - txfee))
        jlog.info('mycjaddr, mychange = {}, {}'.format(cjaddr, changeaddr))

        #The remaining checks are needed to ensure
        #that the coinjoin and change addresses occur
        #exactly once with the required amts, in the output.
        times_seen_cj_addr = 0
        times_seen_change_addr = 0
        for outs in tx.vout:
            if outs.scriptPubKey == cjaddr_script:
                times_seen_cj_addr += 1
                if outs.nValue != amount:
                    return (False, 'Wrong cj_amount. I expect ' + str(amount))
            if outs.scriptPubKey == changeaddr_script:
                times_seen_change_addr += 1
                if outs.nValue != expected_change_value:
                    return (False, 'wrong change, i expect ' + str(
                        expected_change_value))
        if times_seen_cj_addr != 1 or times_seen_change_addr != 1:
            fmt = ('cj or change addr not in tx '
                   'outputs once, #cjaddr={}, #chaddr={}').format
            return (False, (fmt(times_seen_cj_addr, times_seen_change_addr)))
        return (True, None)

    def modify_orders(self, to_cancel, to_announce):
        """This code is called on unconfirm and confirm callbacks,
        and replaces existing orders with new ones, or just cancels
        old ones.
        """
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
                oldorder_s = [o for o in self.offerlist
                              if o['oid'] == ann['oid']]
                if len(oldorder_s) > 0:
                    self.offerlist.remove(oldorder_s[0])
            self.offerlist += to_announce

    @abc.abstractmethod
    def create_my_orders(self):
        """Must generate a set of orders to be displayed
        according to the contents of the wallet + some algo.
        (Note: should be called "create_my_offers")
        """

    @abc.abstractmethod
    def oid_to_order(self, cjorder, oid, amount):
        """Must convert an order with an offer/order id
        into a set of utxos to fill the order.
        Also provides the output addresses for the Taker.
        """

    @abc.abstractmethod
    def on_tx_unconfirmed(self, cjorder, txid):
        """Performs action on receipt of transaction into the
        mempool in the blockchain instance (e.g. announcing orders)
        """

    @abc.abstractmethod
    def on_tx_confirmed(self, cjorder, txid, confirmations):
        """Performs actions on receipt of 1st confirmation of
        a transaction into a block (e.g. announce orders)
        """
