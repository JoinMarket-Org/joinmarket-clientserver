#! /usr/bin/env python
from __future__ import print_function

import base64
import pprint
import random
import sys
import time
import copy

import btc
from jmclient.configure import jm_single, get_p2pk_vbyte, get_p2sh_vbyte
from jmbase.support import get_log
from jmclient.support import (calc_cj_fee, weighted_order_choose, choose_orders,
                              choose_sweep_orders)
from jmclient.wallet import estimate_tx_fee
from jmclient.podle import (generate_podle, get_podle_commitments,
                                    PoDLE, PoDLEError, generate_podle_error_string)
jlog = get_log()


class JMTakerError(Exception):
    pass

class Taker(object):

    def __init__(self,
                 wallet,
                 schedule,
                 order_chooser=weighted_order_choose,
                 sign_method=None,
                 callbacks=None,
                 tdestaddrs=None,
                 ignored_makers=None):
        """Schedule must be a list of tuples: (see sample_schedule_for_testnet
        for explanation of syntax, also schedule.py module in this directory),
        which will be a sequence of joins to do.
        Callbacks:
        External callers set the 3 callbacks for filtering orders,
        sending info messages to client, and action on completion.
        "None" is allowable for taker_info_callback, defaults to log msg.
        Callback function definitions:
        =====================
        filter_orders_callback
        =====================
        args:
        1. orders_fees - a list of two items 1. orders dict 2 total cjfee
        2. cjamount - coinjoin amount in satoshis
        returns:
        False - offers rejected OR
        True - offers accepted OR
        'retry' - offers not accepted but try again
        =======================
        on_finished_callback
        =======================
        args:
        1. res - True means tx successful, False means tx unsucessful
        2. fromtx - True means not the final transaction, False means final
         (end of schedule), 'unconfirmed' means tx seen on the network only.
        3. waittime - passed in minutes, time to wait after confirmation before
         continuing to next tx (thus, only used if fromtx is True).
        4. txdetails - a tuple (txd, txid) - only to be used when fromtx
         is 'unconfirmed', used for monitoring.
        returns:
        None
        ========================
        taker_info_callback
        ========================
        args:
        1. type - one of 'ABORT' or 'INFO', the former signals the client that
         processing of this transaction is aborted, the latter is only an update.
        2. message - an information message.
        returns:
        None
        """
        self.aborted = False
        self.wallet = wallet
        self.schedule = schedule
        self.order_chooser = order_chooser
        self.ignored_makers = [] if not ignored_makers else ignored_makers
        self.waiting_for_conf = False
        self.txid = None
        self.schedule_index = -1
        self.tdestaddrs = [] if not tdestaddrs else tdestaddrs
        #allow custom wallet-based clients to use their own signing code;
        #currently only setting "wallet" is allowed, calls wallet.sign_tx(tx)
        self.sign_method = sign_method
        self.filter_orders_callback = callbacks[0]
        self.taker_info_callback = callbacks[1]
        if not self.taker_info_callback:
            self.taker_info_callback = self.default_taker_info_callback
        self.on_finished_callback = callbacks[2]

    def default_taker_info_callback(self, infotype, msg):
        jlog.debug(infotype + ":" + msg)

    def add_ignored_makers(self, makers):
        self.ignored_makers.extend(makers)

    def initialize(self, orderbook):
        """Once the daemon is active and has returned the current orderbook,
        select offers, re-initialize variables and prepare a commitment,
        then send it to the protocol to fill offers.
        """
        if self.aborted:
            return (False,)
        self.taker_info_callback("INFO", "Received offers from joinmarket pit")
        #choose the next item in the schedule
        self.schedule_index += 1
        if self.schedule_index == len(self.schedule):
            self.taker_info_callback("INFO", "Finished all scheduled transactions")
            self.on_finished_callback(True)
            return (False,)
        else:
            #read the settings from the schedule entry
            si = self.schedule[self.schedule_index]
            self.mixdepth = si[0]
            self.cjamount = si[1]
            #non-integer coinjoin amounts are treated as fractions
            #this is currently used by the tumbler algo
            if isinstance(self.cjamount, float):
                #the mixdepth balance is fixed at the *start* of each new
                #mixdepth in tumble schedules:
                if self.schedule_index == 0 or si[0] != self.schedule[
                    self.schedule_index - 1]:
                    self.mixdepthbal = self.wallet.get_balance_by_mixdepth(
                        )[self.mixdepth]
                #reset to satoshis
                self.cjamount = int(self.cjamount * self.mixdepthbal)
                if self.cjamount < jm_single().mincjamount:
                    jlog.info("Coinjoin amount too low, bringing up to: " + str(
                        jm_single().mincjamount))
                    self.cjamount = jm_single().mincjamount
            self.n_counterparties = si[2]
            self.my_cj_addr = si[3]
            #if destination is flagged "INTERNAL", choose a destination
            #from the next mixdepth modulo the maxmixdepth
            if self.my_cj_addr == "INTERNAL":
                next_mixdepth = (self.mixdepth + 1) % self.wallet.max_mix_depth
                jlog.info("Choosing a destination from mixdepth: " + str(next_mixdepth))
                self.my_cj_addr = self.wallet.get_internal_addr(next_mixdepth)
                jlog.info("Chose destination address: " + self.my_cj_addr)
            self.outputs = []
            self.cjfee_total = 0
            self.maker_txfee_contributions = 0
            self.txfee_default = 5000
            self.txid = None

        sweep = True if self.cjamount == 0 else False
        if not self.filter_orderbook(orderbook, sweep):
            return (False,)
        #choose coins to spend
        self.taker_info_callback("INFO", "Preparing bitcoin data..")
        if not self.prepare_my_bitcoin_data():
            return (False,)
        #Prepare a commitment
        commitment, revelation, errmsg = self.make_commitment()
        if not commitment:
            utxo_pairs, to, ts = revelation
            if len(to) == 0:
                #If any utxos are too new, then we can continue retrying
                #until they get old enough; otherwise, we have to abort
                #(TODO, it's possible for user to dynamically add more coins,
                #consider if this option means we should stay alive).
                self.taker_info_callback("ABORT", errmsg)
                self.on_finished_callback(False)
            else:
                self.taker_info_callback("INFO", errmsg)
            return (False,)
        else:
            self.taker_info_callback("INFO", errmsg)
        return (True, self.cjamount, commitment, revelation, self.orderbook)

    def filter_orderbook(self, orderbook, sweep=False):
        if sweep:
            self.orderbook = orderbook #offers choosing deferred to next step
        else:
            self.orderbook, self.total_cj_fee = choose_orders(
                orderbook, self.cjamount, self.n_counterparties, self.order_chooser,
                self.ignored_makers)
            if self.orderbook is None:
                #Failure to get an orderbook means order selection failed
                #for some reason; no action is taken, we let the stallMonitor
                # + the finished callback decide whether to retry.
                return False
            if self.filter_orders_callback:
                accepted = self.filter_orders_callback([self.orderbook,
                                                        self.total_cj_fee],
                                                       self.cjamount)
                if accepted == "retry":
                    #Special condition if Taker is "determined to continue"
                    #(such as tumbler); even though these offers are rejected,
                    #we don't trigger the finished callback; see above note on
                    #`if self.orderbook is None`
                    return False
                if not accepted:
                    self.on_finished_callback(False)
                    return False
        return True

    def prepare_my_bitcoin_data(self):
        """Get a coinjoin address and a change address; prepare inputs
        appropriate for this transaction"""
        if not self.my_cj_addr:
            #previously used for donations; TODO reimplement?
            raise NotImplementedError
        self.my_change_addr = None
        if self.cjamount != 0:
            try:
                self.my_change_addr = self.wallet.get_internal_addr(self.mixdepth)
            except:
                self.taker_info_callback("ABORT", "Failed to get a change address")
                return False
            #adjust the required amount upwards to anticipate an increase in
            #transaction fees after re-estimation; this is sufficiently conservative
            #to make failures unlikely while keeping the occurence of failure to
            #find sufficient utxos extremely rare. Indeed, a doubling of 'normal'
            #txfee indicates undesirable behaviour on maker side anyway.
            self.total_txfee = 2 * self.txfee_default * self.n_counterparties
            total_amount = self.cjamount + self.total_cj_fee + self.total_txfee
            jlog.info('total estimated amount spent = ' + str(total_amount))
            try:
                self.input_utxos = self.wallet.select_utxos(self.mixdepth,
                                                            total_amount)
            except Exception as e:
                self.taker_info_callback("ABORT",
                                    "Unable to select sufficient coins: " + repr(e))
                return False
        else:
            #sweep
            self.input_utxos = self.wallet.get_utxos_by_mixdepth()[self.mixdepth]
            #do our best to estimate the fee based on the number of
            #our own utxos; this estimate may be significantly higher
            #than the default set in option.txfee * makercount, where
            #we have a large number of utxos to spend. If it is smaller,
            #we'll be conservative and retain the original estimate.
            est_ins = len(self.input_utxos)+3*self.n_counterparties
            jlog.debug("Estimated ins: "+str(est_ins))
            est_outs = 2*self.n_counterparties + 1
            jlog.debug("Estimated outs: "+str(est_outs))
            estimated_fee = estimate_tx_fee(est_ins, est_outs,
                                            txtype=self.wallet.get_txtype())
            jlog.debug("We have a fee estimate: "+str(estimated_fee))
            jlog.debug("And a requested fee of: "+str(
                self.txfee_default * self.n_counterparties))
            self.total_txfee = max([estimated_fee,
                                    self.n_counterparties * self.txfee_default])
            total_value = sum([va['value'] for va in self.input_utxos.values()])
            self.orderbook, self.cjamount, self.total_cj_fee = choose_sweep_orders(
                self.orderbook, total_value, self.total_txfee,
                self.n_counterparties, self.order_chooser,
                self.ignored_makers)
            if not self.orderbook:
                self.taker_info_callback("ABORT",
                                "Could not find orders to complete transaction")
                return False
            if self.filter_orders_callback:
                if not self.filter_orders_callback((self.orderbook,
                                                    self.total_cj_fee),
                                                   self.cjamount):
                    self.on_finished_callback(False)
                    return False

        self.utxos = {None: self.input_utxos.keys()}
        return True

    def receive_utxos(self, ioauth_data):
        """Triggered when the daemon returns utxo data from
        makers who responded; this is the completion of phase 1
        of the protocol
        """
        if self.aborted:
            return (False, "User aborted")
        rejected_counterparties = []
        #Enough data, but need to authorize against the btc pubkey first.
        for nick, nickdata in ioauth_data.iteritems():
            utxo_list, auth_pub, cj_addr, change_addr, btc_sig, maker_pk = nickdata
            if not self.auth_counterparty(btc_sig, auth_pub, maker_pk):
                jlog.debug(
                "Counterparty encryption verification failed, aborting: " + nick)
                #This counterparty must be rejected
                rejected_counterparties.append(nick)

        for rc in rejected_counterparties:
            del ioauth_data[rc]

        self.maker_utxo_data = {}

        for nick, nickdata in ioauth_data.iteritems():
            utxo_list, auth_pub, cj_addr, change_addr, btc_sig, maker_pk = nickdata
            self.utxos[nick] = utxo_list
            utxo_data = jm_single().bc_interface.query_utxo_set(self.utxos[
                nick])
            if None in utxo_data:
                jlog.warn(('ERROR outputs unconfirmed or already spent. '
                           'utxo_data={}').format(pprint.pformat(utxo_data)))
                # when internal reviewing of makers is created, add it here to
                # immediately quit; currently, the timeout thread suffices.
                continue

            #Complete maker authorization:
            #Extract the address fields from the utxos
            #Construct the Bitcoin address for the auth_pub field
            #Ensure that at least one address from utxos corresponds.
            input_addresses = [d['address'] for d in utxo_data]
            auth_address = btc.pubkey_to_p2sh_p2wpkh_address(auth_pub,
                                                             get_p2sh_vbyte())
            if not auth_address in input_addresses:
                jlog.warn("ERROR maker's (" + nick + ")"
                         " authorising pubkey is not included "
                         "in the transaction: " + str(auth_address))
                #this will not be added to the transaction, so we will have
                #to recheck if we have enough
                continue
            total_input = sum([d['value'] for d in utxo_data])
            real_cjfee = calc_cj_fee(self.orderbook[nick]['ordertype'],
                                     self.orderbook[nick]['cjfee'],
                                     self.cjamount)
            change_amount = (total_input - self.cjamount -
                             self.orderbook[nick]['txfee'] + real_cjfee)

            # certain malicious and/or incompetent liquidity providers send
            # inputs totalling less than the coinjoin amount! this leads to
            # a change output of zero satoshis; this counterparty must be removed.
            if change_amount < jm_single().DUST_THRESHOLD:
                fmt = ('ERROR counterparty requires sub-dust change. nick={}'
                       'totalin={:d} cjamount={:d} change={:d}').format
                jlog.warn(fmt(nick, total_input, self.cjamount, change_amount))
                jlog.warn("Invalid change, too small, nick= " + nick)
                continue

            self.outputs.append({'address': change_addr,
                                 'value': change_amount})
            fmt = ('fee breakdown for {} totalin={:d} '
                   'cjamount={:d} txfee={:d} realcjfee={:d}').format
            jlog.info(fmt(nick, total_input, self.cjamount, self.orderbook[
                nick]['txfee'], real_cjfee))
            self.outputs.append({'address': cj_addr, 'value': self.cjamount})
            self.cjfee_total += real_cjfee
            self.maker_txfee_contributions += self.orderbook[nick]['txfee']
            self.maker_utxo_data[nick] = utxo_data

        #Apply business logic of how many counterparties are enough:
        if len(self.maker_utxo_data.keys()) < jm_single().config.getint(
                "POLICY", "minimum_makers"):
            self.taker_info_callback("INFO", "Not enough counterparties, aborting.")
            return (False,
                    "Not enough counterparties responded to fill, giving up")

        self.taker_info_callback("INFO", "Got all parts, enough to build a tx")
        self.nonrespondants = list(self.maker_utxo_data.keys())

        my_total_in = sum([va['value'] for u, va in self.input_utxos.iteritems()
                          ])
        if self.my_change_addr:
            #Estimate fee per choice of next/3/6 blocks targetting.
            estimated_fee = estimate_tx_fee(
                len(sum(self.utxos.values(), [])), len(self.outputs) + 2)
            jlog.info("Based on initial guess: " + str(self.total_txfee) +
                     ", we estimated a miner fee of: " + str(estimated_fee))
            #reset total
            self.total_txfee = estimated_fee
        my_txfee = max(self.total_txfee - self.maker_txfee_contributions, 0)
        my_change_value = (
            my_total_in - self.cjamount - self.cjfee_total - my_txfee)
        #Since we could not predict the maker's inputs, we may end up needing
        #too much such that the change value is negative or small. Note that
        #we have tried to avoid this based on over-estimating the needed amount
        #in SendPayment.create_tx(), but it is still a possibility if one maker
        #uses a *lot* of inputs.
        if self.my_change_addr and my_change_value <= 0:
            raise ValueError("Calculated transaction fee of: " + str(
                self.total_txfee) +
                             " is too large for our inputs;Please try again.")
        elif self.my_change_addr and my_change_value <= jm_single(
        ).BITCOIN_DUST_THRESHOLD:
            jlog.info("Dynamically calculated change lower than dust: " + str(
                my_change_value) + "; dropping.")
            self.my_change_addr = None
            my_change_value = 0
        jlog.info(
            'fee breakdown for me totalin=%d my_txfee=%d makers_txfee=%d cjfee_total=%d => changevalue=%d'
            % (my_total_in, my_txfee, self.maker_txfee_contributions,
               self.cjfee_total, my_change_value))
        if self.my_change_addr is None:
            if my_change_value != 0 and abs(my_change_value) != 1:
                # seems you wont always get exactly zero because of integer
                # rounding so 1 satoshi extra or fewer being spent as miner
                # fees is acceptable
                jlog.info(('WARNING CHANGE NOT BEING '
                           'USED\nCHANGEVALUE = {}').format(my_change_value))
        else:
            self.outputs.append({'address': self.my_change_addr,
                                 'value': my_change_value})
        self.utxo_tx = [dict([('output', u)])
                        for u in sum(self.utxos.values(), [])]
        self.outputs.append({'address': self.coinjoin_address(),
                             'value': self.cjamount})
        random.shuffle(self.utxo_tx)
        random.shuffle(self.outputs)
        tx = btc.mktx(self.utxo_tx, self.outputs)
        jlog.info('obtained tx\n' + pprint.pformat(btc.deserialize(tx)))

        self.latest_tx = btc.deserialize(tx)
        for index, ins in enumerate(self.latest_tx['ins']):
            utxo = ins['outpoint']['hash'] + ':' + str(ins['outpoint']['index'])
            if utxo not in self.input_utxos.keys():
                continue
            # placeholders required
            ins['script'] = 'deadbeef'
        self.taker_info_callback("INFO", "Built tx, sending to counterparties.")
        return (True, self.maker_utxo_data.keys(), tx)

    def auth_counterparty(self, btc_sig, auth_pub, maker_pk):
        """Validate the counterpartys claim to own the btc
        address/pubkey that will be used for coinjoining
        with an ecdsa verification.
        """
        try:
            if not btc.ecdsa_verify(maker_pk, btc_sig, auth_pub):
                jlog.debug('signature didnt match pubkey and message')
                return False
        except Exception as e:
            jlog.info("Failed ecdsa verify for maker pubkey: " + str(maker_pk))
            jlog.info("Exception was: " + repr(e))
            return False
        return True

    def on_sig(self, nick, sigb64):
        """Processes transaction signatures from counterparties.
        Returns True if all signatures received correctly, else
        returns False
        """
        if self.aborted:
            return False
        sig = base64.b64decode(sigb64).encode('hex')
        inserted_sig = False
        txhex = btc.serialize(self.latest_tx)

        # batch retrieval of utxo data
        utxo = {}
        ctr = 0
        for index, ins in enumerate(self.latest_tx['ins']):
            utxo_for_checking = ins['outpoint']['hash'] + ':' + str(ins[
                'outpoint']['index'])
             #'deadbeef' markers mean our own input scripts are not ''
            if (ins['script'] != ''):
                continue
            utxo[ctr] = [index, utxo_for_checking]
            ctr += 1
        utxo_data = jm_single().bc_interface.query_utxo_set([x[
            1] for x in utxo.values()])

        # insert signatures
        for i, u in utxo.iteritems():
            if utxo_data[i] is None:
                continue
            #Check if the sender serialize_scripted the witness
            #item into the sig message; if so, also pick up the amount
            #from the utxo data retrieved from the blockchain to verify
            #the segwit-style signature. Note that this allows a mixed
            #SW/non-SW transaction as each utxo is interpreted separately.
            sig_deserialized = btc.deserialize_script(sig)
            if len(sig_deserialized) == 2:
                ver_sig, ver_pub = sig_deserialized
                wit = None
            elif len(sig_deserialized) == 3:
                ver_sig, ver_pub, wit =  sig_deserialized
            else:
                jlog.debug("Invalid signature message - more than 3 items")
                break
            ver_amt = utxo_data[i]['value'] if wit else None
            sig_good = btc.verify_tx_input(txhex, u[0], utxo_data[i]['script'],
                                               ver_sig, ver_pub, witness=wit,
                                               amount=ver_amt)
            if sig_good:
                jlog.debug('found good sig at index=%d' % (u[0]))
                if wit:
                    self.latest_tx["ins"][u[0]]["txinwitness"] = [ver_sig, ver_pub]
                    self.latest_tx["ins"][u[0]]["script"] = "16" + wit
                else:
                    self.latest_tx["ins"][u[0]]["script"] = sig
                inserted_sig = True
                # check if maker has sent everything possible
                self.utxos[nick].remove(u[1])
                if len(self.utxos[nick]) == 0:
                    jlog.debug(('nick = {} sent all sigs, removing from '
                               'nonrespondant list').format(nick))
                    self.nonrespondants.remove(nick)
                break
        if not inserted_sig:
            jlog.debug('signature did not match anything in the tx')
            # TODO what if the signature doesnt match anything
            # nothing really to do except drop it, carry on and wonder why the
            # other guy sent a failed signature

        tx_signed = True
        for ins in self.latest_tx['ins']:
            if ins['script'] == '':
                tx_signed = False
        if not tx_signed:
            return False
        assert not len(self.nonrespondants)
        jlog.info('all makers have sent their signatures')
        self.taker_info_callback("INFO", "Transaction is valid, signing..")
        jlog.debug("schedule item was: " + str(self.schedule[self.schedule_index]))
        return self.self_sign_and_push()

    def make_commitment(self):
        """The Taker default commitment function, which uses PoDLE.
        Alternative commitment types should use a different commit type byte.
        This will allow future upgrades to provide different style commitments
        by subclassing Taker and changing the commit_type_byte; existing makers
        will simply not accept this new type of commitment.
        In case of success, return the commitment and its opening.
        In case of failure returns (None, None) and constructs a detailed
        log for the user to read and discern the reason.
        """

        def filter_by_coin_age_amt(utxos, age, amt):
            results = jm_single().bc_interface.query_utxo_set(utxos,
                                                              includeconf=True)
            newresults = []
            too_old = []
            too_small = []
            for i, r in enumerate(results):
                #results return "None" if txo is spent; drop this
                if not r:
                    continue
                valid_age = r['confirms'] >= age
                valid_amt = r['value'] >= amt
                if not valid_age:
                    too_old.append(utxos[i])
                if not valid_amt:
                    too_small.append(utxos[i])
                if valid_age and valid_amt:
                    newresults.append(utxos[i])

            return newresults, too_old, too_small

        def priv_utxo_pairs_from_utxos(utxos, age, amt):
            #returns pairs list of (priv, utxo) for each valid utxo;
            #also returns lists "too_old" and "too_small" for any
            #utxos that did not satisfy the criteria for debugging.
            priv_utxo_pairs = []
            new_utxos, too_old, too_small = filter_by_coin_age_amt(utxos.keys(),
                                                                   age, amt)
            new_utxos_dict = {k: v for k, v in utxos.items() if k in new_utxos}
            for k, v in new_utxos_dict.iteritems():
                addr = v['address']
                priv = self.wallet.get_key_from_addr(addr)
                if priv:  #can be null from create-unsigned
                    priv_utxo_pairs.append((priv, k))
            return priv_utxo_pairs, too_old, too_small

        commit_type_byte = "P"
        podle_data = None
        tries = jm_single().config.getint("POLICY", "taker_utxo_retries")
        age = jm_single().config.getint("POLICY", "taker_utxo_age")
        #Minor rounding errors don't matter here
        amt = int(self.cjamount *
                  jm_single().config.getint("POLICY",
                                            "taker_utxo_amtpercent") / 100.0)
        priv_utxo_pairs, to, ts = priv_utxo_pairs_from_utxos(self.input_utxos,
                                                             age, amt)
        #Note that we ignore the "too old" and "too small" lists in the first
        #pass through, because the same utxos appear in the whole-wallet check.

        #For podle data format see: podle.PoDLE.reveal()
        #In first round try, don't use external commitments
        podle_data = generate_podle(priv_utxo_pairs, tries)
        if not podle_data:
            #We defer to a second round to try *all* utxos in wallet;
            #this is because it's much cleaner to use the utxos involved
            #in the transaction, about to be consumed, rather than use
            #random utxos that will persist after. At this step we also
            #allow use of external utxos in the json file.
            if self.wallet.unspent:
                priv_utxo_pairs, to, ts = priv_utxo_pairs_from_utxos(
                    self.wallet.unspent, age, amt)
            #Pre-filter the set of external commitments that work for this
            #transaction according to its size and age.
            dummy, extdict = get_podle_commitments()
            if len(extdict.keys()) > 0:
                ext_valid, ext_to, ext_ts = filter_by_coin_age_amt(
                    extdict.keys(), age, amt)
            else:
                ext_valid = None
            podle_data = generate_podle(priv_utxo_pairs, tries, ext_valid)
        if podle_data:
            jlog.debug("Generated PoDLE: " + pprint.pformat(podle_data))
            revelation = PoDLE(u=podle_data['utxo'],
                                   P=podle_data['P'],
                                   P2=podle_data['P2'],
                                   s=podle_data['sig'],
                                   e=podle_data['e']).serialize_revelation()
            return (commit_type_byte + podle_data["commit"], revelation,
                    "Commitment sourced OK")
        else:
            errmsgheader, errmsg = generate_podle_error_string(priv_utxo_pairs,
                        to, ts, self.wallet.unspent, self.cjamount,
                        jm_single().config.get("POLICY", "taker_utxo_age"),
                        jm_single().config.get("POLICY", "taker_utxo_amtpercent"))

            with open("commitments_debug.txt", "wb") as f:
                errmsgfileheader = ("THIS IS A TEMPORARY FILE FOR DEBUGGING; "
                        "IT CAN BE SAFELY DELETED ANY TIME.\n")
                errmsgfileheader += ("***\n")
                f.write(errmsgfileheader + errmsg)

            return (None, (priv_utxo_pairs, to, ts), errmsgheader + errmsg)

    def coinjoin_address(self):
        if self.my_cj_addr:
            return self.my_cj_addr
        else:
            #Note: donation code removed (possibly temporarily)
            raise NotImplementedError

    def sign_tx(self, tx, i, priv, amount):
        if self.my_cj_addr:
            return self.wallet.sign(tx, i, priv, amount)
        else:
            #Note: donation code removed (possibly temporarily)
            raise NotImplementedError

    def self_sign(self):
        # now sign it ourselves
        tx = btc.serialize(self.latest_tx)
        if self.sign_method == "wallet":
            #Currently passes addresses of to-be-signed inputs
            #to backend wallet; this is correct for Electrum, may need
            #different info for other backends.
            addrs = {}
            for index, ins in enumerate(self.latest_tx['ins']):
                utxo = ins['outpoint']['hash'] + ':' + str(ins['outpoint']['index'])
                if utxo not in self.input_utxos.keys():
                    continue
                addrs[index] = self.input_utxos[utxo]['address']
            tx = self.wallet.sign_tx(tx, addrs)
        else:
            for index, ins in enumerate(self.latest_tx['ins']):
                utxo = ins['outpoint']['hash'] + ':' + str(ins['outpoint']['index'])
                if utxo not in self.input_utxos.keys():
                    continue
                addr = self.input_utxos[utxo]['address']
                amount = self.input_utxos[utxo]["value"]
                tx = self.sign_tx(tx, index, self.wallet.get_key_from_addr(addr),
                                  amount)
        self.latest_tx = btc.deserialize(tx)

    def push(self):
        tx = btc.serialize(self.latest_tx)
        jlog.debug('\n' + tx)
        self.txid = btc.txhash(tx)
        jlog.info('txid = ' + self.txid)
        tx_broadcast = jm_single().config.get('POLICY', 'tx_broadcast')
        nick_to_use = None
        if tx_broadcast == 'self':
            pushed = jm_single().bc_interface.pushtx(tx)
        elif tx_broadcast in ['random-peer', 'not-self']:
            n = len(self.maker_utxo_data)
            if tx_broadcast == 'random-peer':
                i = random.randrange(n + 1)
            else:
                i = random.randrange(n)
            if i == n:
                pushed = jm_single().bc_interface.pushtx(tx)
            else:
                nick_to_use = self.maker_utxo_data.keys()[i]
                pushed = True
        else:
            jlog.info("Only self, random-peer and not-self broadcast "
                      "methods supported. Reverting to self-broadcast.")
            pushed = jm_single().bc_interface.pushtx(tx)
        if not pushed:
            self.on_finished_callback(False, fromtx=True)
        else:
            jm_single().bc_interface.add_tx_notify(
                self.latest_tx, self.unconfirm_callback,
                self.confirm_callback, self.my_cj_addr, vb=get_p2sh_vbyte())
            if nick_to_use:
                return (nick_to_use, tx)
        #if push was not successful, return None

    def self_sign_and_push(self):
        self.self_sign()
        return self.push()

    def unconfirm_callback(self, txd, txid):
        jlog.info("Transaction seen on network, waiting for confirmation")
        #To allow client to mark transaction as "done" (e.g. by persisting state)
        self.on_finished_callback(True, fromtx="unconfirmed")
        self.waiting_for_conf = True

    def confirm_callback(self, txd, txid, confirmations):
        self.waiting_for_conf = False
        if self.aborted:
            #do not trigger on_finished processing (abort whole schedule)
            return
        jlog.debug("Confirmed callback in taker, confs: " + str(confirmations))
        fromtx=False if self.schedule_index + 1 == len(self.schedule) else True
        waittime = self.schedule[self.schedule_index][4]
        self.on_finished_callback(True, fromtx=fromtx, waittime=waittime,
                                  txdetails=(txd, txid))
