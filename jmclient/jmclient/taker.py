#! /usr/bin/env python

import base64
import pprint
import random
from twisted.internet import reactor, task

import jmbitcoin as btc
from jmclient.configure import jm_single, validate_address
from jmbase import get_log, bintohex, hexbin
from jmclient.support import (calc_cj_fee, weighted_order_choose, choose_orders,
                              choose_sweep_orders)
from jmclient.wallet import estimate_tx_fee, compute_tx_locktime
from jmclient.podle import generate_podle, get_podle_commitments
from jmclient.wallet_service import WalletService
from .output import generate_podle_error_string
from .cryptoengine import EngineError
from .schedule import NO_ROUNDING


jlog = get_log()


class JMTakerError(Exception):
    pass

class Taker(object):

    def __init__(self,
                 wallet_service,
                 schedule,
                 max_cj_fee,
                 order_chooser=weighted_order_choose,
                 callbacks=None,
                 tdestaddrs=None,
                 ignored_makers=None):
        """`schedule`` must be a list of tuples: (see sample_schedule_for_testnet
        for explanation of syntax, also schedule.py module in this directory),
        which will be a sequence of joins to do.
        `max_cj_fee` must be a tuple of form: (float, int or float) where the first
        is the maximum relative fee as a decimal and the second is the maximum
        absolute fee in satoshis.
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
        assert isinstance(wallet_service, WalletService)
        self.wallet_service = wallet_service
        self.schedule = schedule
        self.order_chooser = order_chooser
        self.max_cj_fee = max_cj_fee

        #List (which persists between transactions) of makers
        #who have not responded or behaved maliciously at any
        #stage of the protocol.
        self.ignored_makers = [] if not ignored_makers else ignored_makers

        #Used in attempts to complete with subset after second round failure:
        self.honest_makers = []
        #Toggle: if set, only honest makers will be used from orderbook
        self.honest_only = False

        #Temporary (per transaction) list of makers that keeps track of
        #which have responded, both in Stage 1 and Stage 2. Before each
        #stage, the list is set to the full set of expected responders,
        #and entries are removed when honest responses are received;
        #emptiness of the list can be used to trigger completion of
        #processing.
        self.nonrespondants = []

        self.waiting_for_conf = False
        self.txid = None
        self.schedule_index = -1
        self.utxos = {}
        self.tdestaddrs = [] if not tdestaddrs else tdestaddrs
        self.filter_orders_callback = callbacks[0]
        self.taker_info_callback = callbacks[1]
        if not self.taker_info_callback:
            self.taker_info_callback = self.default_taker_info_callback
        self.on_finished_callback = callbacks[2]

    def default_taker_info_callback(self, infotype, msg):
        jlog.info(infotype + ":" + msg)

    def add_ignored_makers(self, makers):
        """Makers should be added to this list when they have refused to
        complete the protocol honestly, and should remain in this set
        for the duration of the Taker run (so, the whole schedule).
        """
        self.ignored_makers.extend(makers)
        self.ignored_makers = list(set(self.ignored_makers))

    def add_honest_makers(self, makers):
        """A maker who has shown willigness to complete the protocol
        by returning a valid signature for a coinjoin can be added to
        this list, the taker can optionally choose to only source
        offers from thus-defined "honest" makers.
        """
        self.honest_makers.extend(makers)
        self.honest_makers = list(set(self.honest_makers))

    def set_honest_only(self, truefalse):
        """Toggle; if set, offers will only be accepted
        from makers in the self.honest_makers list.
        This should not be called unless we already have
        a list of such honest makers (see add_honest_makers()).
        """
        if truefalse:
            if not len(self.honest_makers):
                jlog.debug("Attempt to set honest-only without "
                           "any honest makers; ignored.")
                return
        self.honest_only = truefalse

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
            rounding = si[5]
            #non-integer coinjoin amounts are treated as fractions
            #this is currently used by the tumbler algo
            if isinstance(self.cjamount, float):
                #the mixdepth balance is fixed at the *start* of each new
                #mixdepth in tumble schedules:
                if self.schedule_index == 0 or si[0] != self.schedule[
                    self.schedule_index - 1]:
                    self.mixdepthbal = self.wallet_service.get_balance_by_mixdepth(
                        )[self.mixdepth]
                #reset to satoshis
                self.cjamount = int(self.cjamount * self.mixdepthbal)
                if rounding != NO_ROUNDING:
                    self.cjamount = round_to_significant_figures(self.cjamount,
                        rounding)
                if self.cjamount < jm_single().mincjamount:
                    jlog.info("Coinjoin amount too low, bringing up to: " +
                        btc.amount_to_str(jm_single().mincjamount))
                    self.cjamount = jm_single().mincjamount
            self.n_counterparties = si[2]
            self.my_cj_addr = si[3]
            # for sweeps to external addresses we need an in-wallet import
            # for the transaction monitor (this will be a no-op for txs to
            # in-wallet addresses).
            if self.cjamount == 0 and self.my_cj_addr != "INTERNAL":
                self.wallet_service.import_non_wallet_address(self.my_cj_addr)

            #if destination is flagged "INTERNAL", choose a destination
            #from the next mixdepth modulo the maxmixdepth
            if self.my_cj_addr == "INTERNAL":
                next_mixdepth = (self.mixdepth + 1) % (
                    self.wallet_service.mixdepth + 1)
                jlog.info("Choosing a destination from mixdepth: " + str(
                    next_mixdepth))
                self.my_cj_addr = self.wallet_service.get_internal_addr(next_mixdepth)
                jlog.info("Chose destination address: " + self.my_cj_addr)
            self.outputs = []
            self.cjfee_total = 0
            self.maker_txfee_contributions = 0
            self.latest_tx = None
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
                return ("commitment-failure",)
            else:
                self.taker_info_callback("INFO", errmsg)
                return (False,)
        else:
            self.taker_info_callback("INFO", errmsg)

        #Initialization has been successful. We must set the nonrespondants
        #now to keep track of what changed when we receive the utxo data
        self.nonrespondants = list(self.orderbook.keys())
        return (True, self.cjamount, commitment, revelation, self.orderbook)

    def filter_orderbook(self, orderbook, sweep=False):
        #If honesty filter is set, we immediately filter to only the prescribed
        #honest makers before continuing. In this case, the number of
        #counterparties should already match, and this has to be set by the
        #script instantiating the Taker.
        #Note: If one or more of the honest makers has dropped out in the meantime,
        #we will just have insufficient offers and it will fail in the usual way
        #for insufficient liquidity.
        if self.honest_only:
            orderbook = [o for o in orderbook if o['counterparty'] in self.honest_makers]
        if sweep:
            self.orderbook = orderbook #offers choosing deferred to next step
        else:
            allowed_types = ["reloffer", "absoffer"] if jm_single().config.get(
                "POLICY", "segwit") == "false" else ["swreloffer", "swabsoffer"]
            self.orderbook, self.total_cj_fee = choose_orders(
                orderbook, self.cjamount, self.n_counterparties, self.order_chooser,
                self.ignored_makers, allowed_types=allowed_types,
                max_cj_fee=self.max_cj_fee)
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
                self.my_change_addr = self.wallet_service.get_internal_addr(self.mixdepth)
            except:
                self.taker_info_callback("ABORT", "Failed to get a change address")
                return False
            #adjust the required amount upwards to anticipate an increase in
            #transaction fees after re-estimation; this is sufficiently conservative
            #to make failures unlikely while keeping the occurence of failure to
            #find sufficient utxos extremely rare. Indeed, a doubling of 'normal'
            #txfee indicates undesirable behaviour on maker side anyway.
            self.total_txfee = estimate_tx_fee(3, 2,
                txtype=self.wallet_service.get_txtype()) * self.n_counterparties
            total_amount = self.cjamount + self.total_cj_fee + self.total_txfee
            jlog.info('total estimated amount spent = ' + btc.amount_to_str(total_amount))
            try:
                self.input_utxos = self.wallet_service.select_utxos(self.mixdepth, total_amount,
                                                        minconfs=1)
            except Exception as e:
                self.taker_info_callback("ABORT",
                                    "Unable to select sufficient coins: " + repr(e))
                return False
        else:
            #sweep
            self.input_utxos = self.wallet_service.get_utxos_by_mixdepth()[self.mixdepth]
            #do our best to estimate the fee based on the number of
            #our own utxos; this estimate may be significantly higher
            #than the default set in option.txfee * makercount, where
            #we have a large number of utxos to spend. If it is smaller,
            #we'll be conservative and retain the original estimate.
            est_ins = len(self.input_utxos)+3*self.n_counterparties
            jlog.debug("Estimated ins: "+str(est_ins))
            est_outs = 2*self.n_counterparties + 1
            jlog.debug("Estimated outs: "+str(est_outs))
            self.total_txfee = estimate_tx_fee(est_ins, est_outs,
                                            txtype=self.wallet_service.get_txtype())
            jlog.debug("We have a fee estimate: "+str(self.total_txfee))
            total_value = sum([va['value'] for va in self.input_utxos.values()])
            allowed_types = ["reloffer", "absoffer"] if jm_single().config.get(
                "POLICY", "segwit") == "false" else ["swreloffer", "swabsoffer"]
            self.orderbook, self.cjamount, self.total_cj_fee = choose_sweep_orders(
                self.orderbook, total_value, self.total_txfee,
                self.n_counterparties, self.order_chooser,
                self.ignored_makers, allowed_types=allowed_types,
                max_cj_fee=self.max_cj_fee)
            if not self.orderbook:
                self.taker_info_callback("ABORT",
                                "Could not find orders to complete transaction")
                return False
            if self.filter_orders_callback:
                if not self.filter_orders_callback((self.orderbook,
                                                    self.total_cj_fee),
                                                   self.cjamount):
                    return False

        self.utxos = {None: list(self.input_utxos.keys())}
        return True

    @hexbin
    def receive_utxos(self, ioauth_data):
        """Triggered when the daemon returns utxo data from
        makers who responded; this is the completion of phase 1
        of the protocol
        """
        if self.aborted:
            return (False, "User aborted")

        #Temporary list used to aggregate all ioauth data that must be removed
        rejected_counterparties = []

        #Need to authorize against the btc pubkey first.
        for nick, nickdata in ioauth_data.items():
            utxo_list, auth_pub, cj_addr, change_addr, btc_sig, maker_pk = nickdata
            if not self.auth_counterparty(btc_sig, auth_pub, maker_pk):
                jlog.debug(
                "Counterparty encryption verification failed, aborting: " + nick)
                #This counterparty must be rejected
                rejected_counterparties.append(nick)

            if not validate_address(cj_addr)[0] or not validate_address(change_addr)[0]:
                jlog.warn("Counterparty provided invalid address: {}".format(
                    (cj_addr, change_addr)))
                # Interpreted as malicious
                self.add_ignored_makers([nick])
                rejected_counterparties.append(nick)

        for rc in rejected_counterparties:
            del ioauth_data[rc]

        self.maker_utxo_data = {}

        for nick, nickdata in ioauth_data.items():
            utxo_list, auth_pub, cj_addr, change_addr, _, _ = nickdata
            utxo_data = jm_single().bc_interface.query_utxo_set(utxo_list)
            self.utxos[nick] = utxo_list
            if None in utxo_data:
                jlog.warn(('ERROR outputs unconfirmed or already spent. '
                           'utxo_data={}').format(pprint.pformat(utxo_data)))
                jlog.warn('Disregarding this counterparty.')
                del self.utxos[nick]
                continue

            #Complete maker authorization:
            #Extract the address fields from the utxos
            #Construct the Bitcoin address for the auth_pub field
            #Ensure that at least one address from utxos corresponds.
            for inp in utxo_data:
                try:
                    if self.wallet_service.pubkey_has_script(
                            auth_pub, inp['script']):
                        break
                except EngineError as e:
                    pass
            else:
                jlog.warn("ERROR maker's (" + nick + ")"
                          " authorising pubkey is not included "
                          "in the transaction!")
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
            #We have succesfully processed the data from this nick:
            try:
                self.nonrespondants.remove(nick)
            except Exception as e:
                jlog.warn("Failure to remove counterparty from nonrespondants list: " + str(nick) + \
                          ", error message: " + repr(e))

        #Apply business logic of how many counterparties are enough; note that
        #this must occur after the above ioauth data processing, since we only now
        #know for sure that the data meets all business-logic requirements.
        if len(self.maker_utxo_data) < jm_single().config.getint(
                "POLICY", "minimum_makers"):
            self.taker_info_callback("INFO", "Not enough counterparties, aborting.")
            return (False,
                    "Not enough counterparties responded to fill, giving up")

        self.taker_info_callback("INFO", "Got all parts, enough to build a tx")

        #The list self.nonrespondants is now reset and
        #used to track return of signatures for phase 2
        self.nonrespondants = list(self.maker_utxo_data.keys())

        my_total_in = sum([va['value'] for u, va in self.input_utxos.items()])
        if self.my_change_addr:
            #Estimate fee per choice of next/3/6 blocks targetting.
            estimated_fee = estimate_tx_fee(
                len(sum(self.utxos.values(), [])), len(self.outputs) + 2,
                txtype=self.wallet_service.get_txtype())
            jlog.info("Based on initial guess: " +
                      btc.amount_to_str(self.total_txfee) +
                      ", we estimated a miner fee of: " +
                      btc.amount_to_str(estimated_fee))
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
            raise ValueError("Calculated transaction fee of: " +
                btc.amount_to_str(self.total_txfee) +
                " is too large for our inputs; Please try again.")
        elif self.my_change_addr and my_change_value <= jm_single(
        ).BITCOIN_DUST_THRESHOLD:
            jlog.info("Dynamically calculated change lower than dust: " +
                btc.amount_to_str(my_change_value) + "; dropping.")
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
                           'USED\nCHANGEVALUE = {}').format(btc.amount_to_str(my_change_value)))
        else:
            self.outputs.append({'address': self.my_change_addr,
                                 'value': my_change_value})
        self.utxo_tx = [u for u in sum(self.utxos.values(), [])]
        self.outputs.append({'address': self.coinjoin_address(),
                             'value': self.cjamount})
        self.latest_tx = btc.make_shuffled_tx(self.utxo_tx, self.outputs)
        jlog.info('obtained tx\n' + btc.human_readable_transaction(
            self.latest_tx))

        for index, ins in enumerate(self.latest_tx.vin):
            utxo = (ins.prevout.hash[::-1], ins.prevout.n)
            if utxo not in self.input_utxos.keys():
                continue
            # placeholders required
            ins.scriptSig = btc.CScript.fromhex("deadbeef")
        self.taker_info_callback("INFO", "Built tx, sending to counterparties.")
        return (True, list(self.maker_utxo_data.keys()),
                bintohex(self.latest_tx.serialize()))

    @hexbin
    def auth_counterparty(self, btc_sig, auth_pub, maker_pk):
        """Validate the counterpartys claim to own the btc
        address/pubkey that will be used for coinjoining
        with an ecdsa verification.
        """
        try:
            # maker pubkey as message is in hex format:
            if not btc.ecdsa_verify(bintohex(maker_pk), btc_sig, auth_pub):
                jlog.debug('signature didnt match pubkey and message')
                return False
        except Exception as e:
            jlog.info("Failed ecdsa verify for maker pubkey: " + bintohex(maker_pk))
            jlog.info("Exception was: " + repr(e))
            return False
        return True

    def on_sig(self, nick, sigb64):
        """Processes transaction signatures from counterparties.
        If all signatures received correctly, returns the result
        of self.self_sign_and_push() (i.e. we complete the signing
        and broadcast); else returns False (thus returns False for
        all but last signature).
        """
        if self.aborted:
            return False
        if nick not in self.nonrespondants:
            jlog.debug(('add_signature => nick={} '
                       'not in nonrespondants {}').format(nick, self.nonrespondants))
            return False
        sig = base64.b64decode(sigb64)
        inserted_sig = False

        # batch retrieval of utxo data
        utxo = {}
        ctr = 0
        for index, ins in enumerate(self.latest_tx.vin):
            utxo_for_checking = (ins.prevout.hash[::-1], ins.prevout.n)
             # 'deadbeef' markers mean our own input scripts are not queried
            if ins.scriptSig != b"":
                continue
            utxo[ctr] = [index, utxo_for_checking]
            ctr += 1
        utxo_data = jm_single().bc_interface.query_utxo_set([x[
            1] for x in utxo.values()])
        # insert signatures
        for i, u in utxo.items():
            if utxo_data[i] is None:
                continue
            # Check if the sender included the scriptCode in the sig message;
            # if so, also pick up the amount from the utxo data retrieved
            # from the blockchain to verify the segwit-style signature.
            # Note that this allows a mixed SW/non-SW transaction as each utxo
            # is interpreted separately.
            try:
                sig_deserialized = [a for a in iter(btc.CScript(sig))]
            except Exception as e:
                jlog.debug("Failed to parse junk sig message, ignoring.")
                break
            # abort in case we were given a junk sig (note this previously had
            # to check to avoid crashes in verify_tx_input, no longer (Feb 2020)):
            if not all([x for x in sig_deserialized]):
                jlog.debug("Junk signature: " + str(sig_deserialized) + \
                          ", not attempting to verify")
                break
            if len(sig_deserialized) == 2:
                ver_sig, ver_pub = sig_deserialized
                scriptCode = None
            elif len(sig_deserialized) == 3:
                ver_sig, ver_pub, scriptCode =  sig_deserialized
            else:
                jlog.debug("Invalid signature message - not 2 or 3 items")
                break

            ver_amt = utxo_data[i]['value'] if scriptCode else None
            witness = btc.CScriptWitness(
                [ver_sig, ver_pub]) if scriptCode else None

            # don't attempt to parse `pub` as pubkey unless it's valid.
            if scriptCode:
                try:
                    s = btc.pubkey_to_p2wpkh_script(ver_pub)
                except:
                    jlog.debug("Junk signature message, invalid pubkey, ignoring.")
                    break
            scriptSig = btc.CScript([ver_sig, ver_pub]) if not scriptCode else btc.CScript([s])

            # Pre-Feb 2020, we used the third field scriptCode differently in
            # pre- and post-0.5.0; now the scriptCode is implicit (i.e. calculated
            # by underlying library, so that exceptional case is covered.
            sig_good = btc.verify_tx_input(self.latest_tx, u[0], scriptSig,
                    btc.CScript(utxo_data[i]['script']), amount=ver_amt, witness=witness)

            # verification for the native case is functionally identical but
            # adds another flag; so we can allow it here:
            if not sig_good:
                sig_good = btc.verify_tx_input(self.latest_tx, u[0], scriptSig,
                                    btc.CScript(utxo_data[i]['script']), amount=ver_amt,
                                    witness=witness, native=True)
                # if passes, below code executes, and we should change for native:
                scriptSig = btc.CScript([b""])

            if sig_good:
                jlog.debug('found good sig at index=%d' % (u[0]))

                # Note that, due to the complexity of handling multisig or other
                # arbitrary script (considering sending multiple signatures OTW),
                # there is an assumption of p2sh-p2wpkh or p2wpkh, for the segwit
                # case.
                self.latest_tx.vin[u[0]].scriptSig = scriptSig
                if ver_amt:
                    self.latest_tx.wit.vtxinwit[u[0]] = btc.CTxInWitness(
                    btc.CScriptWitness(witness))
                inserted_sig = True

                # check if maker has sent everything possible
                try:
                    self.utxos[nick].remove(u[1])
                except ValueError:
                    pass
                if len(self.utxos[nick]) == 0:
                    jlog.debug(('nick = {} sent all sigs, removing from '
                               'nonrespondant list').format(nick))
                    try:
                        self.nonrespondants.remove(nick)
                    except ValueError:
                        pass
                break
        if not inserted_sig:
            jlog.debug('signature did not match anything in the tx')
            # TODO what if the signature doesnt match anything
            # nothing really to do except drop it, carry on and wonder why the
            # other guy sent a failed signature

        tx_signed = True
        for ins in self.latest_tx.vin:
            if ins.scriptSig == b"":
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
            new_utxos, too_old, too_small = filter_by_coin_age_amt(list(utxos.keys()),
                                                                   age, amt)
            new_utxos_dict = {k: v for k, v in utxos.items() if k in new_utxos}
            for k, v in new_utxos_dict.items():
                addr = self.wallet_service.script_to_addr(v["script"])
                priv = self.wallet_service.get_key_from_addr(addr)
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
            if any(self.wallet_service.get_utxos_by_mixdepth().values()):
                utxos = {}
                for mdutxo in self.wallet_service.get_utxos_by_mixdepth().values():
                    utxos.update(mdutxo)
                priv_utxo_pairs, to, ts = priv_utxo_pairs_from_utxos(
                    utxos, age, amt)
            #Pre-filter the set of external commitments that work for this
            #transaction according to its size and age.
            dummy, extdict = get_podle_commitments()
            if len(extdict) > 0:
                ext_valid, ext_to, ext_ts = filter_by_coin_age_amt(
                    list(extdict.keys()), age, amt)
            else:
                ext_valid = None
            podle_data = generate_podle(priv_utxo_pairs, tries, ext_valid)
        if podle_data:
            jlog.debug("Generated PoDLE: " + repr(podle_data))
            return (commit_type_byte + bintohex(podle_data.commitment),
                    podle_data.serialize_revelation(),
                    "Commitment sourced OK")
        else:
            errmsgheader, errmsg = generate_podle_error_string(priv_utxo_pairs,
                        to, ts, self.wallet_service, self.cjamount,
                        jm_single().config.get("POLICY", "taker_utxo_age"),
                        jm_single().config.get("POLICY", "taker_utxo_amtpercent"))

            with open("commitments_debug.txt", "wb") as f:
                errmsgfileheader = (b"THIS IS A TEMPORARY FILE FOR DEBUGGING; "
                        b"IT CAN BE SAFELY DELETED ANY TIME.\n")
                errmsgfileheader += (b"***\n")
                f.write(errmsgfileheader + errmsg.encode('utf-8'))

            return (None, (priv_utxo_pairs, to, ts), errmsgheader + errmsg)

    def coinjoin_address(self):
        if self.my_cj_addr:
            return self.my_cj_addr
        else:
            #Note: donation code removed (possibly temporarily)
            raise NotImplementedError

    def self_sign(self):
        # now sign it ourselves
        our_inputs = {}
        for index, ins in enumerate(self.latest_tx.vin):
            utxo = (ins.prevout.hash[::-1], ins.prevout.n)
            if utxo not in self.input_utxos.keys():
                continue
            script = self.input_utxos[utxo]["script"]
            amount = self.input_utxos[utxo]['value']
            our_inputs[index] = (script, amount)
        success, msg = self.wallet_service.sign_tx(self.latest_tx, our_inputs)
        if not success:
            jlog.error("Failed to sign transaction: " + msg)

    def push(self):
        jlog.debug('\n' + bintohex(self.latest_tx.serialize()))
        self.txid = bintohex(self.latest_tx.GetTxid()[::-1])
        jlog.info('txid = ' + self.txid)
        #If we are sending to a bech32 address, in case of sweep, will
        #need to use that bech32 for address import, which requires
        #converting to script (Core does not allow import of bech32)
        if self.my_cj_addr.lower()[:2] in ['bc', 'tb']:
            notify_addr = btc.CCoinAddress(self.my_cj_addr).to_scriptPubKey()
        else:
            notify_addr = self.my_cj_addr
        #add the callbacks *before* pushing to ensure triggering;
        #this does leave a dangling notify callback if the push fails, but
        #that doesn't cause problems.
        self.wallet_service.register_callbacks([self.unconfirm_callback], self.txid,
                                   "unconfirmed")
        self.wallet_service.register_callbacks([self.confirm_callback], self.txid,
                                   "confirmed")
        task.deferLater(reactor,
                        float(jm_single().config.getint(
                            "TIMEOUT", "unconfirm_timeout_sec")),
                        self.wallet_service.check_callback_called,
                        self.txid, self.unconfirm_callback,
                        "unconfirmed",
        "transaction with txid: " + str(self.txid) + " not broadcast.")

        tx_broadcast = jm_single().config.get('POLICY', 'tx_broadcast')
        nick_to_use = None
        if tx_broadcast == 'self':
            pushed = jm_single().bc_interface.pushtx(self.latest_tx.serialize())
        elif tx_broadcast in ['random-peer', 'not-self']:
            n = len(self.maker_utxo_data)
            if tx_broadcast == 'random-peer':
                i = random.randrange(n + 1)
            else:
                i = random.randrange(n)
            if i == n:
                pushed = jm_single().bc_interface.pushtx(self.latest_tx.serialize())
            else:
                nick_to_use = list(self.maker_utxo_data.keys())[i]
                pushed = True
        else:
            jlog.info("Only self, random-peer and not-self broadcast "
                      "methods supported. Reverting to self-broadcast.")
            pushed = jm_single().bc_interface.pushtx(self.latest_tx.serialize())
        if not pushed:
            self.on_finished_callback(False, fromtx=True)
        else:
            if nick_to_use:
                # TODO option not currently functional
                return (nick_to_use, self.latest_tx.serialize())
        #if push was not successful, return None

    def self_sign_and_push(self):
        self.self_sign()
        return self.push()

    def tx_match(self, txd):
        # Takers process only in series, so this should not occur:
        assert self.latest_tx is not None
        # check if the transaction matches our created tx:
        if txd.vout != self.latest_tx.vout:
            return False
        return True

    def unconfirm_callback(self, txd, txid):
        if not self.tx_match(txd):
            return False
        jlog.info("Transaction seen on network, waiting for confirmation")
        #To allow client to mark transaction as "done" (e.g. by persisting state)
        self.on_finished_callback(True, fromtx="unconfirmed")
        self.waiting_for_conf = True
        confirm_timeout_sec = float(jm_single().config.get(
            "TIMEOUT", "confirm_timeout_hours")) * 3600
        task.deferLater(reactor, confirm_timeout_sec,
                        self.wallet_service.check_callback_called,
                        txid, self.confirm_callback, "confirmed",
                        "transaction with txid " + str(txid) + " not confirmed.")
        return True

    def confirm_callback(self, txd, txid, confirmations):
        if not self.tx_match(txd):
            return False
        self.waiting_for_conf = False
        if self.aborted:
            #do not trigger on_finished processing (abort whole schedule),
            # but we still return True as we have finished our listening
            # for this tx:
            return True
        jlog.debug("Confirmed callback in taker, confs: " + str(confirmations))
        fromtx=False if self.schedule_index + 1 == len(self.schedule) else True
        waittime = self.schedule[self.schedule_index][4]
        self.on_finished_callback(True, fromtx=fromtx, waittime=waittime,
                                  txdetails=(txd, txid))
        return True

def round_to_significant_figures(d, sf):
    '''Rounding number d to sf significant figures in base 10'''
    for p in range(-10, 15):
        power10 = 10**p
        if power10 > d:
            sf_power10 = 10**sf
            sigfiged = int(round(d/power10*sf_power10)*power10/sf_power10)
            return sigfiged
    raise RuntimeError()
