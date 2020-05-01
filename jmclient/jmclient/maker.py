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
        jlog.info('obtained tx\n' + btc.hrt(tx))
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

class P2EPMaker(Maker):
    """ The P2EP Maker object is instantiated for a specific payment,
    with a specific address and expected payment amount. It inherits
    normal Maker behaviour on startup and makes fake offers, which
    it does not follow up in direct peer interaction (to be specific:
    `!fill` requests in privmsg are simply ignored). Under the hood,
    the daemon protocol will allow pubkey exchange with any counterparty,
    but only after the Taker makes a !tx proposal matching our intended
    address and payment amount, which were agreed out of band with the
    sender(Taker) counterparty, do we pass over our intended inputs
    and partially signed transaction, thus information leak to snoopers
    is not possible.
    """
    def __init__(self, wallet_service, mixdepth, amount):
        super(P2EPMaker, self).__init__(wallet_service)
        self.receiving_amount = amount
        self.mixdepth = mixdepth
        # destination mixdepth must be different from that
        # which we source coins from; use the standard "next"
        dest_mixdepth = (self.mixdepth + 1) % self.wallet_service.max_mixdepth
        # Select an unused destination in the external branch
        self.destination_addr = self.wallet_service.get_external_addr(
            dest_mixdepth)
        # Callback to request user permission (for e.g. GUI)
        # args: (1) message, as string
        # returns: True or False
        self.user_check = self.default_user_check
        self.user_info = self.default_user_info_callback

    def default_user_check(self, message):
        if input(message) == 'y':
            return True
        return False

    def default_user_info_callback(self, message):
        """ TODO this is basically the same function
        as taker_info_callback (currently used for GUI);
        fold this and some other convenience functions together
        and use a root CJPeer class in jmbase to avoid code
        duplication.
        """
        jlog.info(message)

    def inform_user_details(self):
        self.user_info("Your receiving address is: " + self.destination_addr)
        self.user_info("You will receive amount: " + str(
            self.receiving_amount) + " satoshis.")
        self.user_info("The sender also needs to know your ephemeral "
                  "nickname: " + jm_single().nickname)
        receive_uri = btc.encode_bip21_uri(self.destination_addr, {
            'amount': btc.sat_to_btc(self.receiving_amount),
            'jmnick': jm_single().nickname
        })
        self.user_info("Receive URI: " + receive_uri)
        self.user_info("This information has also been stored in a file payjoin.txt;"
                  " send it to your counterparty when you are ready.")
        with open("payjoin.txt", "w") as f:
            f.write("Payjoin transfer details:\n\n")
            f.write("Receive URI: " + receive_uri + "\n")
            f.write("Address: " + self.destination_addr + "\n")
            f.write("Amount (in sats): " + str(self.receiving_amount) + "\n")
            f.write("Receiver nick: " + jm_single().nickname + "\n")
        if not self.user_check("Enter 'y' to wait for the payment:"):
            sys.exit(EXIT_SUCCESS)

    def create_my_orders(self):
        """ Fake offer for public consumption.
        Requests to fill will be ignored.
        """
        ordertype = random.choice(("swreloffer", "swabsoffer"))
        minsize = random.randint(100000, 10000000)
        maxsize = random.randint(100000, 1000000000) + minsize
        txfee = random.randint(0, 1000)
        if ordertype == "swreloffer":
            cjfee = str(random.randint(0, 100000)/100000000.0)
        else:
            cjfee = random.randint(0, 10000)
        order = {'oid': 0,
                 'ordertype': ordertype,
                 'minsize': minsize,
                 'maxsize': maxsize,
                 'txfee': txfee,
                 'cjfee': cjfee}

        # sanity check
        assert order['minsize'] >= 0
        assert order['maxsize'] > 0
        if order['minsize'] > order['maxsize']:
            jlog.info('minsize (' + str(order['minsize']) + ') > maxsize (' + str(
                order['maxsize']) + ')')
            return []

        return [order]

    def oid_to_order(self, offer, amount):
        # unreachable; only here to satisy abc.
        pass

    def on_tx_unconfirmed(self, txd, txid):
        """ For P2EP Maker there is no "offer", so
        the second argument is repurposed as the deserialized
        transaction.
        """
        self.user_info("The transaction has been broadcast.")
        self.user_info("Txid is: " + txid)
        self.user_info("Transaction in detail: " + pprint.pformat(txd))
        self.user_info("shutting down.")
        reactor.stop()

    def on_tx_confirmed(self, txd, txid, confirmations):
        # will not be reached except in testing
        self.on_tx_unconfirmed(txd, txid)

    @hexbin
    def on_tx_received(self, nick, txser):
        """ Called when the sender-counterparty has sent a transaction proposal.
        1. First we check for the expected destination and amount (this is
           sufficient to identify our cp, as this info was presumably passed
           out of band, as for any normal payment).
        2. Then we verify the validity of the proposed non-coinjoin
           transaction; if not, reject, otherwise store this as a
           fallback transaction in case the protocol doesn't complete.
        3. Next, we select utxos from our wallet, to add into the
           payment transaction as input. Try to select so as to not
           trigger the UIH2 condition, but continue (and inform user)
           even if we can't (if we can't select any coins, broadcast the
           non-coinjoin payment, if the user agrees).
           Proceeding with payjoin:
        4. We update the output amount at the destination address.
        5. We modify the change amount in the original proposal (which
           will be the only other output other than the destination),
           reducing it to account for the increased transaction fee
           caused by our additional proposed input(s).
        6. Finally we sign our own input utxo(s) and re-serialize the
           tx, allowing it to be sent back to the counterparty.
        7. If the transaction is not fully signed and broadcast within
           the time unconfirm_timeout_sec as specified in the joinmarket.cfg,
           we broadcast the non-coinjoin fallback tx instead.
        """
        try:
            tx = btc.CMutableTransaction.deserialize(txser)
        except Exception as e:
            return (False, 'malformed txhex. ' + repr(e))
        self.user_info('obtained proposed fallback (non-coinjoin) ' +\
                       'transaction from sender:\n' + str(tx))

        if len(tx.vout) != 2:
            return (False, "Transaction has more than 2 outputs; not supported.")
        dest_found = False
        destination_index = -1
        change_index = -1
        proposed_change_value = 0
        for index, out in enumerate(tx.vout):
            if out.scriptPubKey == btc.CCoinAddress(
                self.destination_addr).to_scriptPubKey():
                # we found the expected destination; is the amount correct?
                if not out.nValue == self.receiving_amount:
                    return (False, "Wrong payout value in proposal from sender.")
                dest_found = True
                destination_index = index
            else:
                change_found = True
                proposed_change_out = out.scriptPubKey
                proposed_change_value = out.nValue
                change_index = index

        if not dest_found:
            return (False, "Our expected destination address was not found.")

        # Verify valid input utxos provided and check their value.
        # batch retrieval of utxo data
        utxo = {}
        ctr = 0
        for index, ins in enumerate(tx.vin):
            utxo_for_checking = (ins.prevout.hash[::-1], ins.prevout.n)
            utxo[ctr] = [index, utxo_for_checking]
            ctr += 1

        utxo_data = jm_single().bc_interface.query_utxo_set(
            [x[1] for x in utxo.values()])

        total_sender_input = 0
        for i, u in utxo.items():
            if utxo_data[i] is None:
                return (False, "Proposed transaction contains invalid utxos")
            total_sender_input += utxo_data[i]["value"]

        # Check that the transaction *as proposed* balances; check that the
        # included fee is within 0.3-3x our own current estimates, if not user
        # must decide.
        btc_fee = total_sender_input - self.receiving_amount - proposed_change_value
        self.user_info("Network transaction fee of fallback tx is: " + str(
            btc_fee) + " satoshis.")
        fee_est = estimate_tx_fee(len(tx.vin), len(tx.vout),
                                  txtype=self.wallet_service.get_txtype())
        fee_ok = False
        if btc_fee > 0.3 * fee_est and btc_fee < 3 * fee_est:
            fee_ok = True
        else:
            if self.user_check("Is this transaction fee acceptable? (y/n):"):
                fee_ok = True
        if not fee_ok:
            return (False,
                    "Proposed transaction fee not accepted due to tx fee: " + str(
                            btc_fee))

        # This direct rpc call currently assumes Core 0.17, so not using now.
        # It has the advantage of (a) being simpler and (b) allowing for any
        # non standard coins.
        #
        #res = jm_single().bc_interface.rpc('testmempoolaccept', [txser])
        #print("Got this result from rpc call: ", res)
        #if not res["accepted"]:
        #    return (False, "Proposed transaction was rejected from mempool.")

        # Manual verification of the transaction signatures.
        # TODO handle native segwit properly
        for i, u in utxo.items():
            if not btc.verify_tx_input(tx, i,
                                       tx.vin[i].scriptSig,
                                       btc.CScript(utxo_data[i]["script"]),
                                       amount=utxo_data[i]["value"],
                                       witness=tx.wit.vtxinwit[i].scriptWitness):
                return (False, "Proposed transaction is not correctly signed.")

        # At this point we are satisfied with the proposal. Record the fallback
        # in case the sender disappears and the payjoin tx doesn't happen:
        self.user_info("We'll use this serialized transaction to broadcast if your"
                  " counterparty fails to broadcast the payjoin version:")
        self.user_info(bintohex(txser))
        # Keep a local copy for broadcast fallback:
        self.fallback_tx = tx

        # Now we add our own inputs:
        # See the gist comment here:
        # https://gist.github.com/AdamISZ/4551b947789d3216bacfcb7af25e029e#gistcomment-2799709
        # which sets out the decision Bob must make.
        # In cases where Bob can add any amount, he selects one utxo
        # to keep it simple.
        # In cases where he must choose at least X, he selects one utxo
        # which provides X if possible, otherwise defaults to a normal
        # selection algorithm.
        # In those cases where he must choose X but X is unavailable,
        # he selects all coins, and proceeds anyway with payjoin, since
        # it has other advantages (CIOH and utxo defrag).
        my_utxos = {}
        largest_out = max(self.receiving_amount, proposed_change_value)
        max_sender_amt = max([u['value'] for u in utxo_data])
        not_uih2 = False
        if max_sender_amt < largest_out:
            # just select one coin.
            # have some reasonable lower limit but otherwise choose
            # randomly; note that this is actually a great way of
            # sweeping dust ...
            self.user_info("Choosing one coin at random")
            try:
                my_utxos = self.wallet_service.select_utxos(
                    self.mixdepth, jm_single().DUST_THRESHOLD,
                    select_fn=select_one_utxo)
            except:
                return self.no_coins_fallback()
            not_uih2 = True
        else:
            # get an approximate required amount assuming 4 inputs, which is
            # fairly conservative (but guess by necessity).
            fee_for_select = estimate_tx_fee(len(tx.vin) + 4, 2,
                                             txtype=self.wallet_service.get_txtype())
            approx_sum = max_sender_amt - self.receiving_amount + fee_for_select
            try:
                my_utxos = self.wallet_service.select_utxos(self.mixdepth, approx_sum)
                not_uih2 = True
            except Exception:
                # TODO probably not logical to always sweep here.
                self.user_info("Sweeping all coins in this mixdepth.")
                my_utxos = self.wallet_service.get_utxos_by_mixdepth()[self.mixdepth]
                if my_utxos == {}:
                    return self.no_coins_fallback()
        if not_uih2:
            self.user_info("The proposed tx does not trigger UIH2, which "
                      "means it is indistinguishable from a normal "
                      "payment. This is the ideal case. Continuing..")
        else:
            self.user_info("The proposed tx does trigger UIH2, which it makes "
                      "it somewhat distinguishable from a normal payment,"
                      " but proceeding with payjoin..")

        my_total_in = sum([va['value'] for va in my_utxos.values()])
        self.user_info("We selected inputs worth: " + str(my_total_in))
        # adjust the output amount at the destination based on our contribution
        new_destination_amount = self.receiving_amount + my_total_in
        # estimate the required fee for the new version of the transaction
        total_ins = len(tx.vin) + len(my_utxos.keys())
        est_fee = estimate_tx_fee(total_ins, 2, txtype=self.wallet_service.get_txtype())
        self.user_info("We estimated a fee of: " + str(est_fee))
        new_change_amount = total_sender_input + my_total_in - \
            new_destination_amount - est_fee
        self.user_info("We calculated a new change amount of: " + str(new_change_amount))
        self.user_info("We calculated a new destination amount of: " + str(new_destination_amount))
        # now reconstruct the transaction with the new inputs and the
        # amount-changed outputs
        new_outs = [{"address": self.destination_addr,
                     "value": new_destination_amount}]
        if new_change_amount >= jm_single().BITCOIN_DUST_THRESHOLD:
            new_outs.append({"address": str(btc.CCoinAddress.from_scriptPubKey(
                proposed_change_out)), "value": new_change_amount})
        new_ins = [x[1] for x in utxo.values()]
        new_ins.extend(my_utxos.keys())
        new_tx = btc.make_shuffled_tx(new_ins, new_outs, 2, compute_tx_locktime())


        # sign our inputs before transfer
        our_inputs = {}
        for index, ins in enumerate(new_tx.vin):
            utxo = (ins.prevout.hash[::-1], ins.prevout.n)
            if utxo not in my_utxos:
                continue
            script = my_utxos[utxo]["script"]
            amount = my_utxos[utxo]["value"]
            our_inputs[index] = (script, amount)

        success, msg = self.wallet_service.sign_tx(new_tx, our_inputs)
        if not success:
            return (False, "Failed to sign new transaction, error: " + msg)
        txinfo = tuple((x.scriptPubKey, x.nValue) for x in new_tx.vout)
        self.wallet_service.register_callbacks([self.on_tx_unconfirmed], txinfo, "unconfirmed")
        self.wallet_service.register_callbacks([self.on_tx_confirmed], txinfo, "confirmed")
        # The blockchain interface just abandons monitoring if the transaction
        # is not broadcast before the configured timeout; we want to take
        # action in this case, so we add an additional callback to the reactor:
        reactor.callLater(jm_single().config.getint("TIMEOUT",
                            "unconfirm_timeout_sec"), self.broadcast_fallback)
        return (True, nick, bintohex(new_tx.serialize()))

    def no_coins_fallback(self):
        """ Broadcast, optionally, the fallback non-coinjoin transaction
        because we were not able to select coins to contribute.
        """
        self.user_info("Unable to select any coins; this mixdepth is empty.")
        if self.user_check("Would you like to broadcast the non-coinjoin payment?"):
            self.broadcast_fallback()
            return (False, "Coinjoin unsuccessful, fallback attempted.")
        else:
            self.user_info("You chose not to broadcast; the payment has NOT been made.")
            return (False, "No transaction made.")

    def broadcast_fallback(self):
        self.user_info("Broadcasting non-coinjoin fallback transaction.")
        txid = self.fallback_tx.GetTxid()[::-1]
        success = jm_single().bc_interface.pushtx(self.fallback_tx.serialize())
        if not success:
            self.user_info("ERROR: the fallback transaction did not broadcast. "
                      "The payment has NOT been made.")
        else:
            self.user_info("Payment received successfully, but it was NOT a coinjoin.")
            self.user_info("Txid: " + txid)
        reactor.stop()
