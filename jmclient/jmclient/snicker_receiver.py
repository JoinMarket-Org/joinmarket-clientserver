#! /usr/bin/env python

import os
from twisted.application.service import Service
from twisted.internet import task
import jmbitcoin as btc
from jmclient.configure import jm_single
from jmbase import (get_log, utxo_to_utxostr,
                    hextobin, bintohex)
from twisted.application.service import Service

jlog = get_log()

class SNICKERError(Exception):
    pass

class SNICKERReceiverService(Service):
    def __init__(self, receiver):
        assert isinstance(receiver, SNICKERReceiver)
        self.receiver = receiver
        # main monitor loop
        self.monitor_loop = task.LoopingCall(self.receiver.poll_for_proposals)

    def startService(self):
        """ Encapsulates start up actions.
        This service depends on the receiver's
        wallet service to start, so wait for that.
        """
        self.wait_for_wallet = task.LoopingCall(self.wait_for_wallet_sync)
        self.wait_for_wallet.start(5.0)

    def wait_for_wallet_sync(self):
        if self.receiver.wallet_service.isRunning():
            jlog.info("SNICKER service starting because wallet service is up.")
            self.wait_for_wallet.stop()
            self.monitor_loop.start(5.0)
            super().startService()

    def stopService(self, wallet=False):
        """ Encapsulates shut down actions.
        Optionally also shut down the underlying
        wallet service (default False).
        """
        if self.monitor_loop:
            self.monitor_loop.stop()
        if wallet:
            self.receiver.wallet_service.stopService()
        super().stopService()

    def isRunning(self):
        if self.running == 1:
            return True
        return False

class SNICKERReceiver(object):
    supported_flags = []

    def __init__(self, wallet_service, acceptance_callback=None,
                 info_callback=None):
        """
        Class to manage processing of SNICKER proposals and
        co-signs and broadcasts in case the application level
        configuration permits.

        `acceptance_callback`, if specified, must have arguments
        and return type as for the default_acceptance_callback
        in this class.
        """

        # This is a Joinmarket WalletService object.
        self.wallet_service = wallet_service

        # The simplest filter on accepting SNICKER joins:
        # that they pay a minimum of this value in satoshis,
        # which can be negative (e.g. to account for fees).
        self.income_threshold = jm_single().config.getint("SNICKER",
                                                "lowest_net_gain")

        # The acceptance callback which defines if we accept
        # a valid proposal and sign it, or not.
        if acceptance_callback is None:
            self.acceptance_callback = self.default_acceptance_callback
        else:
            self.acceptance_callback = acceptance_callback

        # callback for information messages to UI
        if not info_callback:
            self.info_callback = self.default_info_callback
        else:
            self.info_callback = info_callback
        # A list of currently viable key candidates; these must
        # all be (pub)keys for which the privkey is accessible,
        # i.e. they must be in-wallet keys.
        # This list will be continuously updated by polling the
        # wallet.
        self.candidate_keys = []

        # A list of already processed proposals
        self.processed_proposals = []

        # maintain a list of all successfully broadcast
        # SNICKER transactions in the current run.
        self.successful_txs = []

        # the main monitoring loop that checks for proposals:
        self.proposal_poll_loop = None

    def default_info_callback(self, msg):
        jlog.info(msg)
        if not os.path.exists(self.proposals_source):
            with open(self.proposals_source, "wb") as f:
                jlog.info("created proposals source file.")


    def default_acceptance_callback(self, our_ins, their_ins,
                                    our_outs, their_outs):
        """ Accepts lists of inputs as CTXIns,
        a single output (belonging to us) as a CTxOut,
        and a list of other outputs (belonging not to us) in same
        format, and must return only True or False representing acceptance.

        Note that this code is relying on the calling function to give
        accurate information about the outputs.
        """
        # we must find the utxo in our wallet to get its amount.
        # this serves as a sanity check that the input is indeed
        # ours.
        # we use get_all* because for these purposes mixdepth
        # is irrelevant.
        utxos = self.wallet_service.get_all_utxos()
        our_in_amts = []
        our_out_amts = []
        for i in our_ins:
            utxo_for_i = (i.prevout.hash[::-1], i.prevout.n)
            if  utxo_for_i not in utxos.keys():
                success, utxostr = utxo_to_utxostr(utxo_for_i)
                if not success:
                    jlog.error("Code error: input utxo in wrong format.")
                jlog.debug("The input utxo was not found: " + utxostr)
                jlog.debug("NB: This can simply mean the coin is already spent.")
                return False
            our_in_amts.append(utxos[utxo_for_i]["value"])
        for o in our_outs:
            our_out_amts.append(o.nValue)
        if sum(our_out_amts) - sum(our_in_amts) < self.income_threshold:
            return False
        return True

    def log_successful_tx(self, tx):
        """ TODO: add dedicated SNICKER log file.
        """
        self.successful_txs.append(tx)
        jlog.info(btc.human_readable_transaction(tx))

    def process_proposals(self, proposals):
        """ This is the "meat" of the SNICKERReceiver service.
        It parses proposals and creates and broadcasts transactions
        with the wallet, assuming all conditions are met.
        Note that this is ONLY called from the proposals poll loop.

        Each entry in `proposals` is of form:
        encrypted_proposal - base64 string
        key - hex encoded compressed pubkey, or ''
        if the key is not null, we attempt to decrypt and
        process according to that key, else cycles over all keys.

        If all SNICKER validations succeed, the decision to spend is
        entirely dependent on self.acceptance_callback.
        If the callback returns True, we co-sign and broadcast the
        transaction and also update the wallet with the new
        imported key (TODO: future versions will enable searching
        for these keys using history + HD tree; note the jmbitcoin
        snicker.py module DOES insist on ECDH being correctly used,
        so this will always be possible for transactions created here.

        Returned is a list of txids of any transactions which
        were broadcast, unless a critical error occurs, in which case
        False is returned (to minimize this function's trust in other
        parts of the code being executed, if something appears to be
        inconsistent, we trigger immediate halt with this return).
        """

        for kp in proposals:
            # handle empty list entries:
            if not kp:
                continue
            try:
                p, k = kp.split(',')
            except:
                # could argue for info or warning debug level,
                # but potential for a lot of unwanted output.
                jlog.debug("Invalid proposal string, ignoring: " + kp)
                continue
            if k is not None:
                # note that this operation will succeed as long as
                # the key is in the wallet._script_map, which will
                # be true if the key is at an HD index lower than
                # the current wallet.index_cache
                k = hextobin(k)
                addr = self.wallet_service.pubkey_to_addr(k)
                if not self.wallet_service.is_known_addr(addr):
                    jlog.debug("Key not recognized as part of our "
                               "wallet, ignoring.")
                    continue
                result = self.wallet_service.parse_proposal_to_signed_tx(
                    addr, p, self.acceptance_callback)
                if result[0] is not None:
                    tx, tweak, out_spk = result
                    # We will: rederive the key as a sanity check,
                    # and see if it matches the claimed spk.
                    # Then, we import the key into the wallet
                    # (even though it's re-derivable from history, this
                    # is the easiest for a first implementation).
                    # Finally, we co-sign, then push.
                    # (Again, simplest function: checks already passed,
                    # so do it automatically).
                    tweaked_key = btc.snicker_pubkey_tweak(k, tweak)
                    tweaked_spk = self.wallet_service.pubkey_to_script(
                        tweaked_key)
                    # Derive original path to make sure we change
                    # mixdepth:
                    source_path = self.wallet_service.script_to_path(
                        self.wallet_service.pubkey_to_script(k))
                    # NB This will give the correct source mixdepth independent
                    # of whether the key is imported or not:
                    source_mixdepth = self.wallet_service.get_details(
                        source_path)[0]
                    if not tweaked_spk == out_spk:
                        jlog.error("The spk derived from the pubkey does "
                                   "not match the scriptPubkey returned from "
                                   "the snicker module - code error.")
                        return False
                    # before import, we should derive the tweaked *private* key
                    # from the tweak, also; failure of this critical sanity check
                    # is a code error. If the recreated private key matches, we
                    # import to the wallet. Note that this happens *before* pushing
                    # the coinjoin transaction to the network, which is advisably
                    # conservative (never possible to have broadcast a tx without
                    # having already stored the output's key).
                    success, msg = self.wallet_service.check_tweak_matches_and_import(
                        addr, tweak, tweaked_key, source_mixdepth)
                    if not success:
                        jlog.error(msg)
                        return False

                    # TODO condition on automatic brdcst or not
                    if not jm_single().bc_interface.pushtx(tx.serialize()):
                        # this represents an error about state (or conceivably,
                        # an ultra-short window in which the spent utxo was
                        # consumed in another transaction), but not really
                        # an internal logic error, so we do NOT return False
                        jlog.error("Failed to broadcast SNICKER coinjoin: " +\
                                   bintohex(tx.GetTxid()[::-1]))
                        jlog.info(btc.human_readable_transaction(tx))
                    jlog.info("Successfully broadcast SNICKER coinjoin: " +\
                                  bintohex(tx.GetTxid()[::-1]))
                    self.log_successful_tx(tx)
                else:
                    jlog.debug('Failed to parse proposal: ' + result[1])
            else:
                # Some extra work to implement checking all possible
                # keys.
                jlog.info("Proposal without pubkey was not processed.")

        # Completed processing all proposals without any logic
        # errors (whether the proposals were valid or accepted
        # or not).
        return True

