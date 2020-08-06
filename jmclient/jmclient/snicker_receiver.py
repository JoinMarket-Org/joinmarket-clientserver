#! /usr/bin/env python

import sys

import jmbitcoin as btc
from jmclient.configure import jm_single
from jmbase import (get_log, EXIT_FAILURE, utxo_to_utxostr,
                    bintohex, hextobin)

jlog = get_log()

class SNICKERError(Exception):
    pass

class SNICKERReceiver(object):
    supported_flags = []
    import_branch = 0
    # TODO implement http api or similar
    # for polling, here just a file:
    proposals_source = "proposals.txt"

    def __init__(self, wallet_service, income_threshold=0,
                 acceptance_callback=None):
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
        # which can be negative (to account for fees).
        # TODO this will be a config variable.
        self.income_threshold = income_threshold

        # The acceptance callback which defines if we accept
        # a valid proposal and sign it, or not.
        if acceptance_callback is None:
            self.acceptance_callback = self.default_acceptance_callback
        else:
            self.acceptance_callback = acceptance_callback

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

    def poll_for_proposals(self):
        """ Intended to be invoked in a LoopingCall or other
        event loop.
        Retrieves any entries in the proposals_source, then
        compares with existing,
        and invokes parse_proposal on all new entries.
        # TODO considerable thought should go into how to store
        proposals cross-runs, and also handling of keys, which
        must be optional.
        """
        new_proposals = []
        with open(self.proposals_source, "rb") as f:
            current_entries = f.readlines()
        for entry in current_entries:
            if entry in self.processed_proposals:
                continue
            new_proposals.append(entry)
        if not self.process_proposals(new_proposals):
            jlog.error("Critical logic error, shutting down.")
            sys.exit(EXIT_FAILURE)
        self.processed_proposals.extend(new_proposals)

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
        print("gau returned these utxos: ", utxos)
        our_in_amts = []
        our_out_amts = []
        for i in our_ins:
            utxo_for_i = (i.prevout.hash[::-1], i.prevout.n)
            if  utxo_for_i not in utxos.keys():
                success, utxostr =utxo_to_utxostr(utxo_for_i)
                if not success:
                    jlog.error("Code error: input utxo in wrong format.")
                jlog.debug("The input utxo was not found: " + utxostr)
                return False
            our_in_amts.append(utxos[utxo_for_i]["value"])
        for o in our_outs:
            our_out_amts.append(o.nValue)
        if sum(our_out_amts) - sum(our_in_amts) < self.income_threshold:
            return False
        return True

    def process_proposals(self, proposals):
        """ Each entry in `proposals` is of form:
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
            try:
                p, k = kp.split(b',')
            except:
                jlog.error("Invalid proposal string, ignoring: " + kp)
            if k is not None:
                # note that this operation will succeed as long as
                # the key is in the wallet._script_map, which will
                # be true if the key is at an HD index lower than
                # the current wallet.index_cache
                k = hextobin(k.decode('utf-8'))
                addr = self.wallet_service.pubkey_to_addr(k)
                if not self.wallet_service.is_known_addr(addr):
                    jlog.debug("Key not recognized as part of our "
                               "wallet, ignoring.")
                    continue
                # TODO: interface/API of SNICKERWalletMixin would better take
                # address as argument here, not privkey:
                priv = self.wallet_service.get_key_from_addr(addr)
                result = self.wallet_service.parse_proposal_to_signed_tx(
                    priv, p, self.acceptance_callback)
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
                    # TODO: the more sophisticated actions.
                    tweaked_key = btc.snicker_pubkey_tweak(k, tweak)
                    tweaked_spk = btc.pubkey_to_p2sh_p2wpkh_script(tweaked_key)
                    if not tweaked_spk == out_spk:
                        jlog.error("The spk derived from the pubkey does "
                                   "not match the scriptPubkey returned from "
                                   "the snicker module - code error.")
                        return False
                    # before import, we should derive the tweaked *private* key
                    # from the tweak, also:
                    tweaked_privkey = btc.snicker_privkey_tweak(priv, tweak)
                    if not btc.privkey_to_pubkey(tweaked_privkey) == tweaked_key:
                        jlog.error("Was not able to recover tweaked pubkey "
                                   "from tweaked privkey - code error.")
                        jlog.error("Expected: " + bintohex(tweaked_key))
                        jlog.error("Got: " + bintohex(btc.privkey_to_pubkey(
                            tweaked_privkey)))
                        return False
                    # the recreated private key matches, so we import to the wallet,
                    # note that type = None here is because we use the same
                    # scriptPubKey type as the wallet, this has been implicitly
                    # checked above by deriving the scriptPubKey.
                    self.wallet_service.import_private_key(self.import_branch,
                            self.wallet_service._ENGINE.privkey_to_wif(tweaked_privkey))


                    # TODO condition on automatic brdcst or not
                    if not jm_single().bc_interface.pushtx(tx.serialize()):
                        jlog.error("Failed to broadcast SNICKER CJ.")
                        return False
                    self.successful_txs.append(tx)
                    return True
                else:
                    jlog.debug('Failed to parse proposal: ' + result[1])
                    continue
            else:
                # Some extra work to implement checking all possible
                # keys.
                raise NotImplementedError()

        # Completed processing all proposals without any logic
        # errors (whether the proposals were valid or accepted
        # or not).
        return True

