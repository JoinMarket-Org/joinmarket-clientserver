#! /usr/bin/env python
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401

import sys
import binascii

import jmbitcoin as btc
from jmclient.configure import get_p2pk_vbyte, jm_single
from jmbase.support import get_log

jlog = get_log()

class SNICKERError(Exception):
    pass

class SNICKERReceiver(object):
    versions = [0, 1]
    supported_flags = []
    import_branch = 0
    # TODO implement http api or similar
    # for polling, here just a file:
    proposals_source = "proposals.txt"

    def __init__(self, wallet, income_threshold=0, acceptance_callback=None):
        """
        Class to manage processing of SNICKER proposals and
        co-signs and broadcasts in case the application level
        configuration permits.

        `acceptance_callback`, if specified, must have arguments
        and return type as for the default_acceptance_callback
        in this class.
        """

        # This is a Joinmarket wallet object.
        # TODO support native segwit BIP84, currently
        # library only supports p2sh-p2wpkh so it must
        # be the BIP49 type.
        self.wallet = wallet

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
            self.acceptance_callback - acceptance_callback

        # A list of currently viable key candidates; these must
        # all be (pub)keys for which the privkey is accessible,
        # i.e. they must be in-wallet keys.
        # This list will be continuously updated by polling the
        # wallet.
        self.candidate_keys = []

        # A list of already processed proposals
        self.processed_proposals = []

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
            sys.exit(1)
        self.processed_proposals.extend(new_proposals)

    def default_acceptance_callback(self, our_ins, their_ins,
                                    our_outs, their_outs):
        """ Accepts lists of inputs as per deserialized tx inputs,
        a single output (belonging to us) as per deserialized tx outputs,
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
        utxos = self.wallet.get_all_utxos()
        our_in_amts = []
        our_out_amts = []
        for i in our_ins:
            txid = i["outpoint"]["hash"]
            idx = i["outpoint"]["index"]
            if (txid, idx) not in utxos.keys():
                jlog.debug("The input utxo was not found: " + btc.safe_hexlify(
                    txid) + ":" + str(idx))
                return False
            our_in_amts.append(utxos[(txid, idx)]["value"])
        for o in our_outs:
            our_out_amts.append(o["value"])
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
                k = binascii.unhexlify(k)
                addr = btc.pubkey_to_p2sh_p2wpkh_address(k)
                # TODO this section can be refactored to not extract the
                # privkey from the wallet.
                try:
                    priv = binascii.unhexlify(self.wallet.get_key_from_addr(addr))
                except AssertionError:
                    jlog.debug("Key not recognized as part of our "
                               "wallet, ignoring.")
                    continue
                result = btc.parse_proposal_to_signed_tx(priv, p,
                                            self.acceptance_callback)
                if result[0] is not None:
                    tx, tweak, unsigned_index, out_spk, vb, fb = result
                    if vb not in self.versions:
                        jlog.debug("Unrecognized SNICKER version, ignoring (" + \
                                   str(vb) + ")")
                        continue
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
                    if not btc.privkey_to_pubkey(tweaked_privkey, False) == tweaked_key:
                        jlog.error("Was not able to recover tweaked pubkey "
                        "from tweaked privkey - code error.")
                        jlog.error("Expected: " + btc.safe_hexlify(tweaked_key))
                        jlog.error("Got: " + binascii.hexlify(btc.privkey_to_pubkey(
                            tweaked_privkey, False)))
                        return False
                    # the recreated private key matches, so we import to the wallet,
                    # note that type = None here is because we use the same
                    # scriptPubKey type as the wallet, this has been implicitly
                    # checked above by deriving the scriptPubKey.
                    self.wallet.import_private_key(self.import_branch,
                        btc.wif_compressed_privkey(btc.safe_hexlify(
                            tweaked_privkey),vbyte=get_p2pk_vbyte()))

                    # we are ready to sign and broadcast
                    final_tx, txid = self.wallet.sign_tx_at_index(tx,
                                                                  unsigned_index)
                    if not final_tx:
                        jlog.error("Unable to sign SNICKER transaction even though "
                                   "it passed validity checks. Code error.")
                        return False
                    jlog.info("Produced valid transaction for signing: ")
                    jlog.info(final_tx)
                        # TODO condition on automatic brdcst or not
                    if not jm_single().bc_interface.pushtx(final_tx):
                        jlog.error("Failed to broadcast SNICKER CJ.")
                        return False
                    self.wallet.remove_old_utxos(btc.deserialize(final_tx))
                    self.wallet.add_new_utxos(btc.deserialize(final_tx), txid)
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

