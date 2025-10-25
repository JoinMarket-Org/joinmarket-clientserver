#!/usr/bin/env python3

description="""This tool is to be used in a case where
a user has a BIP39 seedphrase but has no wallet file and no
backup of imported keys, and they had earlier used SNICKER.

This will usually not be needed as you should keep a backup
of your *.jmdat joinmarket wallet file, which contains all
this information.

Before using this tool, you need to do:
`python wallet-tool.py recover` to recover the wallet from
seed, and then:
`bitcoin-cli rescanblockchain ...`
for an appropriate range of blocks in order for Bitcoin Core
to get a record of the transactions that happened with your
HD addresses.

Then, you can run this script to find all the SNICKER-generated
imported addresses that either did have, or still do have, keys
and have them imported back into the wallet.
(Note that this of course won't find any other non-SNICKER imported
keys, so as a reminder, *always* back up either jmdat wallet files,
or at least, the imported keys themselves.)
"""

import sys
from optparse import OptionParser
from jmbase import bintohex, EXIT_ARGERROR, jmprint
import jmbitcoin as btc
from jmclient import (add_base_options, load_program_config,
                      check_regtest, get_wallet_path, open_test_wallet_maybe,
                      WalletService)
from jmclient.configure import get_log

log = get_log()

def get_pubs_and_indices_of_inputs(tx, wallet_service, ours):
    """ Returns a list of items (pubkey, index),
    one per input at index index, in transaction
    tx, spending pubkey pubkey, if the input is ours
    if ours is True, else returns the complementary list.
    """
    our_ins = []
    not_our_ins = []
    for i in range(len(tx.vin)):
        pub, msg = btc.extract_pubkey_from_witness(tx, i)
        if not pub:
            continue
        if not wallet_service.is_known_script(
            wallet_service.pubkey_to_script(pub)):
            not_our_ins.append((pub, i))
        else:
            our_ins.append((pub, i))
    if ours:
        return our_ins
    else:
        return not_our_ins

def get_pubs_and_indices_of_ancestor_inputs(txin, wallet_service, ours):
    """ For a transaction input txin, retrieve the spent transaction,
    and iterate over its inputs, returning a list of items
    (pubkey, index) all of which belong to us if ours is True,
    or else the complementary set.
    Note: the ancestor transactions must be in the dict txlist, which is
    keyed by txid and values are CTransaction; if not,
    an error occurs. This is assumed to be the case because all ancestors
    must be either in the set returned by wallet_sync, or else in the set
    of SNICKER transactions found so far.
    """
    tx = wallet_service.get_transaction(txin.prevout.hash[::-1])
    return get_pubs_and_indices_of_inputs(tx, wallet_service, ours=ours)

def main():  # noqa: C901
    parser = OptionParser(
        usage=
        'usage: %prog [options] walletname',
        description=description
    )
    parser.add_option('-m', '--mixdepth', action='store', type='int',
                  dest='mixdepth', default=0,
                  help="mixdepth to source coins from")
    parser.add_option('-a',
                      '--amtmixdepths',
                      action='store',
                      type='int',
                      dest='amtmixdepths',
                      help='number of mixdepths in wallet, default 5',
                      default=5)
    parser.add_option('-g',
                      '--gap-limit',
                      type="int",
                      action='store',
                      dest='gaplimit',
                      help='gap limit for wallet, default=6',
                      default=6)
    add_base_options(parser)
    (options, args) = parser.parse_args()
    load_program_config(config_path=options.datadir)
    check_regtest()
    if len(args) != 1:
        log.error("Invalid arguments, see --help")
        sys.exit(EXIT_ARGERROR)
    wallet_name = args[0]
    wallet_path = get_wallet_path(wallet_name, None)
    max_mix_depth = max([options.mixdepth, options.amtmixdepths - 1])
    wallet = open_test_wallet_maybe(
        wallet_path, wallet_name, max_mix_depth,
        wallet_password_stdin=options.wallet_password_stdin,
        gap_limit=options.gaplimit)
    wallet_service = WalletService(wallet)

    # step 1: do a full recovery style sync. this will pick up
    # all addresses that we expect to match transactions against,
    # from a blank slate Core wallet that originally had no imports.
    if not options.recoversync:
        jmprint("Recovery sync was not set, but using it anyway.")
    while not wallet_service.synced:
        wallet_service.sync_wallet(fast=False)
    # Note that the user may be interrupted above by the rescan
    # request; this is as for normal scripts; after the rescan is done
    # (usually, only once, but, this *IS* needed here, unlike a normal
    # wallet generation event), we just try again.

    # Now all address from HD are imported, we need to grab
    # all the transactions for those addresses; this includes txs
    # that *spend* as well as receive our coins, so will include
    # "first-out" SNICKER txs as well as ordinary spends and JM coinjoins.
    seed_transactions = wallet_service.get_all_transactions()

    # Search for SNICKER txs and add them if they match.
    # We proceed recursively; we find all one-out matches, then
    # all 2-out matches, until we find no new ones and stop.

    if len(seed_transactions) == 0:
        jmprint("No transactions were found for this wallet. Did you rescan?")
        return False
    
    new_txs = []
    current_block_heights = set()
    for tx in seed_transactions:
        if btc.is_snicker_tx(tx):
            jmprint("Found a snicker tx: {}".format(bintohex(tx.GetTxid()[::-1])))
            equal_outs = btc.get_equal_outs(tx)
            if not equal_outs:
                continue
            if all([wallet_service.is_known_script(
                x.scriptPubKey) == False for x in [a[1] for a in equal_outs]]):
                # it is now *very* likely that one of the two equal
                # outputs is our SNICKER custom output
                # script; notice that in this case, the transaction *must*
                # have spent our inputs, since it didn't recognize ownership
                # of either coinjoin output (and if it did recognize the change,
                # it would have recognized the cj output also).
                # We try to regenerate one of the outputs, but warn if
                # we can't.
                my_indices = get_pubs_and_indices_of_inputs(tx, wallet_service, ours=True)
                for mypub, mi in my_indices:
                    for eo in equal_outs:
                        for (other_pub, i) in get_pubs_and_indices_of_inputs(tx, wallet_service, ours=False):
                            for (our_pub, j) in get_pubs_and_indices_of_ancestor_inputs(tx.vin[mi], wallet_service, ours=True):
                                our_spk = wallet_service.pubkey_to_script(our_pub)
                                our_priv = wallet_service.get_key_from_addr(
                                    wallet_service.script_to_addr(our_spk))
                                tweak_bytes = btc.ecdh(our_priv[:-1], other_pub)
                                tweaked_pub = btc.snicker_pubkey_tweak(our_pub, tweak_bytes)
                                tweaked_spk = wallet_service.pubkey_to_script(tweaked_pub)
                                if tweaked_spk == eo[1].scriptPubKey:
                                    # TODO wallet.script_to_addr has a dubious assertion, that's why
                                    # we use btc method directly:
                                    address_found = str(btc.CCoinAddress.from_scriptPubKey(btc.CScript(tweaked_spk)))
                                    #address_found = wallet_service.script_to_addr(tweaked_spk)
                                    jmprint("Found a new SNICKER output belonging to us.")
                                    jmprint("Output address {} in the following transaction:".format(
                                        address_found))
                                    jmprint(btc.human_readable_transaction(tx))
                                    jmprint("Importing the address into the joinmarket wallet...")
                                    # NB for a recovery we accept putting any imported keys all into
                                    # the same mixdepth (0); TODO investigate correcting this, it will
                                    # be a little complicated.
                                    success, msg = wallet_service.check_tweak_matches_and_import(wallet_service.script_to_addr(our_spk),
                                                tweak_bytes, tweaked_pub, wallet_service.mixdepth)
                                    if not success:
                                        jmprint("Failed to import SNICKER key: {}".format(msg), "error")
                                        return False
                                    else:
                                        jmprint("... success.")
                                    # we want the blockheight to track where the next-round rescan
                                    # must start from
                                    current_block_heights.add(wallet_service.get_transaction_block_height(tx))
                                    # add this transaction to the next round.
                                    new_txs.append(tx)
    if len(new_txs) == 0:
        return True
    seed_transactions.extend(new_txs)
    earliest_new_blockheight = min(current_block_heights)
    jmprint("New SNICKER addresses were imported to the Core wallet; "
            "do rescanblockchain again, starting from block {}, before "
            "restarting this script.".format(earliest_new_blockheight))
    return False

if __name__ == "__main__":
    res = main()
    if not res:
        jmprint("Script finished, recovery is NOT complete.", level="warning")
    else:
        jmprint("Script finished, recovery is complete.")
