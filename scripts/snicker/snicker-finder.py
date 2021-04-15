#!/usr/bin/env python3

description="""Find SNICKER candidate transactions on
the blockchain.

Using a connection to Bitcoin Core, which allows retrieving
full blocks, this script will list the transaction IDs of
transactions that fit the pattern of SNICKER, as codified in
https://gist.github.com/AdamISZ/2c13fb5819bd469ca318156e2cf25d79
and as checked in the `jmbitcoin.snicker` module function
`is_snicker_tx`, and also optionally, transactions that fit the
pattern of Joinmarket coinjoins (see -j).

Pass a starting and finishing block value as argument. If the
finishing block is not provided, it is assumed to be the latest
block.

**Note that this is slow.**

This script does *NOT* require a wallet, but it does require
a connection to Core, so does not work with `no-blockchain`.
Note that this script obviates the need to have txindex enabled
in Bitcoin Core in order to get full transactions, since it
parses the raw blocks.
"""

from optparse import OptionParser
from jmbase import bintohex, EXIT_ARGERROR, jmprint
import jmbitcoin as btc
from jmclient import (jm_single, add_base_options, load_program_config,
                      check_regtest)
from jmclient.configure import get_log

log = get_log()

def found_str(ttype, tx, b):
    return "Found {} transaction: {} in block: {}".format(
        ttype, bintohex(tx.GetTxid()[::-1]), b)

def write_candidate_to_file(ttype, candidate, blocknum, unspents, filename):
    """ Appends the details for the candidate
    transaction to the chosen textfile.
    """
    with open(filename, "a") as f:
        f.write(found_str(ttype, candidate, blocknum) + "\n")
        f.write(btc.human_readable_transaction(candidate)+"\n")
        f.write("Full transaction hex for creating a proposal is "
             "found in the above.\n")
        f.write("The unspent indices are: " + " ".join(
            (str(u) for u in unspents)) + "\n")
def main():
    parser = OptionParser(
        usage=
        'usage: %prog [options] startingblock [endingblock]',
        description=description
    )
    add_base_options(parser)
    parser.add_option('-f',
                      '--filename',
                      action='store',
                      type='str',
                      dest='candidate_file_name',
                      help='filename to write details of candidate '
                           'transactions, default ./candidates.txt',
                      default='candidates.txt')
    parser.add_option(
        '-j',
        '--include-jm',
        action='store_true',
        dest='include_joinmarket',
        default=True,
        help="scan for Joinmarket coinjoin outputs, as well as SNICKER.")

    (options, args) = parser.parse_args()
    load_program_config(config_path=options.datadir)
    if len(args) not in [1,2]:
        log.error("Invalid arguments, see --help")
        sys.exit(EXIT_ARGERROR)

    startblock = int(args[0])
    if len(args) == 1:
        endblock = jm_single().bc_interface.get_current_block_height()
    else:
        endblock = int(args[1])

    check_regtest()

    for b in range(startblock, endblock + 1):
        block = jm_single().bc_interface.get_block(b)
        for t in btc.get_transactions_in_block(block):
            if btc.is_snicker_tx(t):
                log.info(found_str("SNICKER", t, b))
                # get list of unspent outputs; if empty, skip,
                # otherwise, persist to candidate file with unspents
                # marked.
                unspents = jm_single().bc_interface.get_unspent_indices(t)
                if len(unspents) == 0:
                    continue
                write_candidate_to_file("SNICKER", t, b, unspents,
                                        options.candidate_file_name)
            # note elif avoids wasting computation if we already found SNICKER:
            elif options.include_joinmarket:
                cj_amount, n = btc.is_jm_tx(t)
                # here we don't care about the stats; the tx is printed anyway.
                if cj_amount:
                    log.info(found_str("Joinmarket coinjoin", t, b))
                    unspents = jm_single().bc_interface.get_unspent_indices(t)
                    if len(unspents) == 0:
                        continue
                    write_candidate_to_file("Joinmarket coinjoin", t, b,
                                    unspents, options.candidate_file_name)
        log.info("Finished processing block: {}".format(b))
if __name__ == "__main__":
    main()
    jmprint('done', "success")
