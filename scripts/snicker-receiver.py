#! /usr/bin/env python
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401

import sys
from twisted.internet import reactor
from twisted.internet.task import LoopingCall
from twisted.python.log import startLogging
from optparse import OptionParser

from jmbase import get_log, jmprint
from cli_options import add_common_wallet_options
from jmclient import SNICKERReceiver, load_program_config, \
     get_wallet_path, open_test_wallet_maybe, jm_single, sync_wallet

""" This script allows the user to run SNICKER as a receiver
using a Joinmarket wallet, standalone (i.e. not used for
Joinmarket coinjoins or any other function).
Funds for joins can be sourced from any mixdepth, and coinjoin
outputs are placed in the imported section of mixdepth 0 (private
keys are imported into the wallet file).
"""

jlog = get_log()

def snicker_receive():
    parser = OptionParser(usage='usage: %prog [options] [wallet file]')
    add_common_wallet_options(parser)
    parser.add_option('-i', '--income-threshold', action='store', type='int',
                      dest='income', default=0,
                      help='Minimum net income for a coinjoin, in satoshis. '
                      'Can be negative.')
    parser.add_option('-m', '--mixdepth', action='store', type='int',
                      dest='mixdepth', default=None,
                      help="highest mixdepth to use in the wallet")
    (options, args) = parser.parse_args()
    if len(args) < 1:
        parser.error('Needs a wallet')
        sys.exit(0)
    wallet_name = args[0]

    load_program_config()

    wallet_path = get_wallet_path(wallet_name, 'wallets')
    wallet = open_test_wallet_maybe(wallet_path, wallet_name, options.mixdepth)

    while not jm_single().bc_interface.wallet_synced:
        sync_wallet(wallet, fast=options.fastsync)

    # this uses the default acceptance callback, which accepts any
    # transaction meeting the income threshold:
    sR = SNICKERReceiver(wallet, income_threshold=options.income)
    if jm_single().config.get("BLOCKCHAIN", "network") in ["regtest", "testnet"]:
        sR.proposals_source = "test_proposals.txt"
        startLogging(sys.stdout)

    # since this is a monitoring loop, not a service, we can avoid
    # instantiating a protocol instance and just use a looping call.
    loop = LoopingCall(sR.poll_for_proposals)

    jmprint("Starting to monitor the proposals source every 10 seconds...", "info")
    loop.start(10, now=False)

    reactor.run()

if __name__ == "__main__":
    snicker_receive()
    jmprint('done', "success")
