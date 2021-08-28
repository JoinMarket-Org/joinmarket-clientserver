#!/usr/bin/env python3

# A script for noninteractively creating wallets.
# The implementation is similar to wallet_generate_recover_bip39 in jmclient/wallet_utils.py

import sys
import os
from optparse import OptionParser
from jmclient import (
    load_program_config, add_base_options, SegwitWallet, SegwitLegacyWallet,
    create_wallet, jm_single, wallet_utils
)
from jmbase.support import get_log, jmprint

log = get_log()

def main():
    parser = OptionParser(
        usage='usage: %prog [options] wallet_file_name [password]',
        description='Create a wallet with the given wallet name and password.'
    )
    add_base_options(parser)
    (options, args) = parser.parse_args()
    wallet_name = args[0]
    if options.wallet_password_stdin:
        password = sys.stdin.read().encode("utf-8")
    else:
        assert len(args) > 1, "must provide password via stdin (see --help), or as second argument."
        password = args[1].encode("utf-8")

    load_program_config(config_path=options.datadir)
    wallet_root_path = os.path.join(jm_single().datadir, "wallets")
    wallet_path = os.path.join(wallet_root_path, wallet_name)
    if jm_single().config.get("POLICY", "native") == "true":
        walletclass = SegwitWallet
    else:
        walletclass = SegwitLegacyWallet
    wallet = create_wallet(wallet_path, password, wallet_utils.DEFAULT_MIXDEPTH, walletclass)
    jmprint("recovery_seed:{}"
         .format(wallet.get_mnemonic_words()[0]), "important")
    wallet.close()

if __name__ == "__main__":
    main()
