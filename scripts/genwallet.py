#!/usr/bin/env python3

import sys
import os
from optparse import OptionParser
from jmclient import load_program_config, add_base_options, SegwitWallet, SegwitLegacyWallet, create_wallet, jm_single
from jmbase.support import get_log, jmprint

log = get_log()

def main():
    parser = OptionParser(
    usage='usage: %prog [options] wallet_file_name passphrase',
    description='Create a wallet with the given wallet name and passphrase.')
    add_base_options(parser)
    (options, args) = parser.parse_args()
    if options.wallet_password_stdin:
        stdin = sys.stdin.read()
        passphrase = stdin.encode("utf-8")
    else:
        assert len(args) > 1, "must provide passphrase via stdin (see --help), or as second argument."
        passphrase = args[1].encode("utf-8")
    load_program_config(config_path=options.datadir)
    wallet_root_path = os.path.join(jm_single().datadir, "wallets")
    wallet_name = os.path.join(wallet_root_path, args[0])
    if jm_single().config.get("POLICY", "native") == "true":
        walletclass = SegwitWallet
    else:
        walletclass = SegwitLegacyWallet
    wallet = create_wallet(wallet_name, passphrase, 4, walletclass)
    jmprint("recovery_seed:{}"
         .format(wallet.get_mnemonic_words()[0]), "important")
    wallet.close()

if __name__ == "__main__":
    main()
