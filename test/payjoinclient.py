#!/usr/bin/env python
import sys
from twisted.internet import reactor
from jmclient.cli_options import check_regtest
from jmclient import (get_wallet_path, WalletService, open_test_wallet_maybe,
                      jm_single, load_test_config,
                      SegwitLegacyWallet, SegwitWallet)
from jmclient.payjoin import send_payjoin, parse_payjoin_setup

if __name__ == "__main__":
    wallet_name = sys.argv[1]
    mixdepth = int(sys.argv[2])
    usessl = int(sys.argv[3])
    bip21uri = None
    if len(sys.argv) > 4:
        bip21uri = sys.argv[4]
    load_test_config()
    jm_single().datadir = "."
    check_regtest()
    if not bip21uri:
        if usessl == 0:
            pjurl = "http://127.0.0.1:8080"
        else:
            pjurl = "https://127.0.0.1:8080"
        bip21uri = "bitcoin:2N7CAdEUjJW9tUHiPhDkmL9ukPtcukJMoxK?amount=0.3&pj=" + pjurl
    wallet_path = get_wallet_path(wallet_name, None)
    if jm_single().config.get("POLICY", "native") == "true":
        walletclass = SegwitWallet
    else:
        walletclass = SegwitLegacyWallet
    wallet = open_test_wallet_maybe(
        wallet_path, wallet_name, 4,
        wallet_password_stdin=False,
        test_wallet_cls=walletclass,
        gap_limit=6)
    wallet_service = WalletService(wallet)
    # in this script, we need the wallet synced before
    # logic processing for some paths, so do it now:
    while not wallet_service.synced:
        wallet_service.sync_wallet(fast=True)
    # the sync call here will now be a no-op:
    wallet_service.startService()
    manager = parse_payjoin_setup(bip21uri, wallet_service, mixdepth)
    if usessl == 0:
        tlshostnames = None
    else:
        tlshostnames = [b"127.0.0.1"]
    reactor.callWhenRunning(send_payjoin, manager, tls_whitelist=tlshostnames)
    reactor.run()
