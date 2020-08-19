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

    # for now these tests are lazy and only cover two scenarios
    # (which may be the most likely):
    # (1) TLS clearnet server
    # (0) onion non-SSL server
    # so the third argument is 0 or 1 as per that.
    # the 4th argument, serverport, is required for (0),
    # since it's an ephemeral HS address and must include the port
    # Note on setting up the Hidden Service:
    # this happens automatically when running test/payjoinserver.py
    # under pytest, and it prints out the hidden service url after
    # some seconds (just as it prints out the wallet hex).

    usessl = int(sys.argv[3])
    serverport = None
    if len(sys.argv) > 4:
        serverport = sys.argv[4]
    load_test_config()
    jm_single().datadir = "."
    check_regtest()
    if not usessl:
        if not serverport:
            print("test configuration error: usessl = 0 assumes onion "
                  "address which must be specified as the fourth argument")
        else:
            pjurl = "http://" + serverport
    else:
        # hardcoded port for tests:
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
    reactor.callWhenRunning(send_payjoin, manager)
    reactor.run()
