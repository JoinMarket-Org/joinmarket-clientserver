#! /usr/bin/env python
""" Creates a very simple server for payjoin
    payment requests; uses regtest and a single
    JM wallet, provides a hex seed for the sender
    side of the test.
    Use the same command line setup as for ygrunner.py,
    except you needn't specify --nirc=
    NOTE: to run this test you will need a `key.pem`
    and a `cert.pem` in this (test/) directory,
    created in the standard way for ssl certificates.
    Note that (in test) the client will not verify
    them.
"""
import os
from twisted.web.server import Site
from twisted.web.resource import Resource
from twisted.internet import ssl
from twisted.internet import reactor, endpoints
from common import make_wallets
import pytest
from jmbase import jmprint
import jmbitcoin as btc
from jmclient import load_test_config, jm_single,\
     SegwitWallet, SegwitLegacyWallet, cryptoengine, PayjoinServer

import txtorcon

def setup_failed(arg):
    print("SETUP FAILED", arg)
    reactor.stop()

def create_onion_ep(t, hs_public_port):
    return t.create_onion_endpoint(hs_public_port)

def onion_listen(onion_ep, site):
    return onion_ep.listen(site)

def print_host(ep):
    # required so tester can connect:
    jmprint(str(ep.getHost()))

def start_tor(site, hs_public_port):
    d = txtorcon.connect(reactor)
    d.addCallback(create_onion_ep, hs_public_port)
    d.addErrback(setup_failed)
    d.addCallback(onion_listen, site)
    d.addCallback(print_host)

# TODO change test for arbitrary payment requests
payment_amt = 30000000

dir_path = os.path.dirname(os.path.realpath(__file__))

def get_ssl_context():
    """Construct an SSL context factory from the user's privatekey/cert.
    Here just hardcoded for tests.
    Note this is off by default since the cert needs setting up.
    """
    return ssl.DefaultOpenSSLContextFactory(os.path.join(dir_path, "key.pem"),
                                            os.path.join(dir_path, "cert.pem"))

def test_start_payjoin_server(setup_payjoin_server):
    # set up the wallet that the server owns, and the wallet for
    # the sender too (print the seed):
    if jm_single().config.get("POLICY", "native") == "true":
        walletclass = SegwitWallet
    else:
        walletclass = SegwitLegacyWallet

    wallet_services = make_wallets(2,
                                   wallet_structures=[[1, 3, 0, 0, 0]] * 2,
                                   mean_amt=2,
                                   walletclass=walletclass)
    #the server bot uses the first wallet, the sender the second
    server_wallet_service = wallet_services[0]['wallet']
    jmprint("\n\nTaker wallet seed : " + wallet_services[1]['seed'])
    jmprint("\n")
    server_wallet_service.sync_wallet(fast=True)
    site = Site(PayjoinServer(server_wallet_service))
    # TODO: this is just hardcoded manually for now:
    use_tor = False
    if use_tor:
        jmprint("Attempting to start Tor HS ...")
        # port is hardcoded for test:
        start_tor(site, 7081)
    else:
        # TODO for now, just sticking with TLS test as non-encrypted
        # is unlikely to be used, but add that option.
        reactor.listenSSL(8080, site, contextFactory=get_ssl_context())
        #endpoint = endpoints.TCP4ServerEndpoint(reactor, 8080)
        #endpoint.listen(site)
    reactor.run()

@pytest.fixture(scope="module")
def setup_payjoin_server():
    load_test_config()
    jm_single().bc_interface.tick_forward_chain_interval = 10
    jm_single().bc_interface.simulate_blocks()
    # handles the custom regtest hrp for bech32
    cryptoengine.BTC_P2WPKH.VBYTE = 100
