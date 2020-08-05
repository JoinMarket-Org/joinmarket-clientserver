#! /usr/bin/env python

import datetime
import os
import time
import abc
import json
from io import BytesIO
from twisted.python.log import startLogging
from twisted.internet import endpoints, reactor, ssl
from twisted.web.server import Site
from klein import Klein

from optparse import OptionParser
from jmbase import get_log
from jmclient import Maker, jm_single, load_program_config, \
    JMClientProtocolFactory, start_reactor, calc_cj_fee, \
    WalletService, add_base_options, get_wallet_path, open_test_wallet_maybe, wallet_display
from jmbase.support import EXIT_ARGERROR, EXIT_FAILURE

jlog = get_log()

def get_ssl_context(cert_directory):
    """Construct an SSL context factory from the user's privatekey/cert.
    TODO:
    Currently just hardcoded for tests.
    """
    return ssl.DefaultOpenSSLContextFactory(os.path.join(cert_directory, "key.pem"),
                                            os.path.join(cert_directory, "cert.pem"))

def response(request, succeed=True, status=200, **kwargs):
    """
    Build the response body as JSON and set the proper content-type
    header.
    """
    request.setHeader('Content-Type', 'application/json')
    request.setHeader('Access-Control-Allow-Origin', '*')
    request.setResponseCode(status)
    return json.dumps(
        [{'succeed': succeed, 'status': status, **kwargs}])

def start_REST_server(port):
    app = Klein()
    reactor.listenSSL(port, Site(app.resource()), contextFactory=get_ssl_context("."))
    return app

def jmwalletd_main():
    import sys
    wallet_service = None
    parser = OptionParser(usage='usage: %prog [options] [wallet file]')
    parser.add_option('-p', '--port', action='store', type='int',
                      dest='port', default=28183,
                      help='the port over which to serve RPC')
    # TODO: remove the non-relevant base options:
    add_base_options(parser)

    (options, args) = parser.parse_args()

    load_program_config(config_path=options.datadir)

    app = start_REST_server(options.port)

    @app.route('/wallet/<string:walletname>/display', methods=['GET'])
    def displaywallet(request, walletname):
        print(request)
        nonlocal wallet_service
        if not wallet_service:
            #todo return a specific error
            print('called display but no wallet loaded.')
        else:
            walletinfo = wallet_display(wallet_service, False, jsonified=True)
            return response(request, walletname=walletname, walletinfo=walletinfo)

    # handling CORS preflight:
    #@app.route('/', branch=True, methods=['OPTIONS'])
    @app.route('/wallet/<string:walletname>/unlock', methods=['OPTIONS'])
    def preflight(request, walletname):
        print(request)
        request.setHeader("Access-Control-Allow-Origin", "*")
        request.setHeader("Access-Control-Allow-Methods", "POST")
        request.setHeader("Access-Control-Allow-Headers", "Content-Type")

    @app.route('/wallet/<string:walletname>/display', methods=['OPTIONS'])
    def preflight2(request, walletname):
        print(request)
        request.setHeader("Access-Control-Allow-Origin", "*")
        request.setHeader("Access-Control-Allow-Methods", "GET")
        request.setHeader("Access-Control-Allow-Headers", "Content-Type")

    @app.route('/wallet/<string:walletname>/unlock', methods=['POST'])
    def unlockwallet(request, walletname):
        print(request)
        assert isinstance(request.content, BytesIO)
        passwordjson = request.content.read().decode("utf-8")
        password = json.loads(passwordjson)["password"]
        nonlocal wallet_service
        if wallet_service is None:
            wallet_path = get_wallet_path(walletname, None)
            wallet = open_test_wallet_maybe(
                    wallet_path, walletname, 4,
                    password=password.encode("utf-8"),
                    ask_for_password=False)
            wallet_service = WalletService(wallet)
            while not wallet_service.synced:
                wallet_service.sync_wallet(fast=True)
            wallet_service.startService()
            return response(request, walletname=walletname, already_loaded=False)
        else:
            print('wallet was already unlocked.')
            return response(request, walletname=walletname, already_loaded=True)

    if jm_single().bc_interface is None:
        jlog.error("Running jmwallet-daemon requires configured " +
                   "blockchain source.")
        sys.exit(EXIT_FAILURE)
    jlog.info("Starting jmwalletd")

    nodaemon = jm_single().config.getint("DAEMON", "no_daemon")
    daemon = True if nodaemon == 1 else False
    if jm_single().config.get("BLOCKCHAIN", "network") in ["regtest", "testnet"]:
        startLogging(sys.stdout)
    start_reactor(jm_single().config.get("DAEMON", "daemon_host"),
                  jm_single().config.getint("DAEMON", "daemon_port"),
                  None, daemon=daemon)

if __name__ == "__main__":
    jmwalletd_main()
