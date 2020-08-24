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

# only serving single concurrent user for now; cookie global:
cookie = None
wallet_service = None

# for debugging; twisted.web.server.Request objects do not easily serialize:
def print_req(request):
    print(request)
    print(request.method)
    print(request.uri)
    print(request.args)
    print(request.path)
    print(request.content)
    print(list(request.requestHeaders.getAllRawHeaders()))

class NotAuthorized(Exception):
    pass

class NoWalletFound(Exception):
    pass

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

def check_cookie(request):
    request_cookie = request.getHeader(b"JMCookie")
    if cookie != request_cookie:
        print("Invalid cookie: ", request_cookie)
        raise NotAuthorized()

def start_REST_server(port):
    app = Klein()
    reactor.listenSSL(port, Site(app.resource()), contextFactory=get_ssl_context("."))
    return app

def jmwalletd_main():
    import sys
    parser = OptionParser(usage='usage: %prog [options] [wallet file]')
    parser.add_option('-p', '--port', action='store', type='int',
                      dest='port', default=28183,
                      help='the port over which to serve RPC')
    # TODO: remove the non-relevant base options:
    add_base_options(parser)

    (options, args) = parser.parse_args()

    load_program_config(config_path=options.datadir)

    app = start_REST_server(options.port)

    @app.handle_errors(NotAuthorized)
    def not_authorized(request, failure):
        request.setResponseCode(401)
        return "Invalid credentials."

    @app.handle_errors(NoWalletFound)
    def no_wallet_found(request, failure):
        request.setResponseCode(404)
        return "No wallet loaded."

    @app.route('/wallet/<string:walletname>/display', methods=['GET'])
    def displaywallet(request, walletname):
        print_req(request)
        check_cookie(request)
        if not wallet_service:
            print("called display but no wallet loaded")
            raise NoWalletFound()
        else:
            walletinfo = wallet_display(wallet_service, False, jsonified=True)
            return response(request, walletname=walletname, walletinfo=walletinfo)

    # handling CORS preflight for any route:
    @app.route('/', branch=True, methods=['OPTIONS'])
    def preflight(request):
        print_req(request)
        request.setHeader("Access-Control-Allow-Origin", "*")
        request.setHeader("Access-Control-Allow-Methods", "POST")
        # "Cookie" is reserved so we specifically allow our custom cookie using
        # name "JMCookie".
        request.setHeader("Access-Control-Allow-Headers", "Content-Type, JMCookie")

    @app.route('/wallet/<string:walletname>/lock', methods=['GET'])
    def lockwallet(request, walletname):
        global wallet_service
        print_req(request)
        check_cookie(request)
        if not wallet_service:
            print("called lock but no wallet loaded")
            raise NoWalletFound()
        else:
            wallet_service.stopService()
            # reset local reference to null
            wallet_service = None
            # success status implicit:
            return response(request, walletname=walletname)

    @app.route('/wallet/<string:walletname>/unlock', methods=['POST'])
    def unlockwallet(request, walletname):
        global wallet_service
        global cookie
        print_req(request)
        assert isinstance(request.content, BytesIO)
        auth_json = json.loads(request.content.read().decode("utf-8"))
        password = auth_json["password"]
        if wallet_service is None:
            wallet_path = get_wallet_path(walletname, None)
            try:
                wallet = open_test_wallet_maybe(
                        wallet_path, walletname, 4,
                        password=password.encode("utf-8"),
                        ask_for_password=False)
            except StoragePasswordError:
                raise NotAuthorized("invalid password")
            except StorageError as e:
                # e.g. .lock file exists:
                raise NotAuthorized(repr(e))

            # since wallet loaded correctly, authorization is passed, so set
            # cookie for this wallet (currently THE wallet, daemon does not
            # yet support multiple). This is maintained for as long as the
            # daemon is active (i.e. no expiry currently implemented),
            # or until the user switches to a new wallet.
            cookie = request.getHeader(b"JMCookie")
            if cookie is None:
                # TODO different error class? this could mislead:
                raise NotAuthorized()

            # the daemon blocks here until the wallet synchronization
            # from the blockchain interface completes; currently this is
            # fine as long as the client handles the response asynchronously:
            wallet_service = WalletService(wallet)
            while not wallet_service.synced:
                wallet_service.sync_wallet(fast=True)
            wallet_service.startService()
            # now that the WalletService instance is active and ready to
            # respond to requests, we return the status to the client:
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
