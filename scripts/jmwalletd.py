#! /usr/bin/env python

import datetime
import os
import time
import abc
import json
import atexit
from io import BytesIO
from twisted.python.log import startLogging
from twisted.internet import endpoints, reactor, ssl, task
from twisted.web.server import Site
from twisted.application.service import Service
from klein import Klein

from optparse import OptionParser
from jmbase import get_log
from jmclient import Maker, jm_single, load_program_config, \
    JMClientProtocolFactory, start_reactor, calc_cj_fee, \
    WalletService, add_base_options, get_wallet_path, \
    open_test_wallet_maybe, wallet_display, YieldGenerator, \
    get_daemon_serving_params, YieldGeneratorService, \
    SNICKERReceiverService, SNICKERReceiver
from jmbase.support import EXIT_ARGERROR, EXIT_FAILURE

jlog = get_log()

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

class InvalidRequestFormat(Exception):
    pass

class BackendNotReady(Exception):
    pass

# error class for services which are only
# started once:
class ServiceAlreadyStarted(Exception):
    pass

class ServiceNotStarted(Exception):
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

class JMWalletDaemon(Service):
    """ This class functions as an HTTP/TLS server,
    with acccess control, allowing a single client(user)
    to control functioning of encapsulated Joinmarket services.
    """

    app = Klein()
    def __init__(self, port):
        """ Port is the port to serve this daemon
        (using HTTP/TLS).
        """
        # cookie tracks single user's state.
        self.cookie = None
        self.port = port
        # the collection of services which this
        # daemon may switch on and off:
        self.services = {}
        # master single wallet service which we
        # allow the client to start/stop.
        self.services["wallet"] = None
        # label for convenience:
        self.wallet_service = self.services["wallet"]
        # Client may start other services, but only
        # one instance.
        self.services["snicker"] = None
        self.services["maker"] = None
        # ensure shut down does not leave dangling services:
        atexit.register(self.stopService)

    def startService(self):
        """ Encapsulates start up actions.
        Here starting the TLS server.
        """
        super().startService()
        # we do not auto-start any service, including the base
        # wallet service, since the client must actively request
        # that with the appropriate credential (password).
        reactor.listenSSL(self.port, Site(self.app.resource()),
                          contextFactory=get_ssl_context("."))

    def stopService(self):
        """ Encapsulates shut down actions.
        """
        # Currently valid authorization tokens must be removed
        # from the daemon:
        self.cookie = None
        # if the wallet-daemon is shut down, all services
        # it encapsulates must also be shut down.
        for name, service in self.services.items():
            if service:
                service.stopService()
        super().stopService()

    @app.handle_errors(NotAuthorized)
    def not_authorized(self, request, failure):
        request.setResponseCode(401)
        return "Invalid credentials."

    @app.handle_errors(NoWalletFound)
    def no_wallet_found(self, request, failure):
        request.setResponseCode(404)
        return "No wallet loaded."

    @app.handle_errors(BackendNotReady)
    def backend_not_ready(self, request, failure):
        request.setResponseCode(500)
        return "Backend daemon not available"

    @app.handle_errors(InvalidRequestFormat)
    def invalid_request_format(self, request, failure):
        request.setResponseCode(401)
        return "Invalid request format."

    @app.handle_errors(ServiceAlreadyStarted)
    def service_already_started(self, request, failure):
        request.setResponseCode(401)
        return "Service already started."

    def service_not_started(self, request, failure):
        request.setResponseCode(401)
        return "Service cannot be stopped as it is not running."

    def check_cookie(self, request):
        request_cookie = request.getHeader(b"JMCookie")
        if self.cookie != request_cookie:
            jlog.warn("Invalid cookie: " + str(
                request_cookie) + ", request rejected.")
            raise NotAuthorized()

    @app.route('/wallet/<string:walletname>/display', methods=['GET'])
    def displaywallet(self, request, walletname):
        print_req(request)
        self.check_cookie(request)
        if not self.wallet_service:
            print("called display but no wallet loaded")
            raise NoWalletFound()
        else:
            walletinfo = wallet_display(self.wallet_service, False, jsonified=True)
            return response(request, walletname=walletname, walletinfo=walletinfo)

    # handling CORS preflight for any route:
    @app.route('/', branch=True, methods=['OPTIONS'])
    def preflight(self, request):
        print_req(request)
        request.setHeader("Access-Control-Allow-Origin", "*")
        request.setHeader("Access-Control-Allow-Methods", "POST")
        # "Cookie" is reserved so we specifically allow our custom cookie using
        # name "JMCookie".
        request.setHeader("Access-Control-Allow-Headers", "Content-Type, JMCookie")

    @app.route('/wallet/<string:walletname>/snicker/start', methods=['GET'])
    def start_snicker(self, request, walletname):
        self.check_cookie(request)
        if not self.wallet_service:
            raise NoWalletFound()
        if self.services["snicker"] and self.services["snicker"].isRunning():
            raise ServiceAlreadyStarted()
        # TODO: allow client to inject acceptance callbacks to Receiver
        self.services["snicker"] = SNICKERReceiverService(
            SNICKERReceiver(self.wallet_service))
        self.services["snicker"].startService()
        # TODO waiting for startup seems perhaps not needed here?
        return response(request, walletname=walletname)

    @app.route('/wallet/<string:walletname>/snicker/stop', methods=['GET'])
    def stop_snicker(self, request, walletname):
        self.check_cookie(request)
        if not self.wallet_service:
            raise NoWalletFound()
        if not self.services["snicker"]:
            raise ServiceNotStarted()
        self.services["snicker"].stopService()
        return response(request, walletname=walletname)

    @app.route('/wallet/<string:walletname>/maker/start', methods=['POST'])
    def start_maker(self, request, walletname):
        """ Use the configuration in the POST body to start the yield generator:
        """
        assert isinstance(request.content, BytesIO)
        config_json = self.get_POST_body(request, ["txfee", "cjfee_a", "cjfee_r",
                                                   "ordertype", "minsize"])
        if not config_json:
            raise InvalidRequestFormat()
        if not self.wallet_service:
            raise NoWalletFound()

        # daemon must be up before this is started; check:
        daemon_serving_host, daemon_serving_port = get_daemon_serving_params()
        if daemon_serving_port == -1 or daemon_serving_host == "":
            raise BackendNotReady()

        self.services["maker"] = YieldGeneratorService(self.wallet_service,
                                [config_json[x] for x in ["txfee", "cjfee_a",
                                "cjfee_r", "ordertype", "minsize"]])
        self.services["maker"].startService()
        return response(request, walletname=walletname)

    @app.route('/wallet/<string:walletname>/maker/stop', methods=['GET'])
    def stop_maker(self, request, walletname):
        self.check_cookie(request)
        if not self.wallet_service:
            raise NoWalletFound()
        if not self.services["maker"]:
            raise ServiceNotStarted()
        self.services["maker"].stopService()
        return response(request, walletname=walletname)

    @app.route('/wallet/<string:walletname>/lock', methods=['GET'])
    def lockwallet(self, request, walletname):
        print_req(request)
        self.check_cookie(request)
        if not self.wallet_service:
            print("called lock but no wallet loaded")
            raise NoWalletFound()
        else:
            self.wallet_service.stopService()
            self.wallet_service = None
            # success status implicit:
            return response(request, walletname=walletname)

    def get_POST_body(self, request, keys):
        """ given a request object, retrieve values corresponding
        to keys keys in a dict, assuming they were encoded using JSON.
        If *any* of the keys are not present, return False, else
        returns a dict of those key-value pairs.
        """
        assert isinstance(request.content, BytesIO)
        json_data = json.loads(request.content.read().decode("utf-8"))
        retval = {}
        for k in keys:
            if k in json_data:
                retval[k] = json_data[k]
            else:
                return False
        return retval

    @app.route('/wallet/<string:walletname>/unlock', methods=['POST'])
    def unlockwallet(self, request, walletname):
        print_req(request)
        assert isinstance(request.content, BytesIO)
        auth_json = self.get_POST_body(request, ["password"])
        if not auth_json:
            raise InvalidRequestFormat()
        password = auth_json["password"]
        if self.wallet_service is None:
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
            self.cookie = request.getHeader(b"JMCookie")
            if self.cookie is None:
                # TODO different error class? this could mislead:
                raise NotAuthorized()

            # the daemon blocks here until the wallet synchronization
            # from the blockchain interface completes; currently this is
            # fine as long as the client handles the response asynchronously:
            self.wallet_service = WalletService(wallet)
            while not self.wallet_service.synced:
                self.wallet_service.sync_wallet(fast=True)
            self.wallet_service.startService()
            # now that the WalletService instance is active and ready to
            # respond to requests, we return the status to the client:
            return response(request, walletname=walletname, already_loaded=False)
        else:
            print('wallet was already unlocked.')
            return response(request, walletname=walletname, already_loaded=True)

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

    if jm_single().bc_interface is None:
        jlog.error("Running jmwallet-daemon requires configured " +
                   "blockchain source.")
        sys.exit(EXIT_FAILURE)
    jlog.info("Starting jmwalletd")

    jm_wallet_daemon = JMWalletDaemon(options.port)
    jm_wallet_daemon.startService()

    nodaemon = jm_single().config.getint("DAEMON", "no_daemon")
    daemon = True if nodaemon == 1 else False
    if jm_single().config.get("BLOCKCHAIN", "network") in ["regtest", "testnet"]:
        startLogging(sys.stdout)
    start_reactor(jm_single().config.get("DAEMON", "daemon_host"),
                  jm_single().config.getint("DAEMON", "daemon_port"),
                  None, daemon=daemon)

if __name__ == "__main__":
    jmwalletd_main()
