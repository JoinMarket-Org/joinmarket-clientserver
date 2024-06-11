import os
import json
from io import BytesIO
from jmclient.wallet_utils import wallet_showutxos
from twisted.internet import reactor, ssl
from twisted.web.server import Site
from twisted.application.service import Service
from autobahn.twisted.websocket import listenWS
from klein import Klein
import pprint

from jmbitcoin import human_readable_transaction
from jmclient import Taker, jm_single, \
    JMClientProtocolFactory, start_reactor, \
    WalletService, get_wallet_path, direct_send, \
    open_test_wallet_maybe, wallet_display, SegwitLegacyWallet, \
    SegwitWallet, get_daemon_serving_params, YieldGeneratorService, \
    create_wallet, get_max_cj_fee_values, \
    StorageError, StoragePasswordError, JmwalletdWebSocketServerFactory, \
    JmwalletdWebSocketServerProtocol, RetryableStorageError, \
    SegwitWalletFidelityBonds, wallet_gettimelockaddress, \
    NotEnoughFundsException, get_tumble_log, get_tumble_schedule, \
    get_schedule, get_tumbler_parser, schedule_to_text, \
    tumbler_filter_orders_callback, tumbler_taker_finished_update, \
    validate_address, FidelityBondMixin, BaseWallet, WalletError, \
    ScheduleGenerationErrorNoFunds, BIP39WalletMixin, auth
from jmbase.support import get_log, utxostr_to_utxo, JM_CORE_VERSION

jlog = get_log()

api_version_string = "/api/v1"

# for debugging; twisted.web.server.Request objects do not easily serialize:
def print_req(request):
    print(request)
    print(request.method)
    print(request.uri)
    print(request.args)
    print(request.path)
    print(request.content)
    print(list(request.requestHeaders.getAllRawHeaders()))

class AuthorizationError(Exception):
    pass

class InvalidCredentials(AuthorizationError):
    pass

class InvalidToken(AuthorizationError):
    pass

class InsufficientScope(AuthorizationError):
    pass

class NoWalletFound(Exception):
    pass

class InvalidRequestFormat(Exception):
    pass

class BackendNotReady(Exception):
    pass

# error class for actions which are inconsistent with
# current state
class ActionNotAllowed(Exception):
    pass

# error class for services which are only
# started once:
class ServiceAlreadyStarted(Exception):
    pass

# for the special case of the wallet service:
class WalletAlreadyUnlocked(Exception):
    pass

# in wallet creation, if the file exists:
class WalletAlreadyExists(Exception):
    pass

# if the file cannot be created or opened
# due to existing lock:
class LockExists(Exception):
    pass

# some actions require configuration variables
# to proceed (related to fees, in particular);
# if those are not allowed to fall back to defaults,
# we return an error:
class ConfigNotPresent(Exception):
    pass

class ServiceNotStarted(Exception):
    pass

# raised when a requested transaction did
# not successfully broadcast.
class TransactionFailed(Exception):
    pass

# raised when we tried to start a Maker,
# but the wallet was empty/not enough.
class NotEnoughCoinsForMaker(Exception):
    pass

# raised when we tried to start the tumbler,
# but the wallet was empty/not enough.
class NotEnoughCoinsForTumbler(Exception):
    pass

# raised when we cannot read data from our
# yigen-statement csv file:
class YieldGeneratorDataUnreadable(Exception):
    pass


def get_ssl_context(cert_directory):
    """Construct an SSL context factory from the user's privatekey/cert.
    TODO:
    Currently just hardcoded for tests.
    """
    return ssl.DefaultOpenSSLContextFactory(os.path.join(cert_directory, "key.pem"),
                                            os.path.join(cert_directory, "cert.pem"))

def make_jmwalletd_response(request, status=200, **kwargs):
    """
    Build the response body as JSON and set the proper content-type
    header.
    """
    request.setHeader('Content-Type', 'application/json')
    request.setHeader('Access-Control-Allow-Origin', '*')
    request.setHeader("Cache-Control", "no-cache, no-store, must-revalidate")
    request.setHeader("Pragma", "no-cache")
    request.setHeader("Expires", "Sat, 26 Jul 1997 05:00:00 GMT")
    request.setResponseCode(status)
    return json.dumps(kwargs)

CJ_TAKER_RUNNING, CJ_MAKER_RUNNING, CJ_NOT_RUNNING = range(3)

class JMWalletDaemon(Service):
    """ This class functions as an HTTP/TLS server,
    with access control, allowing a single client(user)
    to control functioning of encapsulated Joinmarket services.
    """

    app = Klein()
    def __init__(self, port, wss_port, tls=True):
        """ Port is the port to serve this daemon
        (using HTTP/TLS).
        wss_factory is a twisted protocol factory for the
        websocket connections for clients to subscribe to updates.
        """
        # cookie tracks single user's state.
        self.token = auth.JMTokenAuthority()
        self.active_session = False
        self.port = port
        self.wss_port = wss_port
        self.tls = tls
        pref = "wss" if self.tls else "ws"
        self.wss_url = pref + "://127.0.0.1:" + str(wss_port)
        # the collection of services which this
        # daemon may switch on and off:
        self.services = {}
        # master single wallet service which we
        # allow the client to start/stop.
        self.services["wallet"] = None
        self.wallet_name = "None"
        # Client may start other services, but only
        # one instance.
        self.services["snicker"] = None
        self.services["maker"] = None
        # our taker object will handle doing sends/taker-cjs:
        self.taker = None
        # the factory of type JmwalletdWebsocketServerFactory,
        # which has notification methods that can be passed
        # as callbacks for in-wallet events:
        self.wss_factory = None
        # keep track of whether we're running actively as maker
        # or taker:
        self.coinjoin_state = CJ_NOT_RUNNING
        # keep track of client side connections so they
        # can be shut down cleanly:
        self.coinjoin_connection = None
        # Options for generating a tumble schedule / running the tumbler.
        # Doubles as flag for indicating whether we're currently running
        # a tumble schedule.
        self.tumbler_options = None
        self.tumble_log = None
        # save settings we might temporary change runtime
        self.default_policy_tx_fees = jm_single().config.get("POLICY",
                                                             "tx_fees")

    def get_client_factory(self):
        return JMClientProtocolFactory(self.taker)

    def activate_coinjoin_state(self, state):
        """ To be set when a maker or taker
        operation is initialized; they cannot
        both operate at once, nor can we run repeated
        instances of either (hence 'activate' rather than 'set').
        Since running the maker means running the
        YieldGeneratorService, the start and stop of that service
        is encapsulated here.
        Returns:
        True if and only if the switching on of the chosen state
        (including the 'switching on' of the 'not running' state!)
        was actually enacted. If the new chosen state cannot be
        switched on, returns False.
        """
        assert state in [CJ_MAKER_RUNNING, CJ_TAKER_RUNNING, CJ_NOT_RUNNING]
        if state == self.coinjoin_state:
            # cannot re-active currently active state, as per above;
            # note that this rejects switching "off" when we're already
            # off.
            return False
        elif self.coinjoin_state == CJ_NOT_RUNNING:
            self.coinjoin_state = state
            self.wss_factory.sendCoinjoinStatusUpdate(self.coinjoin_state)
            return True
        elif state == CJ_NOT_RUNNING:
            # currently active, switching off.
            self.coinjoin_state = state
            self.wss_factory.sendCoinjoinStatusUpdate(self.coinjoin_state)
            return True
        # anything else is a conflict and we can't change:
        return False

    def startService(self):
        """ Encapsulates start up actions.
        Here starting the TLS server.
        """
        super().startService()
        # we do not auto-start any service, including the base
        # wallet service, since the client must actively request
        # that with the appropriate credential (password).
        # initialise the web socket service for subscriptions
        self.wss_factory = JmwalletdWebSocketServerFactory(self.wss_url, self.token)
        self.wss_factory.protocol = JmwalletdWebSocketServerProtocol
        if self.tls:
            cf = get_ssl_context(os.path.join(jm_single().datadir, "ssl"))
            listener_rpc = reactor.listenSSL(self.port, Site(
                self.app.resource()), contextFactory=cf)
            listener_ws = listenWS(self.wss_factory, contextFactory=cf)
        else:
            listener_rpc = reactor.listenTCP(self.port, Site(
                self.app.resource()))
            listener_ws = listenWS(self.wss_factory, contextFactory=None)
        return (listener_rpc, listener_ws)

    def stopService(self):
        """ Top-level service (JMWalletDaemon itself) shutdown.
        """
        self.stopSubServices()
        super().stopService()

    def stopSubServices(self):
        """ This:
        - shuts down the wallet service, and deletes its name.
        - removes the currently valid auth token.
        - shuts down any other running sub-services, such as yieldgenerator.
        - shuts down (aborts) any taker-side coinjoining happening.
        """
        self.token.reset()
        self.active_session = False
        self.wss_factory.active_session = False
        self.wallet_name = None
        # if the wallet-daemon is shut down, all services
        # it encapsulates must also be shut down.
        for name, service in self.services.items():
            if service and service.running == 1:
                service.stopService()
        # these Services cannot be guaranteed to be
        # re-startable (the WalletService for example,
        # is explicitly not). So we remove these references
        # after stopping.
        for n in self.services:
            self.services[n] = None
        # taker is not currently encapsulated with a Service;
        # if it is running, shut down:
        if self.coinjoin_state == CJ_TAKER_RUNNING:
            self.taker.aborted = True
            self.taker_finished(False)

    def auth_err(self, request, error, description=None):
        value = f'Bearer, error="{error}"'
        if description is not None:
            value += f', error_description="{description}"'
        request.setHeader("WWW-Authenticate", value)
        return

    def err(self, request, message):
        """ Return errors in a standard format.
        """
        request.setHeader('Content-Type', 'application/json')
        return json.dumps({"message": message})

    @app.handle_errors(ActionNotAllowed)
    def not_allowed(self, request, failure):
        request.setResponseCode(400)
        return self.err(request, "Action not allowed")

    @app.handle_errors(InvalidCredentials)
    def invalid_credentials(self, request, failure):
        request.setResponseCode(401)
        return self.err(request, "Invalid credentials.")

    @app.handle_errors(InvalidToken)
    def invalid_token(self, request, failure):
        request.setResponseCode(401)
        return self.auth_err(request, "invalid_token", failure.getErrorMessage())

    @app.handle_errors(InsufficientScope)
    def insufficient_scope(self, request, failure):
        request.setResponseCode(403)
        return self.auth_err(
            request,
            "insufficient_scope",
            "The request requires higher privileges (scopes) than provided by "
            "the scopes granted to the client and represented by the access token.",
        )

    @app.handle_errors(NoWalletFound)
    def no_wallet_found(self, request, failure):
        request.setResponseCode(404)
        return self.err(request, "No wallet loaded.")

    @app.handle_errors(BackendNotReady)
    def backend_not_ready(self, request, failure):
        request.setResponseCode(503)
        return self.err(request, "Backend daemon not available")

    @app.handle_errors(InvalidRequestFormat)
    def invalid_request_format(self, request, failure):
        request.setResponseCode(400)
        return self.err(request, "Invalid request format.")

    @app.handle_errors(ServiceAlreadyStarted)
    def service_already_started(self, request, failure):
        request.setResponseCode(401)
        return self.err(request, "Service already started.")

    @app.handle_errors(WalletAlreadyUnlocked)
    def wallet_already_unlocked(self, request, failure):
        request.setResponseCode(401)
        return self.err(request, "Wallet already unlocked.")

    @app.handle_errors(WalletAlreadyExists)
    def wallet_already_exists(self, request, failure):
        request.setResponseCode(409)
        return self.err(request, "Wallet file cannot be overwritten.")

    @app.handle_errors(LockExists)
    def lock_exists(self, request, failure):
        request.setResponseCode(409)
        return self.err(request,
                    "Wallet cannot be created/opened, it is locked.")

    @app.handle_errors(ConfigNotPresent)
    def config_not_present(self, request, failure):
        request.setResponseCode(409)
        return self.err(request,
            "Action cannot be performed, config vars are not set.")

    @app.handle_errors(ServiceNotStarted)
    def service_not_started(self, request, failure):
        request.setResponseCode(401)
        return self.err(request,
                "Service cannot be stopped as it is not running.")

    @app.handle_errors(TransactionFailed)
    def transaction_failed(self, request, failure):
        # TODO 409 as 'conflicted state' may not be ideal?
        request.setResponseCode(409)
        return self.err(request, "Transaction failed.")

    @app.handle_errors(NotEnoughCoinsForMaker)
    def not_enough_coins(self, request, failure):
        # as above, 409 may not be ideal
        request.setResponseCode(409)
        return self.err(request, "Maker could not start, no confirmed coins.")

    @app.handle_errors(NotEnoughCoinsForTumbler)
    def not_enough_coins_tumbler(self, request, failure):
        # as above, 409 may not be ideal
        request.setResponseCode(409)
        return self.err(request, "Tumbler could not start, no confirmed coins.")

    @app.handle_errors(YieldGeneratorDataUnreadable)
    def yieldgenerator_report_unavailable(self, request, failure):
        request.setResponseCode(404)
        return self.err(request, "Yield generator report not available.")

    def check_cookie(self, request, *, verify_exp: bool = True):
        # Token itself is stated after `Bearer ` prefix, it must be removed
        access_token = request.getHeader("Authorization")[7:]
        try:
            self.token.verify(access_token)
        except auth.InvalidScopeError:
            raise InsufficientScope()
        except auth.ExpiredSignatureError:
            if verify_exp:
                raise InvalidToken("The access token provided is expired.")
            else:
                pass
        except Exception as e:
            jlog.debug(e)
            raise InvalidToken(
                "The access token provided is revoked, malformed, or invalid for other reasons."
            )
    
    def check_cookie_if_present(self, request):
        auth_header = request.getHeader('Authorization')
        if auth_header is not None:
            self.check_cookie(request)

    def get_POST_body(self, request, required_keys, optional_keys=None):
        """ given a request object, retrieve values corresponding
        to keys in a dict, assuming they were encoded using JSON.
        If *any* of the required_keys are not present or required_keys
        and optional_keys clash, return False, else returns a dict of those
        key-value pairs and any of the optional key-value pairs.
        """
        assert isinstance(request.content, BytesIO)
        # we swallow any formatting failure here:
        try:
            json_data = json.loads(request.content.read().decode(
                "utf-8"))
            required_body = {k: json_data[k] for k in required_keys}

            if optional_keys is not None:
                optional_body = {k: json_data[k] for k in optional_keys if k in json_data}

                for key in optional_body:
                    if not key in required_body:
                        required_body[key] = optional_body[key]
                    else:
                        return False

            return required_body
        except:
            return False

    def parse_tumbler_options_from_json(self, tumbler_options_json):
        parsed_tumbler_options = {}

        for key, val in tumbler_options_json.items():
            if isinstance(val, list):
                # Convert JSON lists to tuples.
                parsed_tumbler_options[key] = tuple(val)
            elif key == 'order_choose_fn':
                # Todo: No support for custom order choose function via API yet.
                pass
            else:
                parsed_tumbler_options[key] = val

        return parsed_tumbler_options

    def initialize_wallet_service(self, request, wallet, wallet_name, **kwargs):
        """ Called only when the wallet has loaded correctly, so
        authorization is passed, so set cookie for this wallet
        (currently THE wallet, daemon does not yet support multiple).
        This is maintained for 30 minutes currently, or until the user
        switches to a new wallet.
        If an existing wallet_service was in place, it needs to be stopped.
        Here we must also register transaction update callbacks, to fire
        events in the websocket connection.
        """
        if self.services["wallet"]:
            # we allow a new successful authorization (with password)
            # to shut down the currently running service(s), if there
            # are any.
            # This will stop all supporting services and wipe
            # state (so wallet, maker service and cookie/token):
            self.stopSubServices()

        self.services["wallet"] = WalletService(wallet)
        # restart callback needed, otherwise wallet creation will
        # automatically lead to shutdown.
        # TODO: this means that it's possible, in non-standard usage
        # patterns, for the sync to complete without a full record of
        # balances; there are various approaches to passing warnings
        # or requesting rescans, none are implemented yet.
        def dummy_restart_callback(msg):
            jlog.warn("Ignoring rescan request from backend wallet service: " + msg)
        self.services["wallet"].add_restart_callback(dummy_restart_callback)
        self.active_session = True
        self.wss_factory.active_session = True
        self.wallet_name = wallet_name
        # Add wallet_name to token scope
        self.token.add_to_scope(wallet_name)
        self.services["wallet"].register_callbacks(
            [self.wss_factory.sendTxNotification], None)
        self.services["wallet"].startService()
        # now that the WalletService instance is active and ready to
        # respond to requests, we return the status to the client:

        # return type is different for a newly created OR recovered
        # wallet, in this case we use the 'seedphrase' kwarg as trigger:
        if "seedphrase" in kwargs:
            return make_jmwalletd_response(
                request,
                status=201,
                walletname=self.wallet_name,
                seedphrase=kwargs.get("seedphrase"),
                **self.token.issue(),
            )
        else:
            return make_jmwalletd_response(
                request, walletname=self.wallet_name, **self.token.issue()
            )

    def taker_finished(self, res, fromtx=False, waittime=0.0, txdetails=None):
        if not self.tumbler_options:
            # We were doing a single coinjoin -- stop taker.
            self.stop_taker(res)
            jm_single().config.set("POLICY", "tx_fees",
                                   self.default_policy_tx_fees)
        else:
            # We're running the tumbler.
            assert self.tumble_log is not None

            logsdir = os.path.join(os.path.dirname(jm_single().config_location), "logs")
            sfile = os.path.join(logsdir, self.tumbler_options['schedulefile'])

            tumbler_taker_finished_update(self.taker, sfile, self.tumble_log, self.tumbler_options, res, fromtx, waittime, txdetails)

            if not fromtx:
                # The tumbling schedule's final transaction is done.
                self.stop_taker(res)
                self.tumbler_options = None
            elif fromtx != "unconfirmed":
                # A non-final transaction in the tumbling schedule is done -- continue schedule after wait time.
                reactor.callLater(waittime*60, self.clientfactory.getClient().clientStart)

    def stop_taker(self, res):
        self.taker = None

        if not res:
            jlog.info("Coinjoin did not complete successfully.")
        else:
            jlog.info("Coinjoin completed correctly")

        # Note; it's technically possible for this to return False if somehow
        # we are currently in inactive state, but it isn't an error:
        self.activate_coinjoin_state(CJ_NOT_RUNNING)
        # remove dangling connections
        if self.clientfactory:
            self.clientfactory.proto_client.request_mc_shutdown()
        if self.coinjoin_connection:
            try:
                self.coinjoin_connection.disconnect()
                # note that "serverconn" here is the jm messaging daemon,
                # listening for new connections, so we don't shut it down
                # as both makers and takers will assume it's started up.
            except Exception as e:
                # Should not happen, but avoid crash if trying to
                # shut down something that already disconnected:
                jlog.warn("Failed to shut down connection: " + repr(e))
            self.coinjoin_connection = None

    def filter_orders_callback(self,orderfees, cjamount):
        """ Currently we rely on the user's fee limit choices
        and don't allow them to inspect the offers before acceptance.
        TODO: two phase response to client.
        """
        return True

    def filter_orders_callback_tumbler(self, orders_fees, cjamount):
        return tumbler_filter_orders_callback(orders_fees, cjamount, self.taker)

    def check_daemon_ready(self):
        # daemon must be up before coinjoins start.
        daemon_serving_host, daemon_serving_port = get_daemon_serving_params()
        if daemon_serving_port == -1 or daemon_serving_host == "":
            raise BackendNotReady()
        return (daemon_serving_host, daemon_serving_port)

    def get_wallet_cls_from_type(self, wallettype: str) -> BaseWallet:
        if wallettype == "sw":
            return SegwitWallet
        elif wallettype == "sw-legacy":
            return SegwitLegacyWallet
        elif wallettype == "sw-fb":
            return SegwitWalletFidelityBonds
        else:
            raise InvalidRequestFormat()

    def get_wallet_name_from_req(self, walletname: str) -> str:
        """ use the config's data location combined with the json
        data from the request to construct the wallet path
        """
        wallet_root_path = os.path.join(jm_single().datadir, "wallets")
        return os.path.join(wallet_root_path, walletname)

    """ RPC begins here.
    """

    # handling CORS preflight for any route:
    # TODO is this ever needed?
    @app.route('/', branch=True, methods=['OPTIONS'])
    def preflight(self, request):
        request.setHeader("Access-Control-Allow-Origin", "*")
        request.setHeader("Access-Control-Allow-Methods", "POST")

    with app.subroute(api_version_string) as app:
        @app.route('/token', methods=['POST'])
        def refresh(self, request):
            self.check_cookie(request, verify_exp=False)

            def _mkerr(err, description=""):
                return make_jmwalletd_response(
                    request, status=400, message=err, error_description=description
                )

            try:
                assert isinstance(request.content, BytesIO)
                post_body = self.get_POST_body(request, ["grant_type", "refresh_token"])
                grant_type = post_body["grant_type"]
                if grant_type not in {"refresh_token"}:
                    return _mkerr(
                        "unsupported_grant_type",
                        "The authorization grant type is not supported by the authorization server.",
                    )
                token = post_body["refresh_token"]
            except:
                return _mkerr(
                    "invalid_request",
                    "The request is missing a required parameter, "
                    "includes an unsupported parameter value (other than grant type), "
                    "repeats a parameter, includes multiple credentials, "
                    "or is otherwise malformed.",
                )
            try:
                self.token.verify(token, token_type=grant_type.split("_")[0])
                return make_jmwalletd_response(
                    request, walletname=self.wallet_name, **self.token.issue()
                )

            except auth.ExpiredSignatureError:
                return _mkerr(
                    "invalid_grant",
                    f"The provided {grant_type} is expired.",
                )
            except auth.InvalidScopeError:
                return _mkerr(
                    "invalid_scope",
                    "The requested scope is invalid, unknown, malformed, "
                    "or exceeds the scope granted by the resource owner.",
                )
            except Exception:
                return _mkerr(
                    "invalid_grant",
                    f"The provided {grant_type} is invalid, revoked, "
                    "or was issued to another client.",
                )

        @app.route('/wallet/<string:walletname>/display', methods=['GET'])
        def displaywallet(self, request, walletname):
            print_req(request)
            self.check_cookie(request)
            if not self.services["wallet"]:
                jlog.warn("displaywallet called, but no wallet loaded")
                raise NoWalletFound()
            if not self.wallet_name == walletname:
                jlog.warn("called displaywallet with wrong wallet")
                raise InvalidRequestFormat()
            else:
                walletinfo = wallet_display(self.services["wallet"], False, jsonified=True)
                return make_jmwalletd_response(request, walletname=walletname, walletinfo=walletinfo)

        @app.route('/wallet/<string:walletname>/rescanblockchain/<int:blockheight>', methods=['GET'])
        def rescanblockchain(self, request, walletname, blockheight):
            """ This route lets the user trigger the rescan action in the backend.
            Note that it technically "shouldn't" require a wallet to be loaded,
            but since we hide all blockchain access behind the wallet service,
            it currently *does* require this.
            An additional subtlety to bear in mind: the action of rescanblockchain
            depends on the *currently loaded Bitcoin Core wallet*, that Core wallet
            load event is currently done on startup of Joinmarket, depending on
            the setting in the joinmarket.cfg file.
            """
            print_req(request)
            self.check_cookie(request)
            if not self.services["wallet"]:
                jlog.warn("rescanblockchain called, but no wallet service active.")
                raise NoWalletFound()
            if not self.wallet_name == walletname:
                jlog.warn("called rescanblockchain with wrong wallet")
                raise InvalidRequestFormat()
            else:
                self.services["wallet"].rescanblockchain(blockheight)
                return make_jmwalletd_response(request, walletname=walletname)

        @app.route('/getinfo', methods=['GET'])
        def version(self, request):
            """ This route sends information about the backend, including
            the running version of Joinmarket,
            back to the client. It does *not* pay attention to any state,
            including authentication tokens.
            """
            return make_jmwalletd_response(request,version=JM_CORE_VERSION)

        @app.route('/session', methods=['GET'])
        def session(self, request):
            """ This route functions as a heartbeat, and communicates
            to the client what the current status of the wallet
            and services is. TODO: add more data to send to client.
            """
            #validate auth header if provided
            #this lets caller know if cookie is invalid or outdated
            self.check_cookie_if_present(request)

            maker_running = self.coinjoin_state == CJ_MAKER_RUNNING
            coinjoin_in_process = self.coinjoin_state == CJ_TAKER_RUNNING

            # fields which may or may not be available:
            schedule = None
            offer_list = None
            nickname = None
            # We don't technically *know* the backend is not
            # rescanning, but that would be a strange scenario:
            rescanning = False

            block_height = None

            if self.services["wallet"]:
                if self.services["wallet"].isRunning():
                    rescanning, _ = self.services["wallet"].get_backend_wallet_rescan_status()
                    wallet_name = self.wallet_name
                    # At this point if an `auth_header` is present, it has been checked
                    # by the call to `check_cookie_if_present` above.
                    auth_header = request.getHeader('Authorization')
                    if auth_header is not None:
                        block_height = self.services["wallet"].current_blockheight

                        if self.coinjoin_state == CJ_TAKER_RUNNING and \
                           self.tumbler_options is not None:
                                if self.taker is not None and not self.taker.aborted:
                                    schedule = self.taker.schedule
                        elif maker_running:
                            offer_list = self.services["maker"].yieldgen.offerlist
                            # maker's nick is useful for tracking; so we only report
                            # it if authed and maker running:
                            if jm_single().nickname is not None:
                                nickname = jm_single().nickname

                else:
                    wallet_name = "not yet loaded"
            else:
                wallet_name = "None"

            return make_jmwalletd_response(
                request,
                session=self.active_session,
                maker_running=maker_running,
                coinjoin_in_process=coinjoin_in_process,
                schedule=schedule,
                wallet_name=wallet_name,
                offer_list=offer_list,
                nickname=nickname,
                rescanning=rescanning,
                block_height=block_height,
            )

        @app.route('/wallet/<string:walletname>/taker/direct-send', methods=['POST'])
        def directsend(self, request, walletname):
            """ Use the contents of the POST body to do a direct send from
            the active wallet at the chosen mixdepth.
            """
            self.check_cookie(request)
            assert isinstance(request.content, BytesIO)
            payment_info_json = self.get_POST_body(request, ["mixdepth", "amount_sats", "destination"], ["txfee", "utxos"])

            if not payment_info_json:
                raise InvalidRequestFormat()
            if not self.services["wallet"]:
                raise NoWalletFound()
            if not self.wallet_name == walletname:
                raise InvalidRequestFormat()
            # This is a synchronous operation (no delay is expected),
            # hence the reference to the CJ_* lock is really just a gate
            # on performing the action (so simpler to not update the
            # state, otherwise we would have to revert it correctly in
            # all error conditions).
            if not self.coinjoin_state == CJ_NOT_RUNNING:
                raise ActionNotAllowed()

            if "txfee" in payment_info_json:
                if int(payment_info_json["txfee"]) > 0:
                    jm_single().config.set("POLICY", "tx_fees",
                                           str(payment_info_json["txfee"]))
                else:
                    raise InvalidRequestFormat()

            try:
                mixdepth = int(payment_info_json["mixdepth"])
                destination = payment_info_json["destination"]
                amount_sats = int(payment_info_json["amount_sats"])
                dest_and_amounts = [(destination, amount_sats)]
                utxos = payment_info_json.get("utxos", None)

                tx = direct_send(
                    self.services["wallet"],
                    mixdepth,
                    dest_and_amounts,
                    utxos,
                    return_transaction=True,
                    answeryes=True
                    )

                jm_single().config.set("POLICY", "tx_fees",
                                       self.default_policy_tx_fees)
            except AssertionError:
                jm_single().config.set("POLICY", "tx_fees",
                                       self.default_policy_tx_fees)
                raise InvalidRequestFormat()
            except NotEnoughFundsException as e:
                jm_single().config.set("POLICY", "tx_fees",
                                       self.default_policy_tx_fees)
                raise TransactionFailed(repr(e))
            except Exception:
                jm_single().config.set("POLICY", "tx_fees",
                                       self.default_policy_tx_fees)
                raise
            if not tx:
                # this should not really happen; not a coinjoin
                # so tx should go through.
                raise TransactionFailed()
            return make_jmwalletd_response(request,
                            txinfo=human_readable_transaction(tx, False))

        @app.route('/wallet/<string:walletname>/maker/start', methods=['POST'])
        def start_maker(self, request, walletname):
            """ Use the configuration in the POST body to start the yield generator:
            """
            print_req(request)
            self.check_cookie(request)
            assert isinstance(request.content, BytesIO)
            config_json = self.get_POST_body(request, ["txfee", "cjfee_a", "cjfee_r",
                                                       "ordertype", "minsize"])
            if not config_json:
                raise InvalidRequestFormat()
            if not self.services["wallet"]:
                raise NoWalletFound()
            if not self.wallet_name == walletname:
                raise InvalidRequestFormat()

            dhost, dport = self.check_daemon_ready()

            for key, val in config_json.items():
                if(key == 'cjfee_r' or key == 'ordertype'):
                    pass
                else:
                    try:
                        config_json[key] = int(config_json[key])
                    except ValueError:
                        raise InvalidRequestFormat()
            # these fields are not used by the "basic" yg.
            # TODO "upgrade" this to yg-privacyenhanced type.
            config_json['txfee_factor'] = None
            config_json["cjfee_factor"] = None
            config_json["size_factor"] = None

            self.services["maker"] = YieldGeneratorService(self.services["wallet"],
                                    dhost, dport,
                                    [config_json[x] for x in ["txfee", "cjfee_a",
                                    "cjfee_r", "ordertype", "minsize",
                                    "txfee_factor", "cjfee_factor","size_factor"]])
            # make sure that our state here is consistent with any unexpected
            # shutdown of the maker (such as from a invalid minsize causing startup
            # to fail):
            def cleanup():
                self.activate_coinjoin_state(CJ_NOT_RUNNING)
            def setup_set_coinjoin_state():
                # note this returns False if we cannot update the state.
                if not self.activate_coinjoin_state(CJ_MAKER_RUNNING):
                    raise ServiceAlreadyStarted()
            # don't even start up the service if there aren't any coins
            # to offer:
            def setup_sanitycheck_balance():
                # note: this will only be non-zero if coins are confirmed.
                # note: a call to start_maker necessarily is after a successful
                # sync has already happened (this is different from CLI yg).
                # note: an edge case of dusty amounts is lost here; it will get
                # picked up by Maker.try_to_create_my_orders().
                gbbm = self.services["wallet"].get_balance_by_mixdepth(
                    verbose=False, minconfs=1)
                if len(gbbm) == 0 or all([v==0 for v in gbbm.values()]):
                    # note: this raise will prevent the setup
                    # of the service (and therefore the startup) from
                    # proceeding:
                    raise NotEnoughCoinsForMaker()
                # We must also not start if the only coins available are of
                # the TL type *even* if the TL is expired. This check is done
                # here early, as above, to avoid the maker service starting.
                utxos = self.services["wallet"].get_all_utxos()
                # remove any TL type:
                utxos = [u for u in utxos.values() if not \
                         FidelityBondMixin.is_timelocked_path(u["path"])]
                # Note that only the following check is required since we
                # already checked that balance is non-zero.
                if len(utxos) == 0:
                    raise NotEnoughCoinsForMaker()

            self.services["maker"].addCleanup(cleanup)
            # order of addition of service setup functions matters;
            # if a precondition should prevent the update of the
            # coinjoin_state, it must come first:
            self.services["maker"].addSetup(setup_sanitycheck_balance)
            self.services["maker"].addSetup(setup_set_coinjoin_state)
            # Service startup now checks and updates coinjoin state,
            # assuming setup is successful:
            self.services["maker"].startService()

            return make_jmwalletd_response(request, status=202)

        @app.route('/wallet/<string:walletname>/maker/stop', methods=['GET'])
        def stop_maker(self, request, walletname):
            self.check_cookie(request)
            if not self.services["wallet"]:
                raise NoWalletFound()
            if not self.wallet_name == walletname:
                raise InvalidRequestFormat()
            if not self.services["maker"] or not self.coinjoin_state == \
               CJ_MAKER_RUNNING:
                raise ServiceNotStarted()
            self.services["maker"].stopService()
            return make_jmwalletd_response(request, status=202)

        def get_json_yigen_report(self):
            """ Returns a json object whose contents are:
            a list of strings, each string is a comma separated record of
            a coinjoin event, directly read from yigen-statement.csv without
            further processing.
            """
            try:
                datadir = os.path.join(jm_single().datadir, "logs")
                with open(os.path.join(datadir, "yigen-statement.csv"), "r") as f:
                    yigen_data = f.readlines()
                return yigen_data
            except Exception as e:
                jlog.warn("Yigen report failed to find file: {}".format(repr(e)))
                raise YieldGeneratorDataUnreadable()

        @app.route('/wallet/yieldgen/report', methods=['GET'])
        def yieldgen_report(self, request):
            # Note that this is *not* a maker function, and
            # not wallet specific (the report aggregates over time,
            # even with different wallets), and does not require
            # an authenticated session (it reads the filesystem, like
            # /all)
            # note: can raise, most particularly if file has not been
            # created because maker never ran (or deleted):
            yigen_data = self.get_json_yigen_report()
            # this is the successful case; note the object can
            # be an empty list:
            return make_jmwalletd_response(request, yigen_data=yigen_data)

        @app.route('/wallet/<string:walletname>/lock', methods=['GET'])
        def lockwallet(self, request, walletname):
            print_req(request)
            self.check_cookie(request)
            if self.services["wallet"] and not self.wallet_name == walletname:
                raise InvalidRequestFormat()
            if not self.services["wallet"]:
                jlog.warn("Called lock, but no wallet loaded")
                # we could raise NoWalletFound here, but is
                # easier for clients if they can gracefully call
                # lock multiple times:
                already_locked = True
            else:
                # notice that here a wallet locking event shuts down
                # everything.
                # TODO: changing this so a maker can run in the background
                # while locked, will require auto-detection of coinjoin
                # state on future unlock.
                self.stopSubServices()
                already_locked = False
            return make_jmwalletd_response(request, walletname=walletname,
                                           already_locked=already_locked)

        @app.route('/wallet/create', methods=["POST"])
        def createwallet(self, request):
            print_req(request)
            # we only handle one wallet at a time;
            # if there is a currently unlocked wallet,
            # refuse to process the request:
            if self.services["wallet"]:
                raise WalletAlreadyUnlocked()
            request_data = self.get_POST_body(request,
                            ["walletname", "password", "wallettype"])
            if not request_data:
                raise InvalidRequestFormat()
            wallet_cls = self.get_wallet_cls_from_type(
                request_data["wallettype"])
            try:
                wallet = create_wallet(self.get_wallet_name_from_req(
                    request_data["walletname"]),
                    request_data["password"].encode("ascii"),
                    4, wallet_cls=wallet_cls)
                # extension not yet supported in RPC create; TODO
                seed, extension = wallet.get_mnemonic_words()
            except RetryableStorageError:
                raise LockExists()
            except StorageError:
                raise WalletAlreadyExists()
            # finally, after the wallet is successfully created, we should
            # start the wallet service, then return info to the caller:
            return self.initialize_wallet_service(request, wallet,
                                        request_data["walletname"],
                                        seedphrase=seed)

        @app.route('/wallet/recover', methods=["POST"])
        def recoverwallet(self, request):
            print_req(request)
            # we only handle one wallet at a time;
            # if there is a currently unlocked wallet,
            # refuse to process the request:
            if self.services["wallet"]:
                raise WalletAlreadyUnlocked()
            request_data = self.get_POST_body(request,
                            ["walletname", "password",
                             "wallettype", "seedphrase"])
            if not request_data:
                raise InvalidRequestFormat()
            wallet_cls = self.get_wallet_cls_from_type(
                request_data["wallettype"])
            seedphrase = request_data["seedphrase"]
            seedphrase = seedphrase.strip()
            if not seedphrase:
                raise InvalidRequestFormat()
            try:
                entropy = BIP39WalletMixin.entropy_from_mnemonic(seedphrase)
            except WalletError:
                # should only occur if the seedphrase is not valid BIP39:
                raise InvalidRequestFormat()
            try:
                wallet = create_wallet(self.get_wallet_name_from_req(
                    request_data["walletname"]),
                    request_data["password"].encode("ascii"),
                    4, wallet_cls=wallet_cls, entropy=entropy)
            except RetryableStorageError:
                raise LockExists()
            except StorageError:
                raise WalletAlreadyExists()
            # finally, after the wallet is successfully created, we should
            # start the wallet service, then return info to the caller:
            return self.initialize_wallet_service(request, wallet,
                                        request_data["walletname"],
                                        seedphrase=seedphrase)

        @app.route('/wallet/<string:walletname>/unlock', methods=['POST'])
        def unlockwallet(self, request, walletname):
            """ If a user succeeds in authenticating and opening a
            wallet, we start the corresponding wallet service.
            Notice that in the case the user fails for any reason,
            then any existing wallet service, and corresponding token,
            will remain active.
            """
            print_req(request)
            assert isinstance(request.content, BytesIO)
            auth_json = self.get_POST_body(request, ["password"])
            if not auth_json:
                raise InvalidRequestFormat()
            password = auth_json["password"]
            wallet_path = get_wallet_path(walletname, None)

            # for someone trying to re-access the wallet, using their
            # password as authentication, and get a fresh token, we still
            # need to authenticate against the password, but we cannot directly
            # re-open the wallet file (it is currently locked), but we don't
            # yet want to bother to shut down services - because if their
            # authentication is successful, we can happily leave everything
            # running (wallet service and e.g. a yieldgenerator).
            # Hence here, if it is the same name, we do a read-only open
            # and proceed to issue a new token if the open is successful,
            # otherwise error.
            if walletname == self.wallet_name:
                try:
                    # returned wallet object is ditched:
                    open_test_wallet_maybe(
                        wallet_path, walletname, 4,
                        password=password.encode("utf-8"),
                        ask_for_password=False,
                        read_only=True)
                except StoragePasswordError:
                    # actually effects authentication
                    raise InvalidCredentials()
                except StorageError:
                    # wallet is not openable, this should not happen
                    raise NoWalletFound()
                except Exception:
                    # wallet file doesn't exist or is wrong format,
                    # this also shouldn't happen so raise:
                    raise NoWalletFound()
                # no exceptions raised means we just return token:
                return make_jmwalletd_response(
                    request,
                    walletname=self.wallet_name,
                    **self.token.issue(),
                    )

            # This is a different wallet than the one currently open;
            # try to open it, then initialize the service(s):
            try:
                wallet = open_test_wallet_maybe(
                        wallet_path, walletname, 4,
                        password=password.encode("utf-8"),
                        ask_for_password=False,
                        gap_limit = jm_single().config.getint("POLICY", "gaplimit"))
            except StoragePasswordError:
                raise InvalidCredentials()
            except RetryableStorageError:
                # .lock file exists
                raise LockExists()
            except StorageError:
                # wallet is not openable
                raise NoWalletFound()
            except Exception:
                # wallet file doesn't exist or is wrong format
                raise NoWalletFound()
            return self.initialize_wallet_service(request, wallet, walletname)

        #This route should return list of current wallets created.
        @app.route('/wallet/all', methods=['GET'])
        def listwallets(self, request):
            wallet_dir = os.path.join(jm_single().datadir, 'wallets')
            # TODO: we only allow .jmdat files, and assume they
            # are actually wallets; but we should validate these
            # wallet files before returning them (though JM itself
            # never puts any other kind of file in this directory,
            # the user conceivably might).
            if not os.path.exists(wallet_dir):
                wallets = []
            else:
                wallets = os.listdir(wallet_dir)
                wallets = [w for w in wallets if w.endswith("jmdat")]
            return make_jmwalletd_response(request, wallets=wallets)

        #route to get external address for deposit
        @app.route('/wallet/<string:walletname>/address/new/<string:mixdepth>', methods=['GET'])
        def getaddress(self, request, walletname, mixdepth):
            self.check_cookie(request)
            if not self.services["wallet"]:
                raise NoWalletFound()
            if not self.wallet_name == walletname:
                raise InvalidRequestFormat()
            try:
                mixdepth = int(mixdepth)
            except ValueError:
                raise InvalidRequestFormat()
            address = self.services["wallet"].get_external_addr(mixdepth)
            return make_jmwalletd_response(request, address=address)

        @app.route('/wallet/<string:walletname>/address/timelock/new/<string:lockdate>', methods=['GET'])
        def gettimelockaddress(self, request, walletname, lockdate):
            self.check_cookie(request)
            if not self.services["wallet"]:
                raise NoWalletFound()
            if not self.wallet_name == walletname:
                raise InvalidRequestFormat()
            try:
                timelockaddress = wallet_gettimelockaddress(
                    self.services["wallet"].wallet, lockdate)
            except Exception:
                raise InvalidRequestFormat()
            if timelockaddress == "":
                raise InvalidRequestFormat()
            return make_jmwalletd_response(request, address=timelockaddress)

        @app.route('/wallet/<string:walletname>/configget', methods=["POST"])
        def configget(self, request, walletname):
            """ Note that this requires authentication but is not wallet-specific.
            Note also that return values are always strings.
            """
            self.check_cookie(request)
            # This is more just a sanity check; if user is using the wrong
            # walletname but the right token, something has gone very wrong:
            if not self.wallet_name == walletname:
                raise InvalidRequestFormat()
            config_json = self.get_POST_body(request, ["section", "field"])
            if not config_json:
                raise InvalidRequestFormat()
            try:
                val = jm_single().config.get(config_json["section"],
                                             config_json["field"])
            except:
                # assuming failure here is a badly formed section/field:
                raise ConfigNotPresent()
            return make_jmwalletd_response(request, configvalue=val)

        @app.route('/wallet/<string:walletname>/configset', methods=["POST"])
        def configset(self, request, walletname):
            """ Note that this requires authentication but is not wallet-specific.
            Note also that supplied values must always be strings.
            """
            self.check_cookie(request)
            # This is more just a sanity check; if user is using the wrong
            # walletname but the right token, something has gone very wrong:
            if not self.wallet_name == walletname:
                raise InvalidRequestFormat()
            config_json = self.get_POST_body(request, ["section", "field", "value"])
            if not config_json:
                raise InvalidRequestFormat()
            try:
                jm_single().config.set(config_json["section"],
                            config_json["field"], config_json["value"])
                if config_json["section"] == "POLICY":
                    if config_json["field"] == "tx_fees":
                        self.default_policy_tx_fees = config_json["value"]
            except:
                raise ConfigNotPresent()
            # null return indicates success in updating:
            return make_jmwalletd_response(request)

        @app.route('/wallet/<string:walletname>/freeze', methods=["POST"])
        def freeze(self, request, walletname):
            """ Freeze (true) or unfreeze (false), for spending a specified utxo
            in this wallet. Note that this is persisted in the wallet file,
            so the status survives across sessions. Note that re-application of
            the same state is allowed and does not alter the 200 OK return.
            """
            self.check_cookie(request)
            if not self.wallet_name == walletname:
                raise InvalidRequestFormat()
            freeze_json = self.get_POST_body(request, ["utxo-string", "freeze"])
            if not freeze_json:
                raise InvalidRequestFormat()
            to_disable = freeze_json["freeze"]
            valid, txidindex = utxostr_to_utxo(freeze_json["utxo-string"])
            if not valid:
                raise InvalidRequestFormat()
            # Do not update wallet state if coinjoin services are active
            if not self.coinjoin_state == CJ_NOT_RUNNING:
                raise ActionNotAllowed()
            txid, index = txidindex
            try:
                # note: this does not raise or fail if the applied
                # disable state (true/false) is the same as the current
                # one; that is accepted and not an error.
                self.services["wallet"].disable_utxo(txid, index, to_disable)
            except AssertionError:
                # should be impossible because format checked by
                # utxostr_to_utxo:
                raise InvalidRequestFormat()
            return make_jmwalletd_response(request)

        def get_listutxos_response(self, utxos):
            res = []
            for k, v in utxos.items():
                v["utxo"] = k
                res.append(v)
            return res

        #route to list utxos
        @app.route('/wallet/<string:walletname>/utxos',methods=['GET'])
        def listutxos(self, request, walletname):
            self.check_cookie(request)
            if not self.services["wallet"]:
                raise NoWalletFound()
            if not self.wallet_name == walletname:
                raise InvalidRequestFormat()
            # note: the output of `showutxos` is already a string for CLI;
            # but we return json:
            utxos = json.loads(wallet_showutxos(self.services["wallet"], False))
            utxos_response = self.get_listutxos_response(utxos)
            return make_jmwalletd_response(request, utxos=utxos_response)

        # route to abort a currently running coinjoin
        @app.route('/wallet/<string:walletname>/taker/stop', methods=['GET'])
        def stopcoinjoin(self, request, walletname):
            self.check_cookie(request)
            if not self.services["wallet"]:
                raise NoWalletFound()
            if not self.wallet_name == walletname:
                raise InvalidRequestFormat()
            if not self.coinjoin_state == CJ_TAKER_RUNNING:
                raise ServiceNotStarted()
            # prevent the next step, responding to AMP messages
            # from jmdaemon backend, from continuing:
            self.taker.aborted = True
            self.taker_finished(False)
            return make_jmwalletd_response(request, status=202)

        #route to start a coinjoin transaction
        @app.route('/wallet/<string:walletname>/taker/coinjoin', methods=['POST'])
        def docoinjoin(self, request, walletname):
            self.check_cookie(request)
            if not self.services["wallet"]:
                raise NoWalletFound()
            if not self.wallet_name == walletname:
                raise InvalidRequestFormat()
            request_data = self.get_POST_body(request,
                                              ["mixdepth", "amount_sats",
                                               "counterparties",
                                               "destination"],
                                              ["txfee"])
            if not request_data or \
               ("txfee" in request_data and int(request_data["txfee"]) <= 0):
                raise InvalidRequestFormat()
            #see file scripts/sample-schedule-for-testnet for schedule format
            waittime = 0
            rounding= 16
            completion_flag= 0
            # A schedule is a list of lists, here we have only one item
            try:
                schedule = [[int(request_data["mixdepth"]),
                             int(request_data["amount_sats"]),
                             int(request_data["counterparties"]),
                             request_data["destination"], waittime,
                             rounding, completion_flag]]
            except ValueError:
                raise InvalidRequestFormat()
            # Instantiate a Taker.
            # `order_chooser` is whatever is default for Taker.
            # max_cj_fee is to be set based on config values.
            # If user has not set config, we only for now raise
            # an error specific to this case; in future we can
            # pass a request to a client to set the values, as
            # we do in CLI (the usual reasoning applies as to
            # why no defaults).
            def dummy_user_callback(rel, abs):
                raise ConfigNotPresent()
            max_cj_fee= get_max_cj_fee_values(jm_single().config,
                        None, user_callback=dummy_user_callback)
            # Before actual start, update our coinjoin state:
            if not self.activate_coinjoin_state(CJ_TAKER_RUNNING):
                raise ServiceAlreadyStarted()

            if "txfee" in request_data:
                jm_single().config.set("POLICY", "tx_fees",
                                       str(request_data["txfee"]))

            self.taker = Taker(self.services["wallet"], schedule,
                               max_cj_fee = max_cj_fee,
                               callbacks=(self.filter_orders_callback,
                                          None, self.taker_finished))
            # TODO ; this makes use of a pre-existing hack to allow
            # selectively disabling the stallMonitor function that checks
            # if transactions went through or not; here we want to cleanly
            # destroy the Taker after an attempt is made, successful or not.
            self.taker.testflag = True
            self.clientfactory = self.get_client_factory()

            dhost, dport = self.check_daemon_ready()

            _, self.coinjoin_connection = start_reactor(dhost, dport,
                                self.clientfactory, rs=False)
            return make_jmwalletd_response(request, status=202)

        @app.route('/wallet/<walletname>/getseed', methods=['GET'])
        def getseed(self, request, walletname):
            self.check_cookie(request)
            if not self.services["wallet"]:
                raise NoWalletFound()
            if not self.wallet_name == walletname:
                raise InvalidRequestFormat()
            seedphrase, _ = self.services["wallet"].get_mnemonic_words()
            return make_jmwalletd_response(request, seedphrase=seedphrase)

        @app.route('/wallet/<string:walletname>/taker/schedule', methods=['POST'])
        def start_tumbler(self, request, walletname):
            self.check_cookie(request)

            if self.coinjoin_state is not CJ_NOT_RUNNING or self.tumbler_options is not None:
                # Tumbler, taker, or maker seems to be running already.
                return make_jmwalletd_response(request, status=409)

            if not self.services["wallet"]:
                raise NoWalletFound()
            if not self.wallet_name == walletname:
                raise InvalidRequestFormat()

            # -- Options parsing -----------------------------------------------

            # Start with default tumbler options from the tumbler CLI.
            (options, args) = get_tumbler_parser().parse_args([])
            tumbler_options = vars(options)

            request_data = self.get_POST_body(request, ["destination_addresses"],
                                  ["tumbler_options"])
            if not request_data:
                raise InvalidRequestFormat()

            destaddrs = request_data["destination_addresses"]
            for daddr in destaddrs:
                success, _ = validate_address(daddr)
                if not success:
                    raise InvalidRequestFormat()

            if "tumbler_options" in request_data:
                requested_tumbler_options = self.parse_tumbler_options_from_json(
                    request_data["tumbler_options"])

                for k in tumbler_options:
                    if k in requested_tumbler_options:
                        tumbler_options[k] = requested_tumbler_options[k]

            # Setting max_cj_fee based on global config.
            # We won't respect it being set via tumbler_options for now.
            def dummy_user_callback(rel, abs):
                raise ConfigNotPresent()

            max_cj_fee = get_max_cj_fee_values(jm_single().config,
                                               None,
                                               user_callback=dummy_user_callback)

            jm_single().mincjamount = tumbler_options['mincjamount']

            # -- Schedule generation -------------------------------------------

            # Always generates a new schedule. No restart support for now.
            try:
                schedule = get_tumble_schedule(tumbler_options,
                                           destaddrs,
                                           self.services["wallet"].get_balance_by_mixdepth())
            except ScheduleGenerationErrorNoFunds:
                raise NotEnoughCoinsForTumbler()

            logsdir = os.path.join(os.path.dirname(jm_single().config_location),
                                   "logs")
            sfile = os.path.join(logsdir, tumbler_options['schedulefile'])
            with open(sfile, "wb") as f:
                f.write(schedule_to_text(schedule))

            if self.tumble_log is None:
                self.tumble_log = get_tumble_log(logsdir)

            self.tumble_log.info("TUMBLE STARTING")
            self.tumble_log.info("With this schedule: ")
            self.tumble_log.info(pprint.pformat(schedule))

            # -- Running the Taker ---------------------------------------------

            # For simplicity, we're not doing any fee estimation for now.
            # We might want to add fee estimation (see scripts/tumbler.py) to
            # prevent users from overspending on fees when tumbling with small
            # amounts.

            if not self.activate_coinjoin_state(CJ_TAKER_RUNNING):
                raise ServiceAlreadyStarted()

            self.tumbler_options = tumbler_options

            self.taker = Taker(self.services["wallet"],
                               schedule,
                               max_cj_fee=max_cj_fee,
                               order_chooser=self.tumbler_options['order_choose_fn'],
                               callbacks=(self.filter_orders_callback_tumbler, None,
                                          self.taker_finished),
                               tdestaddrs=destaddrs)
            self.clientfactory = self.get_client_factory()

            dhost, dport = self.check_daemon_ready()

            _, self.coinjoin_connection = start_reactor(dhost,
                                                        dport,
                                                        self.clientfactory,
                                                        rs=False)

            return make_jmwalletd_response(request, status=202, schedule=schedule)

        @app.route('/wallet/<string:walletname>/taker/schedule', methods=['GET'])
        def get_tumbler_schedule(self, request, walletname):
            self.check_cookie(request)

            if not self.services["wallet"]:
                raise NoWalletFound()
            if not self.wallet_name == walletname:
                raise InvalidRequestFormat()

            if not self.tumbler_options or not self.coinjoin_state == CJ_TAKER_RUNNING:
                return make_jmwalletd_response(request, status=404)

            logsdir = os.path.join(os.path.dirname(jm_single().config_location), "logs")
            sfile = os.path.join(logsdir, self.tumbler_options['schedulefile'])
            res, schedule = get_schedule(sfile)

            if not res:
                return make_jmwalletd_response(request, status=500)

            return make_jmwalletd_response(request, schedule=schedule)
