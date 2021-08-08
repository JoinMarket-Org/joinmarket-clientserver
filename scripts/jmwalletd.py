#! /usr/bin/env python

from jmbitcoin import *
import datetime
import os
import time
import abc
import json
import atexit
from io import BytesIO
from jmclient.wallet_utils import wallet_showseed,wallet_showutxos
from twisted.python.log import startLogging
from twisted.internet import endpoints, reactor, ssl, task
from twisted.web.server import Site
from twisted.application.service import Service
from klein import Klein

from optparse import OptionParser
from jmbase import get_log
from jmbitcoin import human_readable_transaction
from jmclient import Taker, Maker, jm_single, load_program_config, \
    JMClientProtocolFactory, start_reactor, calc_cj_fee, \
    WalletService, add_base_options, get_wallet_path, direct_send, \
    open_test_wallet_maybe, wallet, wallet_display, SegwitLegacyWallet, \
    SegwitWallet, get_daemon_serving_params, YieldGeneratorService, \
    SNICKERReceiverService, SNICKERReceiver, create_wallet, \
    StorageError, StoragePasswordError, get_max_cj_fee_values
from jmbase.support import get_log, set_logging_level, jmprint,EXIT_ARGERROR, EXIT_FAILURE,DUST_THRESHOLD
import glob

import jwt

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

# for the special case of the wallet service:
class WalletAlreadyUnlocked(Exception):
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
        print("in init")
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

    @app.handle_errors(WalletAlreadyUnlocked)
    def wallet_already_unlocked(self, request, failure):
        request.setResponseCode(401)
        return "Wallet already unlocked."

    def service_not_started(self, request, failure):
        request.setResponseCode(401)
        return "Service cannot be stopped as it is not running."

    # def check_cookie(self, request):
    #     request_cookie = request.getHeader(b"JMCookie")
    #     if self.cookie != request_cookie:
    #         jlog.warn("Invalid cookie: " + str(
    #             request_cookie) + ", request rejected.")
    #         raise NotAuthorized()

    def check_cookie(self, request):
        print("header details:")
        #part after bearer is what we need
        auth_header=((request.getHeader('Authorization')))
        request_cookie = None
        if auth_header is not None:
            request_cookie=auth_header[7:]
        
        print("request cookie is",request_cookie)
        print("actual cookie is",self.cookie)
        if request_cookie==None or self.cookie != request_cookie:
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

    #Heartbeat route

    @app.route('/session',methods=['GET'])
    def sessionExists(self, request):
        #if no wallet loaded then clear frontend session info
        #when no wallet status is false
        session = not self.cookie==None
        return response(request,session=session)


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

    @app.route('/wallet/<string:walletname>/taker/direct-send', methods=['POST'])
    def send_direct(self, request, walletname):
        """ Use the contents of the POST body to do a direct send from
        the active wallet at the chosen mixdepth.
        """
        self.check_cookie(request)
        assert isinstance(request.content, BytesIO)
        
        payment_info_json = self.get_POST_body(request, ["mixdepth", "amount_sats",
                                                         "destination"])
        
        if not payment_info_json:
            raise InvalidRequestFormat()
        if not self.wallet_service:
            raise NoWalletFound()
        
        tx = direct_send(self.wallet_service, int(payment_info_json["amount_sats"]),
                    int(payment_info_json["mixdepth"]),
                    destination=payment_info_json["destination"],
                    return_transaction=True,answeryes=True)
        
        # tx = direct_send(self.wallet_service, payment_info_json["amount_sats"],
        #             payment_info_json["mixdepth"],
        #             optin_rbf=payment_info_json["optin_rbf"],
        #             return_transaction=True)
        return response(request, walletname=walletname,
                        txinfo=human_readable_transaction(tx))

    @app.route('/wallet/<string:walletname>/maker/start', methods=['POST'])
    def start_maker(self, request, walletname):
        """ Use the configuration in the POST body to start the yield generator:
        """
        self.check_cookie(request)
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

        for key,val in config_json.items():
            if(key == 'cjfee_r' or key == 'ordertype'):
                pass
            
            else:
                config_json[key] = int(config_json[key])
#  self.txfee_factor, self.cjfee_factor, self.size_factor
        config_json['txfee_factor'] = None
        config_json["cjfee_factor"] = None
        config_json["size_factor"] = None

        self.services["maker"] = YieldGeneratorService(self.wallet_service,
                                daemon_serving_host, daemon_serving_port,
                                [config_json[x] for x in ["txfee", "cjfee_a",
                                "cjfee_r", "ordertype", "minsize","txfee_factor","cjfee_factor","size_factor"]])
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
            self.cookie = None
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

    @app.route('/wallet/create', methods=["POST"])
    def createwallet(self, request):
        print_req(request)

        # we only handle one wallet at a time;
        # if there is a currently unlocked wallet,
        # refuse to process the request:
        if self.wallet_service:
            raise WalletAlreadyUnlocked()

        request_data = self.get_POST_body(request,
                        ["walletname", "password", "wallettype"])
        
        
        if not request_data or request_data["wallettype"] not in [
            "sw", "sw-legacy"]:
            raise InvalidRequestFormat()

        wallet_cls = SegwitWallet if request_data[
            "wallettype"]=="sw" else SegwitLegacyWallet

        # use the config's data location combined with the json
        # data to construct the wallet path:
        wallet_root_path = os.path.join(jm_single().datadir, "wallets")
        wallet_name = os.path.join(wallet_root_path, request_data["walletname"])
        
        try:
            wallet = create_wallet(wallet_name,  request_data["password"].encode("ascii"),
                               4, wallet_cls=wallet_cls)
            print("seedphrase is ")
            seedphrase_help_string = wallet_showseed(wallet)
            
            
        except StorageError as e:
            raise NotAuthorized(repr(e))

        # finally, after the wallet is successfully created, we should
        # start the wallet service:

        #return response(request,message="Wallet Created Succesfully,unlock it for further use")
        return self.initialize_wallet_service(request, wallet, seedphrase=seedphrase_help_string)


    def initialize_wallet_service(self, request, wallet,**kwargs):
        """ Called only when the wallet has loaded correctly, so
        authorization is passed, so set cookie for this wallet
        (currently THE wallet, daemon does not yet support multiple).
        This is maintained for as long as the daemon is active (i.e.
        no expiry currently implemented), or until the user switches
        to a new wallet.
        """
        
        encoded_token = jwt.encode({"wallet": "name_of_wallet","exp" :datetime.datetime.utcnow()+datetime.timedelta(minutes=30)},"secret")
        encoded_token = encoded_token.strip()
        print(encoded_token)
        # decoded_token = jwt.decode(encoded_token,"secret",algorithms=["HS256"])
        # print(decoded_token)
        # request.addCookie(b'session_token', encoded_token)
        # self.cookie = encoded_token
        self.cookie = encoded_token
        #self.cookie = request.getHeader(b"JMCookie")


        if self.cookie is None:
            raise NotAuthorized("No cookie")

        # the daemon blocks here until the wallet synchronization
        # from the blockchain interface completes; currently this is
        # fine as long as the client handles the response asynchronously:
        self.wallet_service = WalletService(wallet)
        while not self.wallet_service.synced:
            self.wallet_service.sync_wallet(fast=True)
        self.wallet_service.startService()
        # now that the WalletService instance is active and ready to
        # respond to requests, we return the status to the client:

        #def response(request, succeed=True, status=200, **kwargs):
        if('seedphrase' in kwargs):
            return response(request,
                        walletname=self.wallet_service.get_wallet_name(),
                        already_loaded=False,token=encoded_token,seedphrase = kwargs.get('seedphrase'))
        else:
            return response(request,
                        walletname=self.wallet_service.get_wallet_name(),
                        already_loaded=False,token=encoded_token)

    @app.route('/wallet/<string:walletname>/unlock', methods=['POST'])
    def unlockwallet(self, request, walletname):
        print_req(request)
        #print(get_current_chain_params())
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
            return self.initialize_wallet_service(request, wallet)
        else:
            print('wallet was already unlocked.')
            return response(request,
                            walletname=self.wallet_service.get_wallet_name(),
                            already_loaded=True)


    #This route should return list of current wallets created.
    @app.route('/wallet/all', methods=['GET'])
    def listwallets(self, request):
        #this is according to the assumption that wallets are there in /.joinmarket by default, also currently path for linux system only.
        #first user taken for path
        user_path = glob.glob('/home/*/')[0]
        
        wallet_dir = f"{user_path}.joinmarket/wallets/*.jmdat"
        wallets = (glob.glob(wallet_dir))
        
        offset = len(user_path)+len('.joinmarket/wallets/')
        #to get only names
        short_wallets = [wallet[offset:] for wallet in wallets]
        return response(request,wallets=short_wallets)

    #route to get external address for deposit
    @app.route('/address/new/<string:mixdepth>',methods=['GET'])
    def getaddress(self, request, mixdepth):
        
        self.check_cookie(request)
        if not self.wallet_service:
            raise NoWalletFound()
        mixdepth = int(mixdepth)
        address = self.wallet_service.get_external_addr(mixdepth)
        return response(request,address=address)

    #route to list utxos
    @app.route('/wallet/utxos',methods=['GET'])
    def listUtxos(self, request):
        self.check_cookie(request)
        if not self.wallet_service:
            raise NoWalletFound()
        utxos = wallet_showutxos(self.wallet_service, False)
        
        return response(request,transactions=utxos)

    #return True for now
    def filter_orders_callback(self,orderfees, cjamount):
        return True


    #route to start a coinjoin transaction
    @app.route('/wallet/taker/coinjoin',methods=['POST'])
    def doCoinjoin(self, request):
        self.check_cookie(request)
        if not self.wallet_service:
            raise NoWalletFound()

        request_data = self.get_POST_body(request,["mixdepth", "amount", "counterparties","destination"])
        #refer sample schedule testnet
        waittime = 0
        rounding=16
        completion_flag=0
        #list of list
        schedule = [[int(request_data["mixdepth"]), int(request_data["amount"]), int(request_data["counterparties"]), request_data["destination"], waittime, rounding, completion_flag]]
        print(schedule)
        #instantiate a taker
        #keeping order_chooser as default for now

        #max_cj_feee is to be set based on config values (jmsingle.config.get policy var->max cj fee abs in configure.py)
        
        max_cj_fee=(1,float('inf'))
        print("max cj fee is,",max_cj_fee)
        self.taker = Taker(self.wallet_service, schedule, max_cj_fee = max_cj_fee, callbacks=(self.filter_orders_callback, None,  self.taker_finished))

        clientfactory = JMClientProtocolFactory(self.taker)
        
        nodaemon = jm_single().config.getint("DAEMON", "no_daemon")
        daemon = True if nodaemon == 1 else False
        dhost = jm_single().config.get("DAEMON", "daemon_host")
        dport = jm_single().config.getint("DAEMON", "daemon_port")
        
        if jm_single().config.get("BLOCKCHAIN", "network") == "regtest":
            startLogging(sys.stdout)
        start_reactor(dhost, dport, clientfactory, daemon=daemon, rs=False)

    def taker_finished(self, res, fromtx=False, waittime=0.0, txdetails=None):
        
        if fromtx == "unconfirmed":
            #If final entry, stop *here*, don't wait for confirmation
            return
        if fromtx:
            if res:
                txd, txid = txdetails
                reactor.callLater(waittime*60,
                                  clientfactory.getClient().clientStart)
            else:
                #a transaction failed; we'll try to repeat without the
                #troublemakers.
                #If this error condition is reached from Phase 1 processing,
                #and there are less than minimum_makers honest responses, we
                #just give up (note that in tumbler we tweak and retry, but
                #for sendpayment the user is "online" and so can manually
                #try again).
                #However if the error is in Phase 2 and we have minimum_makers
                #or more responses, we do try to restart with the honest set, here.
                if self.taker.latest_tx is None:
                    #can only happen with < minimum_makers; see above.
                    jlog.info("A transaction failed but there are insufficient "
                             "honest respondants to continue; giving up.")
                    reactor.stop()
                    return
                #This is Phase 2; do we have enough to try again?
                self.taker.add_honest_makers(list(set(
                    self.taker.maker_utxo_data.keys()).symmetric_difference(
                        set(self.taker.nonrespondants))))
                if len(self.taker.honest_makers) < jm_single().config.getint(
                    "POLICY", "minimum_makers"):
                    jlog.info("Too few makers responded honestly; "
                             "giving up this attempt.")
                    reactor.stop()
                    return
                jmprint("We failed to complete the transaction. The following "
                      "makers responded honestly: " + str(self.taker.honest_makers) +\
                      ", so we will retry with them.", "warning")
                #Now we have to set the specific group we want to use, and hopefully
                #they will respond again as they showed honesty last time.
                #we must reset the number of counterparties, as well as fix who they
                #are; this is because the number is used to e.g. calculate fees.
                #cleanest way is to reset the number in the schedule before restart.
                self.taker.schedule[self.taker.schedule_index][2] = len(self.taker.honest_makers)
                jlog.info("Retrying with: " + str(self.taker.schedule[
                    self.taker.schedule_index][2]) + " counterparties.")
                #rewind to try again (index is incremented in Taker.initialize())
                self.taker.schedule_index -= 1
                self.taker.set_honest_only(True)
                reactor.callLater(5.0, clientfactory.getClient().clientStart)
        else:
            if not res:
                jlog.info("Did not complete successfully, shutting down")
            #Should usually be unreachable, unless conf received out of order;
            #because we should stop on 'unconfirmed' for last (see above)
            else:
                jlog.info("All transactions completed correctly")
            reactor.stop()
        

def jmwalletd_main():
    import sys
    parser = OptionParser(usage='usage: %prog [options] [wallet file]')
    parser.add_option('-p', '--port', action='store', type='int',
                      dest='port', default=28183,
                      help='the port over which to serve RPC, default 28183')
    # TODO: remove the non-relevant base options:
    add_base_options(parser)

    (options, args) = parser.parse_args()

    load_program_config(config_path=options.datadir)

    if jm_single().bc_interface is None:
        jlog.error("Running jmwallet-daemon requires configured " +
                   "blockchain source.")
        sys.exit(EXIT_FAILURE)
    jlog.info("Starting jmwalletd on port: " + str(options.port))

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
