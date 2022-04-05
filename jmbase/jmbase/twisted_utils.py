
from zope.interface import implementer
from twisted.internet.error import ReactorNotRunning
from twisted.internet import reactor, defer
from twisted.internet.endpoints import (TCP4ClientEndpoint,
                        UNIXClientEndpoint, serverFromString)
from twisted.web.client import Agent, BrowserLikePolicyForHTTPS
import txtorcon
from txtorcon.web import tor_agent
from txtorcon import TorControlProtocol, TorConfig

_custom_stop_reactor_is_set = False
custom_stop_reactor = None

# This removes `CONF_CHANGED` requests
# over the Tor control port, which aren't needed for our use case.
def patch_add_event_listener(self, evt, callback):
    if evt not in self.valid_events.values():
        try:
            evt = self.valid_events[evt]
        except KeyError:
            raise RuntimeError("Unknown event type: " + evt)

    if evt.name not in self.events and evt.name != "CONF_CHANGED":
        self.events[evt.name] = evt
        d = self.queue_command('SETEVENTS %s' % ' '.join(self.events.keys()))
    else:
        d = defer.succeed(None)
    evt.listen(callback)
    return d
TorControlProtocol.add_event_listener = patch_add_event_listener

# Similar to above, but more important:
# txtorcon making too nosy requests for config data; this
# simply prevents the request, which the package allows.
def patch_get_defaults(self):
    return dict()
TorConfig._get_defaults = patch_get_defaults

from twisted.web.server import Site
from twisted.web.resource import Resource
from twisted.web.iweb import IPolicyForHTTPS
from twisted.internet.ssl import CertificateOptions
from .support import wrapped_urlparse

# txtorcon outputs erroneous warnings about hiddenservice directory strings,
# annoyingly, so we suppress it here:
import warnings
warnings.filterwarnings("ignore")

""" This whitelister allows us to accept any cert for a specific
    domain, and is to be used for testing only; the default Agent
    behaviour of twisted.web.client.Agent for https URIs is
    the correct one in production (i.e. uses local trust store).
"""
@implementer(IPolicyForHTTPS)
class WhitelistContextFactory(object):
    def __init__(self, good_domains=None):
        """
        :param good_domains: List of domains. The URLs must be in bytes
        """
        if not good_domains:
            self.good_domains = []
        else:
            self.good_domains = good_domains
        # by default, handle requests like a browser would
        self.default_policy = BrowserLikePolicyForHTTPS()

    def creatorForNetloc(self, hostname, port):
        # check if the hostname is in the the whitelist,
        # otherwise return the default policy
        if hostname in self.good_domains:
            return CertificateOptions(verify=False)
        return self.default_policy.creatorForNetloc(hostname, port)

def set_custom_stop_reactor(fn):
    global _custom_stop_reactor_is_set
    global custom_stop_reactor
    _custom_stop_reactor_is_set = True
    custom_stop_reactor = fn

def stop_reactor():
    if not _custom_stop_reactor_is_set:
        _stop_reactor()
    else:
        custom_stop_reactor()

def _stop_reactor():
    """ The value of the bool `reactor.running`
    does not reliably tell us whether the
    reactor is running (!). There are startup
    and shutdown phases not reported externally
    by IReactorCore. So we must catch Exceptions
    raised by trying to stop the reactor.
    """
    try:
        reactor.stop()
    except ReactorNotRunning:
        pass

def is_hs_uri(s):
    x = wrapped_urlparse(s)
    if x.hostname.endswith(".onion"):
        return (x.scheme, x.hostname, x.port)
    return False

def get_tor_agent(socks5_host, socks5_port):
    torEndpoint = TCP4ClientEndpoint(reactor, socks5_host, socks5_port)
    return tor_agent(reactor, torEndpoint)

def get_nontor_agent(tls_whitelist=[]):
    """ The tls_whitelist argument must be a list of hosts for which
    TLS certificate verification may be omitted, default none.
    """
    if len(tls_whitelist) == 0:
        agent = Agent(reactor)
    else:
        agent = Agent(reactor,
                contextFactory=WhitelistContextFactory(tls_whitelist))
    return agent

def config_to_hs_ports(virtual_port, host, port):
    # See https://github.com/meejah/txtorcon/blob/0c416cc8fe18b913cd0c7422935885a1bfecf4c0/txtorcon/onion.py#L1320
    # for non default config, pass port mapping strings like:
    # "80 127.0.0.1:1234"
    return "{} {}:{}".format(virtual_port, host, port)

class JMHiddenService(object):
    """ Wrapper class around the actions needed to
    create and serve on a hidden service; an object of
    type either Resource or server.ProtocolFactory must
    be provided in the constructor, which does the HTTP
    (GET, POST) or other protocol serving actions.
    """
    def __init__(self, proto_factory_or_resource, info_callback,
                 error_callback, onion_hostname_callback, tor_control_host,
                 tor_control_port, serving_host, serving_port,
                 virtual_port=None,
                 shutdown_callback=None,
                 hidden_service_dir=""):
        if isinstance(proto_factory_or_resource, Resource):
            # TODO bad naming, in this case it doesn't start
            # out as a protocol factory; a Site is one, a Resource isn't.
            self.proto_factory = Site(proto_factory_or_resource)
            self.proto_factory.displayTracebacks = False
        else:
            self.proto_factory = proto_factory_or_resource
        self.info_callback = info_callback
        self.error_callback = error_callback
        # this has a separate callback for convenience, it should
        # be passed the literal *.onion string (port is already
        # known and is 80 by default)
        self.onion_hostname_callback = onion_hostname_callback
        self.shutdown_callback = shutdown_callback
        if not virtual_port:
            self.virtual_port = 80
        else:
            self.virtual_port = virtual_port
        self.tor_control_host = tor_control_host
        self.tor_control_port = tor_control_port
        # note that defaults only exist in jmclient
        # config object, so no default here:
        self.serving_host = serving_host
        self.serving_port = serving_port
        # this is used to serve an onion from the filesystem,
        # NB: Because of how txtorcon is set up, this option
        # uses a *separate tor instance* owned by the owner of
        # this script (because txtorcon needs to read the
        # HS dir), whereas if this option is "", we set up
        # an ephemeral HS on the global or pre-existing tor.
        self.hidden_service_dir = hidden_service_dir

    def start_tor(self):
        """ This function executes the workflow
        of starting the hidden service and returning its hostname
        """
        self.info_callback("Attempting to start onion service on port: {} "
                           "...".format(self.virtual_port))
        if self.hidden_service_dir == "":
            if str(self.tor_control_host).startswith('unix:'):
                control_endpoint = UNIXClientEndpoint(reactor,
                                        self.tor_control_host[5:])
            else:
                control_endpoint = TCP4ClientEndpoint(reactor,
                                self.tor_control_host, self.tor_control_port)
            d = txtorcon.connect(reactor, control_endpoint)
            d.addCallback(self.create_onion_ep)
            d.addErrback(self.setup_failed)
            # TODO: add errbacks to the next two calls in
            # the chain:
            d.addCallback(self.onion_listen)
            d.addCallback(self.print_host)
        else:
            ep = "onion:" + str(self.virtual_port) + ":localPort="
            ep += str(self.serving_port)
            # endpoints.TCPHiddenServiceEndpoint creates version 2 by
            # default for backwards compat (err, txtorcon needs to update that ...)
            ep += ":version=3"
            ep += ":hiddenServiceDir="+self.hidden_service_dir
            onion_endpoint = serverFromString(reactor, ep)
            d = onion_endpoint.listen(self.proto_factory)
            d.addCallback(self.print_host_filesystem)


    def setup_failed(self, arg):
        # Note that actions based on this failure are deferred to callers:
        self.error_callback("Setup failed: " + str(arg))

    def create_onion_ep(self, t):
        self.tor_connection = t
        portmap_string = config_to_hs_ports(self.virtual_port,
                                self.serving_host, self.serving_port)
        return t.create_onion_service(
            ports=[portmap_string], private_key=txtorcon.DISCARD)

    def onion_listen(self, onion):
        # 'onion' arg is the created EphemeralOnionService object;
        # now we know it exists, we start serving the Site on the
        # relevant port:
        self.onion =  onion
        serverstring = "tcp:{}:interface={}".format(self.serving_port,
                                                    self.serving_host)
        onion_endpoint = serverFromString(reactor, serverstring)
        print("created the onion endpoint, now calling listen")
        return onion_endpoint.listen(self.proto_factory)

    def print_host(self, ep):
        """ Callback fired once the HS is available
        and the site is up ready to receive requests.
        The hidden service hostname will be used in the BIP21 uri.
        """
        self.onion_hostname_callback(self.onion.hostname)

    def print_host_filesystem(self, port):
        """ As above but needed to respect slightly different
        callback chain for this case (where we start our own tor
        instance for the filesystem-based onion).
        """
        self.onion = port.onion_service
        self.onion_hostname_callback(self.onion.hostname)

    def shutdown(self):
        self.tor_connection.protocol.transport.loseConnection()
        self.info_callback("Hidden service shutdown complete")
        if self.shutdown_callback:
            self.shutdown_callback()

class JMHTTPResource(Resource):
    """ Object acting as HTTP serving resource
    """
    def __init__(self, info_callback, shutdown_callback):
        self.info_callback = info_callback
        self.shutdown_callback = shutdown_callback
        super().__init__()

    isLeaf = True

    def render_GET(self, request):
        """ by default we serve a simple string which can be used e.g.
        to check if an ephemeral HS is upon Tor Browser; child classes
        may override.
        """
        return "<html>Only for testing.</html>".encode("utf-8")
