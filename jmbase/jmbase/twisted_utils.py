
from zope.interface import implementer
from twisted.internet.error import ReactorNotRunning
from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.web.client import Agent, BrowserLikePolicyForHTTPS
import txtorcon
from txtorcon.web import tor_agent
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

def stop_reactor():
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

class JMHiddenService(object):
    """ Wrapper class around the actions needed to
    create and serve on a hidden service; an object of
    type Resource must be provided in the constructor,
    which does the HTTP serving actions (GET, POST serving).
    """
    def __init__(self, resource, info_callback, error_callback,
                 onion_hostname_callback, tor_control_host,
                 tor_control_port, serving_port = None,
                 shutdown_callback = None):
        self.site = Site(resource)
        self.site.displayTracebacks = False
        self.info_callback = info_callback
        self.error_callback = error_callback
        # this has a separate callback for convenience, it should
        # be passed the literal *.onion string (port is already
        # known and is 80 by default)
        self.onion_hostname_callback = onion_hostname_callback
        self.shutdown_callback = shutdown_callback
        if not serving_port:
            self.port = 80
        else:
            self.port = serving_port
        self.tor_control_host = tor_control_host
        self.tor_control_port = tor_control_port
        print("got these settings: ", self.port, self.site, self.tor_control_host, self.tor_control_port)

    def start_tor(self):
        """ This function executes the workflow
        of starting the hidden service and returning its hostname
        """
        self.info_callback("Attempting to start onion service on port: {} "
                           "...".format(self.port))
        if str(self.tor_control_host).startswith('unix:'):
            control_endpoint = UNIXClientEndpoint(reactor,
                                    self.tor_control_host[5:])
        else:
            control_endpoint = TCP4ClientEndpoint(reactor,
                            self.tor_control_host,self.tor_control_port)
        d = txtorcon.connect(reactor, control_endpoint)
        d.addCallback(self.create_onion_ep)
        d.addErrback(self.setup_failed)
        # TODO: add errbacks to the next two calls in
        # the chain:
        d.addCallback(self.onion_listen)
        d.addCallback(self.print_host)

    def setup_failed(self, arg):
        # Note that actions based on this failure are deferred to callers:
        self.error_callback("Setup failed: " + str(arg))

    def create_onion_ep(self, t):
        self.tor_connection = t
        return t.create_onion_endpoint(self.port, private_key=txtorcon.DISCARD)

    def onion_listen(self, onion_ep):
        return onion_ep.listen(self.site)

    def print_host(self, ep):
        """ Callback fired once the HS is available;
        we let the caller know the hidden service onion hostname,
        which is not otherwise available to them:
        """
        # Note that ep,getHost().onion_port must return the same
        # port as we chose in self.port; if not there is an error.
        assert ep.getHost().onion_port == self.port
        self.onion_hostname_callback(ep.getHost().onion_uri)

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
