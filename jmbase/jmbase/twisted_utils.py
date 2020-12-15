
from zope.interface import implementer
from twisted.internet.error import ReactorNotRunning
from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.web.client import Agent, BrowserLikePolicyForHTTPS
from txtorcon.web import tor_agent
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