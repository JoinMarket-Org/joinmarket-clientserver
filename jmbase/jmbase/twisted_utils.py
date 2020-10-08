
from twisted.internet.error import ReactorNotRunning, AlreadyCancelled
from twisted.internet import reactor

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
