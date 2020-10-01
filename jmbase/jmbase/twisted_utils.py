
from twisted.internet.error import ReactorNotRunning, AlreadyCancelled
from twisted.internet import reactor

def stop_reactor():
    """ Both in startup and shutdown,
    the value of the bool `reactor.running`
    does not reliably tell us whether the
    reactor is running (!). There are startup
    and shutdown phases not reported externally
    by IReactorCore.
    Hence the Exception catch is needed here.
    """
    try:
        if reactor.running:
            reactor.stop()
    except ReactorNotRunning:
        pass
