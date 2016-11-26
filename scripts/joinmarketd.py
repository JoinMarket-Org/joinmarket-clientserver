import sys
from twisted.internet import reactor
from twisted.python.log import startLogging, err
import jmdaemon

def startup_joinmarketd(port, finalizer=None, finalizer_args=None):
    """Start event loop for joinmarket daemon here.
    Args:
    port : port over which to serve the daemon
    finalizer: a function which is called after the reactor has shut down.
    finalizer_args : arguments to finalizer function.
    """
    startLogging(sys.stdout)
    factory = jmdaemon.JMDaemonServerProtocolFactory()
    reactor.listenTCP(port, factory)
    if finalizer:
        reactor.addSystemEventTrigger("after", "shutdown", finalizer,
                                      finalizer_args)
    reactor.run()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        port = 27183
    else:
        port = int(sys.argv[1])
    startup_joinmarketd(port)
