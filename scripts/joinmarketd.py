#!/usr/bin/env python3
import sys
from twisted.internet import reactor
from twisted.python.log import startLogging
import jmdaemon

def startup_joinmarketd(host, port, usessl, factories=None,
                        finalizer=None, finalizer_args=None):
    """Start event loop for joinmarket daemon here.
    Args:
    port : port over which to serve the daemon
    finalizer: a function which is called after the reactor has shut down.
    finalizer_args : arguments to finalizer function.
    """
    startLogging(sys.stdout)
    if not factories:
        factories = [jmdaemon.JMDaemonServerProtocolFactory(),
                     jmdaemon.SNICKERDaemonServerProtocolFactory(),
                     jmdaemon.BIP78ServerProtocolFactory()]
    for factory in factories:
        jmdaemon.start_daemon(host, port, factory, usessl,
                              './ssl/key.pem', './ssl/cert.pem')
        port -= 1000
    if finalizer:
        reactor.addSystemEventTrigger("after", "shutdown", finalizer,
                                      finalizer_args)
    reactor.run()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        port = 27183
    else:
        port = int(sys.argv[1])
    usessl = False
    if len(sys.argv) > 2:
        if int(sys.argv[2]) != 0:
            usessl = True
    if len(sys.argv) > 3:
        host = sys.argv[3]
    else:
        host = 'localhost'
    startup_joinmarketd(host, port, usessl)
