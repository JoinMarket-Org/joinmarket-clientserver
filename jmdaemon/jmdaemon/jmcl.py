#!/usr/bin/env python3
from pyln.client import Plugin
import json
import os
from twisted.internet import reactor
from twisted.internet.protocol import ReconnectingClientFactory
from twisted.protocols.basic import LineReceiver

""" jmcl - joinmarket over clightning.
    This is deliberately a very "dumb" plugin.
    It does almost nothing other than try to
    forward messages, received as onionmessages,
    from other nodes.
    Messages are forwarded over a plain TCP socket
    on localhost, using LineReceiver as the app-layer
    way to distinguish individual messages.
    In addition to forwarding messages, there are defined
    a few "control messages", which relate to connected/
    disconnected status of peers.
"""

class TCPPassthroughClientProtocol(LineReceiver):
    def connectionMade(self):
        plugin.log("Connection to joinmarketd backend established OK.")
        plugin.is_connected_to_backend = True
        self.send_message(self.starting_msg)

    def dataReceived(self, data):
        """ We're not currently receiving data from the backend.
        """
        self.transport.loseConnection()

    def send_message(self, message: bytes) -> None:
        self.sendLine(message)

    def connectionLost(self, reason):
        pass

tcppp = TCPPassthroughClientProtocol()

class TCPPassthroughClientFactory(ReconnectingClientFactory):
    def buildProtocol(self, addr):
        return tcppp
    def clientConnectionLost(self, connector, reason):
        if reactor.running:
            ReconnectingClientFactory.clientConnectionLost(
                self, connector, reason)
    def clientConnectionFailed(self, connector, reason):
        if reactor.running:
            ReconnectingClientFactory.clientConnectionFailed(
                self, connector, reason)

def send_tcp_message(msg: bytes) -> None:
    if plugin.is_connected_to_backend:
        tcppp.send_message(msg)
    else:
        reactor.connectTCP("localhost", plugin.jmport,
                           TCPPassthroughClientFactory())
        tcppp.starting_msg = msg
    
def send_local_control_message(msgtype: int, text: str) -> None:
    # Notice that this does *not* have the same format as those
    # that come from the onionmessage calls:
    msg = {"unknown_fields": [{"number": msgtype, "value": text}]}
    send_tcp_message(json.dumps(msg).encode("utf-8"))

plugin = Plugin(autopatch=False)
plugin.is_connected_to_backend = False

plugin.add_option("jmport",
                  "49100",
                  "TCP port for communication with joinmarketd",
                  "int")

@plugin.init()
def init(options, configuration, plugin):
    plugin.log("Plugin JMCL.py initialized")
    plugin.jmport = options["jmport"]

@plugin.subscribe("connect")
def on_connect(plugin, id, address, **kwargs):
    plugin.log("Received connect event for peer {}".format(id))
    plugin.log("With address: {}".format(address))
    send_local_control_message(785, id + "@" + address[
        "address"] + ":" + str(address["port"]))

@plugin.subscribe("disconnect")
def on_disconnect(plugin, id, **kwargs):
    plugin.log("Received disconnect event for peer {}".format(id))
    send_local_control_message(787, id)

@plugin.hook("onion_message")
def on_onion_message(plugin, onion_message, **kwargs):
    send_tcp_message(json.dumps(onion_message).encode("utf-8"))
    return {"result": "continue"}

def run():
    # If we are not running inside lightningd we'll print usage
    # and some information about the plugin.
    if os.environ.get('LIGHTNINGD_PLUGIN', None) != '1':
        return plugin.print_usage()
    inner_run()

def inner_run():
    # iterate manually to shut down gracefully at the end:
    try:
        l = next(plugin.stdin.buffer)
    except StopIteration:
        reactor.stop()
        return

    plugin.buffer += l
    msgs = plugin.buffer.split(b'\n\n')
    if len(msgs) < 2:
        reactor.callLater(0.0, inner_run)
        return
    plugin.buffer = plugin._multi_dispatch(msgs)
    reactor.callLater(0.0, inner_run)

plugin.buffer = b""
reactor.callWhenRunning(run)
reactor.run()

