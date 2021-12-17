#!/usr/bin/env python3
from pyln.client import Plugin
from collections import namedtuple
from urllib.parse import urlparse, parse_qs
import socket
import logging
import json
import os
import re
from binascii import hexlify

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

# The following socket code is liberally copied from:
# https://github.com/lightningd/plugins/blob/43fc3c6d34430bd46a332ff588df0feb66c4bc26/backup/socketbackend.py;
# it extracts only the minimal required to:
# (a) connect to a remote port
# (b) send data *lines* to it (format allows us the receiver/server
# to use `twisted.protocols.basic.LineReceiver`).

# Total number of reconnection tries
RECONNECT_TRIES=5

# Delay in seconds between reconnections (initial)
RECONNECT_DELAY=5

# Scale delay factor after each failure
RECONNECT_DELAY_BACKOFF=1.5

HostPortInfo = namedtuple('HostPortInfo', ['host', 'port', 'addrtype'])
SocketURLInfo = namedtuple('SocketURLInfo', ['target', 'proxytype', 'proxytarget'])

# Network address type.
class AddrType:
    IPv4 = 0
    IPv6 = 1
    NAME = 2

# Proxy type. Only SOCKS5 supported at the moment as this is sufficient for Tor.
class ProxyType:
    DIRECT = 0
    SOCKS5 = 1

def parse_host_port(path: str) -> HostPortInfo:
    '''Parse a host:port pair.'''
    if path.startswith('['): # bracketed IPv6 address
        eidx = path.find(']')
        if eidx == -1:
            raise ValueError('Unterminated bracketed host address.')
        host = path[1:eidx]
        addrtype = AddrType.IPv6
        eidx += 1
        if eidx >= len(path) or path[eidx] != ':':
            raise ValueError('Port number missing.')
        eidx += 1
    else:
        eidx = path.find(':')
        if eidx == -1:
            raise ValueError('Port number missing.')
        host = path[0:eidx]
        if re.match(r'\d+\.\d+\.\d+\.\d+$', host): # matches IPv4 address format
            addrtype = AddrType.IPv4
        else:
            addrtype = AddrType.NAME
        eidx += 1

    try:
        port = int(path[eidx:])
    except ValueError:
        raise ValueError('Invalid port number')

    return HostPortInfo(host=host, port=port, addrtype=addrtype)

def parse_socket_url(destination: str) -> SocketURLInfo:
    '''Parse a socket: URL to extract the information contained in it.'''
    url = urlparse(destination)
    if url.scheme != 'socket':
        raise ValueError('Scheme for socket backend must be socket:...')

    target = parse_host_port(url.path)

    proxytype = ProxyType.DIRECT
    proxytarget = None
    # parse query parameters
    # reject unknown parameters (currently all of them)
    qs = parse_qs(url.query)
    for (key, values) in qs.items():
        if key == 'proxy': # proxy=socks5:127.0.0.1:9050
            if len(values) != 1:
                raise ValueError('Proxy can only have one value')

            (ptype, ptarget) = values[0].split(':', 1)
            if ptype != 'socks5':
                raise ValueError('Unknown proxy type ' + ptype)

            proxytype = ProxyType.SOCKS5
            proxytarget = parse_host_port(ptarget)
        else:
            raise ValueError('Unknown query string parameter ' + key)

    return SocketURLInfo(target=target, proxytype=proxytype, proxytarget=proxytarget)

# This is still part of the "copied" code, but heavily
# simplified/modified as no receiving is necessary, nor any
# protocol other than lines:
class SocketToBackend(object):
    delimiter = b"\r\n"

    def initialize(self, destination: str):
        self.destination = destination
        self.url = parse_socket_url(destination)

    def connect(self):
        if self.url.proxytype == ProxyType.DIRECT:
            if self.url.target.addrtype == AddrType.IPv6:
                self.sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else: # TODO NAME is assumed to be IPv4 for now
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            assert False, "Not currently supporting SOCKS5"
            #assert(self.url.proxytype == ProxyType.SOCKS5)
            #import socks
            #self.sock = socks.socksocket()
            #self.sock.set_proxy(socks.SOCKS5, self.url.proxytarget.host, self.url.proxytarget.port)

        logging.info('Connecting to {}:{} (addrtype {}, proxytype {}, proxytarget {})...'.format(
            self.url.target.host, self.url.target.port, self.url.target.addrtype,
                self.url.proxytype, self.url.proxytarget))
        try:
            self.sock.connect((self.url.target.host, self.url.target.port))
        except Exception as e:
            plugin.log("JMCL failed to connect to backend at host, port: {}, {} "
                       "with exception: {}".format(self.url.target.host,
                                                   self.url.target.port, repr(e)))
            return
        plugin.log('Connected to JM backend at: {}'.format(self.destination))
        plugin.is_connected_to_backend = True

    def sendLine(self, msg: bytes) -> None:
        # TODO no length check here; should be accepted
        # by backend if len(msg) < basic.LineReceiver.MAX_LENGTH
        try:
            self.sock.sendall(msg + self.delimiter)
        except Exception as e:
            plugin.log("JMCL failed to send message, exception: {}".format(
                repr(e)))

backend_line_sender = SocketToBackend()

def send_tcp_message(msg: bytes) -> None:
    if not plugin.is_connected_to_backend:
        # The 'lazy wait to connect' logic used here
        # accounts for the fact that we don't expect the
        # backend server to be up until we're ready to send
        # messages:
        plugin.log("Attempting connection to backend on port: {}".format(plugin.jmport))
        backend_line_sender.initialize("socket:127.0.0.1:" + str(plugin.jmport))
        backend_line_sender.connect()
    backend_line_sender.sendLine(msg)
    
def send_local_control_message(msgtype: int, text: str) -> None:
    # We use the same msgtype/msg format as custommsg for now:
    hextype = "%0.4x" % msgtype
    hextext = hexlify(text.encode("utf-8")).decode("utf-8")
    msg = {"peer_id": "00", "payload": hextype + hextext}
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
def on_connect(plugin, id, direction, address, **kwargs):
    if direction == "out":
        msgtype = 785
    else:
        msgtype = 797
    send_local_control_message(msgtype, id + "@" + address[
        "address"] + ":" + str(address["port"]))

@plugin.subscribe("disconnect")
def on_disconnect(plugin, id, **kwargs):
    send_local_control_message(787, id)

@plugin.hook("custommsg")
def on_custommsg(peer_id, payload, plugin, **kwargs):
    send_tcp_message(json.dumps({"peer_id": peer_id,
                                 "payload": payload}).encode("utf-8"))
    return {"result": "continue"}

if os.environ.get('LIGHTNINGD_PLUGIN', None) != '1':
    plugin.print_usage()
else:
    plugin.run()
