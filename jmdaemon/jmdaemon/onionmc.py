from jmdaemon.message_channel import MessageChannel
from jmdaemon.protocol import COMMAND_PREFIX, JM_VERSION
from jmbase import get_log,  JM_APP_NAME, JMHiddenService
import json
import copy
from typing import Callable, Union
from twisted.internet import reactor, task, protocol
from twisted.protocols import basic
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.address import IPv4Address, IPv6Address
from txtorcon.socks import TorSocksEndpoint

log = get_log()

def network_addr_to_string(location: Union[IPv4Address, IPv4Address]) -> str:
    if isinstance(location, (IPv4Address, IPv6Address)):
        host = location.host
        port = location.port
    else:
        # TODO handle other addr types
        assert False
    return host + ":" + str(port)

# module-level var to control whether we use Tor or not
# (specifically for tests):
testing_mode = False
def set_testing_mode(configdata: dict) -> None:
    """ Toggles testing mode which enables non-Tor
    network setup:
    """
    global testing_mode
    if not "regtest_count" in configdata:
        log.debug("Onion message channel is not using regtest mode.")
        testing_mode = False
        return
    try:
        s, e = [int(x) for x in configdata["regtest_count"].split(",")]
    except Exception as e:
        log.info("Failed to get regtest count settings, error: {}".format(repr(e)))
        testing_mode = False
        return
    if s == 0 and e == 0:
        testing_mode = False
        return
    testing_mode = True

"""
Messaging protocol (which wraps the underlying Joinmarket
messaging protocol) used here is documented in:
Joinmarket-Docs/onion-messaging.md
"""

LOCAL_CONTROL_MESSAGE_TYPES = {"connect": 785, "disconnect": 787, "connect-in": 797}
CONTROL_MESSAGE_TYPES = {"peerlist": 789, "getpeerlist": 791,
                         "handshake": 793, "dn-handshake": 795,
                         "ping": 797, "pong": 799, "disconnect": 801}
JM_MESSAGE_TYPES = {"privmsg": 685, "pubmsg": 687}

# Used for some control message construction, as detailed below.
NICK_PEERLOCATOR_SEPARATOR = ";"

# location_string and nick must be set before sending,
# otherwise invalid:
client_handshake_json = {"app-name": JM_APP_NAME,
 "directory": False,
 "location-string": "",
 "proto-ver": JM_VERSION,
 "features": {},
 "nick": ""
}

# default acceptance false; code must switch it on:
server_handshake_json = {"app-name": JM_APP_NAME,
  "directory": True,
  "proto-ver-min": JM_VERSION,
  "proto-ver-max": JM_VERSION,
  "features": {},
  "accepted": False,
  "nick": "",
  "motd": "Default MOTD, replace with information for the directory."
 }

# states that keep track of relationship to a peer
PEER_STATUS_UNCONNECTED, PEER_STATUS_CONNECTED, PEER_STATUS_HANDSHAKED, \
    PEER_STATUS_DISCONNECTED = range(4)


class OnionPeerError(Exception):
    pass

class OnionPeerDirectoryWithoutHostError(OnionPeerError):
    pass

class OnionPeerConnectionError(OnionPeerError):
    pass

class OnionCustomMessageDecodingError(Exception):
    pass

class OnionCustomMessage(object):
    """ Encapsulates the messages passed over the wire
    to and from other onion peers
    """
    def __init__(self, text: str, msgtype: int):
        self.text = text
        self.msgtype = msgtype

    def encode(self) -> str:
        self.encoded = json.dumps({"type": self.msgtype,
                        "line": self.text}).encode("utf-8")
        return self.encoded

    @classmethod
    def from_string_decode(cls, msg: str) -> 'OnionCustomMessage':
        """ Build a custom message from a json-ified string.
        """
        try:
            msg_obj = json.loads(msg)
            text = msg_obj["line"]
            msgtype = msg_obj["type"]
        except:
            raise OnionCustomMessageDecodingError
        return cls(text, msgtype)

class OnionLineProtocol(basic.LineReceiver):
    def connectionMade(self):
        self.factory.register_connection(self)

    def connectionLost(self, reason):
        self.factory.register_disconnection(self)

    def lineReceived(self, line: str) -> None:
        #print("received", repr(line))
        try:
            msg = OnionCustomMessage.from_string_decode(line)
        except OnionCustomMessageDecodingError:
            log.debug("Received invalid message, dropping connection.")
            self.transport.loseConnection()
            return
        self.factory.receive_message(msg, self)

    def message(self, message: OnionCustomMessage) -> None:
        #log.info("in OnionLineProtocol, about to send message: {} to peer {}".format(message.encode(), self.transport.getPeer()))
        self.transport.write(message.encode() + self.delimiter)

class OnionLineProtocolFactory(protocol.ServerFactory):
    """ This factory allows us to start up instances
    of the LineReceiver protocol that are instantiated
    towards us.
    As such, it is responsible for keeping track
    """
    protocol = OnionLineProtocol

    def __init__(self, client: 'OnionMessageChannel'):
        self.client = client
        self.peers = {}

    def register_connection(self, p: OnionLineProtocol) -> None:
        # make a local control message registering
        # the new connection
        peer_location = network_addr_to_string(p.transport.getPeer())
        self.client.register_connection(peer_location, direction=0)
        self.peers[peer_location] = p

    def register_disconnection(self, p: OnionLineProtocol) -> None:
        # make a local control message registering
        # the new connection
        peer_location = network_addr_to_string(p.transport.getPeer())
        self.client.register_disconnection(peer_location)
        if not peer_location in self.peers:
            log.warn("Disconnection event registered for non-existent peer.")
            return
        del self.peers[peer_location]

    def receive_message(self, message: OnionCustomMessage,
                        p: OnionLineProtocol) -> None:
        self.client.receive_msg(message, network_addr_to_string(
            p.transport.getPeer()))

    def send(self, message: OnionCustomMessage, destination: str) -> bool:
        #print("trying to send in OnionLineProtocolFactory.")
        #print("message: {}, destination: {}".format(message.encode(), destination))
        if not (destination in self.peers):
            print("sending message {}, destination {} was not in peers {}".format(message.encode(), destination, self.peers))
            return False
        proto = self.peers[destination]
        proto.message(message)
        return True

class OnionClientFactory(protocol.ServerFactory):
    """ We define a distinct protocol factory for outbound connections.
    Notably, this factory supports only *one* protocol instance at a time.
    """
    protocol = OnionLineProtocol

    def __init__(self, message_receive_callback: Callable,
                 connection_callback: Callable,
                 disconnection_callback: Callable):
        self.proto_client = None
        # callback takes OnionCustomMessage as arg and returns None
        self.message_receive_callback = message_receive_callback
        # connection callback, no args, returns None
        self.connection_callback = connection_callback
        # disconnection the same
        self.disconnection_callback = disconnection_callback

    def register_connection(self, p: OnionLineProtocol) -> None:
        #print("in OnionClientFactory, registered a connection, proto instance: ", p)
        self.proto_client = p
        self.connection_callback()

    def register_disconnection(self, p: OnionLineProtocol) -> None:
        self.proto_client = None
        self.disconnection_callback()

    def send(self, msg: OnionCustomMessage) -> bool:
        self.proto_client.message(msg)

    def receive_message(self, message: OnionCustomMessage,
                        p: OnionLineProtocol) -> None:
        self.message_receive_callback(message)

    """
    def clientConnectionLost(self, connector, reason):
        log.debug('Connection to peer lost: {}, reason: {}'.format(connector, reason))
        if reactor.running:
            log.info('Attempting to reconnect...')
            protocol.ReconnectingClientFactory.clientConnectionLost(
                self, connector, reason)

    def clientConnectionFailed(self, connector, reason):
        log.debug('Connection to peer failed: {}, reason: {}'.format(
            connector, reason))
        if reactor.running:
            log.info('Attempting to reconnect...')
            protocol.ReconnectingClientFactory.clientConnectionFailed(
                self, connector, reason)
    """

class OnionPeer(object):

    def __init__(self, messagechannel: 'OnionMessageChannel',
                 socks5_host: str, socks5_port: int,
                 hostname: str=None, port: int=-1,
                 directory: bool=False, nick: str="",
                 handshake_callback: Callable=None):
        # reference to the managing OnionMessageChannel instance is
        # needed so that we know where to send the messages received
        # from this peer:
        self.messagechannel = messagechannel
        self.nick = nick
        # client side net config:
        self.socks5_host = socks5_host
        self.socks5_port = socks5_port
        # remote net config:
        self.hostname = hostname
        self.port = port
        if directory and not (self.hostname):
            raise OnionPeerDirectoryWithoutHostError()
        self.directory = directory
        self._status = PEER_STATUS_UNCONNECTED
        #A function to be called to initiate a handshake;
        # it should take a single argument, an OnionPeer object,
        #and return None.
        self.handshake_callback = handshake_callback
        # Keep track of the protocol factory used to connect
        # to the remote peer. Note that this won't always be used,
        # if we have an inbound connection from this peer:
        self.factory = None
        # alternate location strings are used for inbound
        # connections for this peer (these will be used first
        # and foremost by directories, sending messages backwards
        # on a connection created towards them).
        self.alternate_location = ""

    def set_alternate_location(self, location_string: str):
        self.alternate_location = location_string

    def update_status(self, destn_status: int) -> None:
        """ Wrapping state updates to enforce:
        (a) that the handshake is triggered by connection
        outwards, and (b) to ensure no illegal state transitions.
        """
        assert destn_status in range(4)
        ignored_updates = []
        if self._status == PEER_STATUS_UNCONNECTED:
            allowed_updates = [PEER_STATUS_CONNECTED,
                               PEER_STATUS_DISCONNECTED]
        elif self._status == PEER_STATUS_CONNECTED:
            # updates from connected->connected are harmless
            allowed_updates = [PEER_STATUS_CONNECTED,
                               PEER_STATUS_DISCONNECTED,
                               PEER_STATUS_HANDSHAKED]
        elif self._status ==  PEER_STATUS_HANDSHAKED:
            allowed_updates = [PEER_STATUS_DISCONNECTED]
            ignored_updates = [PEER_STATUS_CONNECTED]
        elif self._status == PEER_STATUS_DISCONNECTED:
            allowed_updates = [PEER_STATUS_CONNECTED]
            ignored_updates = [PEER_STATUS_DISCONNECTED]
        if destn_status in ignored_updates:
            # TODO: this happens sometimes from 2->1; why?
            log.debug("Attempt to update status of peer from {} "
                      "to {} ignored.".format(self._status, destn_status))
            return
        assert destn_status in allowed_updates, ("couldn't update state "
                        "from {} to {}".format(self._status, destn_status))
        self._status = destn_status
        # the handshakes are always initiated by a client:
        if destn_status == PEER_STATUS_CONNECTED:
            log.info("We, {}, are calling the handshake callback as client.".format(self.messagechannel.self_as_peer.peer_location()))
            self.handshake_callback(self)

    def status(self) -> int:
        """ Simple getter function for the wrapped _status:
        """
        return self._status

    def set_nick(self, nick: str) -> None:
        self.nick = nick

    def get_nick_peerlocation_ser(self) -> str:
        if not self.nick:
            raise OnionPeerError("Cannot serialize "
                "identifier string without nick.")
        return self.nick + NICK_PEERLOCATOR_SEPARATOR + \
               self.peer_location()

    @classmethod
    def from_location_string(cls, mc: 'OnionMessageChannel',
                location: str,
                socks5_host: str,
                socks5_port: int,
                directory: bool=False,
                handshake_callback: Callable=None) -> 'OnionPeer':
        """ Allows construction of an OnionPeer from the
        connection information given by the network interface.
        TODO: special handling for inbound is needed.
        """
        host, port = location.split(":")
        return cls(mc, socks5_host, socks5_port, hostname=host,
                   port=int(port), directory=directory,
                   handshake_callback=handshake_callback)

    def set_host_port(self, hostname: str, port: int) -> None:
        """ If the connection info is discovered
        after this peer was already added to our list,
        we can set it with this method.
        """
        self.hostname = hostname
        self.port = port

    def set_location(self, location_string: str) -> bool:
        """ Allows setting location from an unchecked
        input string argument; if the string does not have
        the required format,
        will return False, otherwise self.hostname, self.port are
        updated for future `peer_location` calls, and True is returned.
        """
        try:
            host, port = location_string.split(":")
            portint = int(port)
            assert portint > 0
        except Exception as e:
            log.debug("Failed to update host and port of this peer, "
                      "error: {}".format(repr(e)))
            return False
        self.hostname = host
        self.port = portint
        return True

    def peer_location(self) -> str:
        assert (self.hostname and self.port > 0)
        return self.hostname + ":" + str(self.port)

    def send(self, message: OnionCustomMessage) -> bool:
        """ If the message can be sent on either an inbound or
        outbound connection, True is returned, else False.
        """
        if not self.factory:
            #print("We are: {}. peer, wich was directory {}, did not have factory, so we send via mc".format(
            #    self.messagechannel.self_as_peer.peer_location(), self.directory))
            # we try to send via the overall message channel serving
            # protocol, i.e. we assume the connection was made inbound:
            #print("and to this location: ", self.peer_location())
            return self.messagechannel.proto_factory.send(message, self.alternate_location)
        #print("peer which was directory {} did have factory {}, we send via that".format(self.directory, self.factory))
        return self.factory.send(message)

    def receive_message(self, message: OnionCustomMessage) -> None:
        self.messagechannel.receive_msg(message, self.peer_location())

    def connect(self) -> None:
        """ This method is called to connect, over Tor, to the remote
        peer at the given onion host/port.
        The connection is 'persistent' in the sense that we use a
        ReconnectingClientFactory.
        """
        if self._status in [PEER_STATUS_HANDSHAKED, PEER_STATUS_CONNECTED]:
            return
        if not (self.hostname and self.port > 0):
            raise OnionPeerConnectionError(
                "Cannot connect without host, port info")

        self.factory = OnionClientFactory(self.receive_message,
            self.register_connection, self.register_disconnection)
        if testing_mode:
            print("{} is making a tcp connection to {}, {}, {},".format(
                self.messagechannel.self_as_peer.peer_location(), self.hostname, self.port, self.factory))
            self.tcp_connector = reactor.connectTCP(self.hostname, self.port, self.factory)
        else:
            torEndpoint = TCP4ClientEndpoint(reactor, self.socks5_host, self.socks5_port)
            onionEndpoint = TorSocksEndpoint(torEndpoint, self.hostname, self.port)
            onionEndpoint.connect(self.factory)

    def register_connection(self) -> None:
        self.messagechannel.register_connection(self.peer_location(), direction=1)

    def register_disconnection(self) -> None:
        self.messagechannel.register_disconnection(self.peer_location())

    def try_to_connect(self) -> None:
        """ This method wraps OnionPeer.connect and accepts
        any error if that fails.
        """
        try:
            self.connect()
        except OnionPeerConnectionError as e:
            log.debug("Tried to connect but failed: {}".format(repr(e)))
        except Exception as e:
            log.warn("Got unexpected exception in connect attempt: {}".format(
                repr(e)))

    def disconnect(self) -> None:
        if self._status in [PEER_STATUS_UNCONNECTED, PEER_STATUS_DISCONNECTED]:
            return
        if not (self.hostname and self.port > 0):
            raise OnionPeerConnectionError(
                "Cannot disconnect without host, port info")
        d = self.reconnecting_service.stopService()
        d.addCallback(self.complete_disconnection)
        d.addErrback(log.warn, "Failed to disconnect from peer {}.".format(
            self.peer_location()))

    def complete_disconnection(self):
        log.debug("Disconnected from peer: {}".format(self.peer_location()))
        self.update_status(PEER_STATUS_DISCONNECTED)
        self.factory = None

class OnionDirectoryPeer(OnionPeer):
    delay = 4.0
    def try_to_connect(self) -> None:
        # Delay deliberately expands out to very
        # long times as yg-s tend to be very long
        # running bots:
        self.delay *= 1.5
        if self.delay > 10000:
            log.warn("Cannot connect to directory node peer: {} "
                     "after 20 attempts, giving up.".format(self.peer_location()))
            return
        try:
            self.connect()
        except OnionPeerConnectionError:
            reactor.callLater(self.delay, self.try_to_connect)

class OnionMessageChannel(MessageChannel):
    """ Receives messages via a Torv3 hidden/onion service.
    Sends messages to other nodes of the same type over Tor
    via SOCKS5.
    Uses one or more configured "directory nodes"
    to access a list of current active nodes, and updates
    dynamically from messages seen.
    """

    def __init__(self,
                 configdata,
                 daemon=None):
        MessageChannel.__init__(self, daemon=daemon)
        # hostid is a feature to avoid replay attacks across message channels;
        # TODO investigate, but for now, treat onion-based as one "server".
        self.hostid = "onion-network"
        self.tor_control_host = configdata["tor_control_host"]
        self.tor_control_port = int(configdata["tor_control_port"])
        self.onion_serving_host=configdata["onion_serving_host"]
        self.onion_serving_port=int(configdata["onion_serving_port"])
        self.hidden_service_dir = configdata["hidden_service_dir"]
        # client side config:
        self.socks5_host = "127.0.0.1"
        self.socks5_port = 9050
        # we use the setting in the config sent over from
        # the client, to decide whether to set up our connections
        # over localhost (if testing), without Tor:
        set_testing_mode(configdata)
        log.info("after call to testing_mode, it is: {}".format(testing_mode))
        # keep track of peers. the list will be instances
        # of OnionPeer:
        self.peers = set()
        for dn in configdata["directory_nodes"].split(","):
            # note we don't use a nick for directories:
            self.peers.add(OnionDirectoryPeer.from_location_string(
                self, dn, self.socks5_host, self.socks5_port,
                directory=True, handshake_callback=self.handshake_as_client))
        # we can direct messages via the protocol factory, which
        # will index protocol connections by peer location:
        self.proto_factory = OnionLineProtocolFactory(self)
        if testing_mode:
            # we serve over TCP:
            self.testing_serverconn = reactor.listenTCP(self.onion_serving_port,
                                self.proto_factory, interface="localhost")
            self.onion_hostname = "127.0.0.1"
        else:
            self.hs = JMHiddenService(self.proto_factory,
                                      self.info_callback,
                                      self.setup_error_callback,
                                      self.onion_hostname_callback,
                                      self.tor_control_host,
                                      self.tor_control_port,
                                      self.onion_serving_host,
                                      self.onion_serving_port,
                                      shutdown_callback=self.shutdown_callback,
                                      hidden_service_dir=self.hidden_service_dir)
            # this call will start bringing up the HS; when it's finished,
            # it will fire the `onion_hostname_callback`, or if it fails,
            # it'll fire the `setup_error_callback`.
            self.hs.start_tor()

            # This will serve as our unique identifier, indicating
            # that we are ready to communicate (in both directions) over Tor.
            self.onion_hostname = None

        # intended to represent the special case of 'we are the
        # only directory node known', however for now dns don't interact
        # so this has no role. TODO probably remove it.
        self.genesis_node = False

        # waiting loop for all directories to have
        # connected (note we could use a deferred but
        # the rpc connection calls are not using twisted)
        self.wait_for_directories_loop = None

    def info_callback(self, msg):
        log.info(msg)

    def setup_error_callback(self, msg):
        log.error(msg)

    def shutdown_callback(self, msg):
        log.info("in shutdown callback: {}".format(msg))

    def onion_hostname_callback(self, hostname):
        """ This entrypoint marks the start of the OnionMessageChannel
        running, since we need this unique identifier as our name
        before we can start working (we need to compare it with the
        configured directory nodes).
        """
        print("hostname: ", hostname)
        print("type: ", type(hostname))
        log.info("setting onion hostname to : {}".format(hostname))
        self.onion_hostname = hostname

# ABC implementation section
    def run(self) -> None:
        self.hs_up_loop = task.LoopingCall(self.check_onion_hostname)
        self.hs_up_loop.start(0.5)

    def get_pubmsg(self, msg:str, source_nick:str ="") -> str:
        """ Converts a message into the known format for
        pubmsgs; if we are not sending this (because we
        are a directory, forwarding it), `source_nick` must be set.
        Note that pubmsg does NOT prefix the *message* with COMMAND_PREFIX.
        """
        nick = source_nick if source_nick else self.nick
        return nick + COMMAND_PREFIX + "PUBLIC" + msg
 
    def get_privmsg(self, nick: str, cmd: str, message: str,
                    source_nick=None) -> None:
        """ See `get_pubmsg` for comment on `source_nick`.
        """
        from_nick = source_nick if source_nick else self.nick
        return from_nick + COMMAND_PREFIX + nick + COMMAND_PREFIX + \
               cmd + " " + message

    def _pubmsg(self, msg:str) -> None:
        """ Best effort broadcast of message `msg`:
        send the message to every known directory node,
        with the PUBLIC message type and nick.
        """
        peerids = self.get_directory_peers()
        msg = OnionCustomMessage(self.get_pubmsg(msg),
                                JM_MESSAGE_TYPES["pubmsg"])
        for peerid in peerids:
            # currently a directory node can send its own
            # pubmsgs (act as maker or taker); this will
            # probably be removed but is useful in testing:
            if peerid == self.self_as_peer.peer_location():
                self.receive_msg(msg, "00")
            else:
                self._send(self.get_peer_by_id(peerid), msg)

    def _privmsg(self, nick: str, cmd: str, msg:str) -> None:
        log.debug("Privmsging to: {}, {}, {}".format(nick, cmd, msg))
        encoded_privmsg = OnionCustomMessage(self.get_privmsg(nick, cmd, msg),
                            JM_MESSAGE_TYPES["privmsg"])
        peerid = self.get_peerid_by_nick(nick)
        if peerid:
            peer = self.get_peer_by_id(peerid)
        # notice the order matters here!:
        if not peerid or not peer or not peer.status() == PEER_STATUS_HANDSHAKED:
            # If we are trying to message a peer via their nick, we
            # may not yet have a connection; then we just
            # forward via directory nodes.
            log.debug("Privmsg peer: {} but don't have peerid; "
                     "sending via directory.".format(nick))
            try:
                # TODO change this to redundant or switching?
                peer = self.get_connected_directory_peers()[0]
            except Exception as e:
                log.warn("Failed to send privmsg because no "
                "directory peer is connected. Error: {}".format(repr(e)))
                return
        self._send(peer, encoded_privmsg)

    def _announce_orders(self, offerlist: list) -> None:
        for offer in offerlist:
            self._pubmsg(offer)

# End ABC implementation section

    def check_onion_hostname(self):
        if not self.onion_hostname:
            return
        self.hs_up_loop.stop()
        # now our hidden service is up, we must check our peer status
        # then set up directories.
        self.get_our_peer_info()
        # at this point the only peers added are directory
        # nodes from config; we try to connect to all.
        # We will get other peers to add to our list once they
        # start sending us messages.
        reactor.callLater(0.0, self.connect_to_directories)

    def get_our_peer_info(self) -> None:
        """ Create a special OnionPeer object,
        outside of our peerlist, to refer to ourselves.
        """
        dp = self.get_directory_peers()
        self_dir = False
        # only for publically exposed onion does the 'virtual port' exist;
        # for local tests we always connect to an actual machine port:
        port_to_check = 80 if not testing_mode else self.onion_serving_port
        my_location_str = self.onion_hostname + ":" + str(port_to_check)
        log.info("To check if we are genesis, we compare {} with {}".format(my_location_str, dp))
        if [my_location_str] == dp:
            log.info("This is the genesis node: {}".format(self.onion_hostname))
            self.genesis_node = True
            self_dir = True
        elif my_location_str in dp:
            # Here we are just one of many directory nodes,
            # which should be fine, we should just be careful
            # to not query ourselves.
            self_dir = True
        self.self_as_peer = OnionPeer(self, self.socks5_host, self.socks5_port,
                                      self.onion_hostname, self.onion_serving_port,
                                        self_dir, nick=self.nick,
                                        handshake_callback=None)

    def connect_to_directories(self) -> None:
        if self.genesis_node:
            # we are a directory and we have no directory peers;
            # just start.
            self.on_welcome(self)
            return
        # the remaining code is only executed by non-directories:
        for p in self.peers:
            log.info("Trying to connect to node: {}".format(p.peer_location()))
            try:
                p.connect()
            except OnionPeerConnectionError:
                pass
        # do not trigger on_welcome event until all directories
        # configured are ready:
        self.on_welcome_sent = False
        self.wait_for_directories_loop = task.LoopingCall(
            self.wait_for_directories)
        self.wait_for_directories_loop.start(10.0)

    def handshake_as_client(self, peer: OnionPeer) -> None:
        assert peer.status() == PEER_STATUS_CONNECTED
        if self.self_as_peer.directory:
            log.debug("Not sending client handshake to {} because we are directory.".format(peer.peer_location()))
            return
        our_hs = copy.deepcopy(client_handshake_json)
        our_hs["location-string"] = self.self_as_peer.peer_location()
        our_hs["nick"] = self.nick
        # We fire and forget the handshake; successful setting
        # of the `is_handshaked` var in the Peer object will depend
        # on a valid/success return via the custommsg hook in the plugin.
        log.info("Sending this handshake: {} to peer {}".format(json.dumps(our_hs), peer.peer_location()))
        self._send(peer, OnionCustomMessage(json.dumps(our_hs),
                                    CONTROL_MESSAGE_TYPES["handshake"]))

    def handshake_as_directory(self, peer: OnionPeer, our_hs: dict) -> None:
        assert peer.status() == PEER_STATUS_CONNECTED
        log.info("Sending this handshake as directory: {}".format(json.dumps(our_hs)))
        self._send(peer, OnionCustomMessage(json.dumps(our_hs),
                    CONTROL_MESSAGE_TYPES["dn-handshake"]))

    def get_directory_peers(self) -> list:
        return [ p.peer_location() for p in self.peers if p.directory is True]

    def get_peerid_by_nick(self, nick:str) -> Union[OnionPeer, None]:
        for p in self.get_all_connected_peers():
            if p.nick == nick:
                return p.peer_location()
        return None

    def _send(self, peer: OnionPeer, message: OnionCustomMessage) -> bool:
        try:
            return peer.send(message)
        except Exception as e:
            # This can happen when a peer disconnects, depending
            # on the timing:
            log.warn("Failed to send message to: {}, error: {}".format(
                peer.peer_location(), repr(e)))
            return False

    def shutdown(self):
        """ TODO
        """

    def receive_msg(self, message: OnionCustomMessage, peer_location: str) -> None:
        """ Messages from peers and also connection related control
        messages. These messages either come via OnionPeer or via
        the main OnionLineProtocolFactory instance that handles all
        inbound connections.
        """
        if self.self_as_peer.directory:
            print("received message as directory: ", message.encode())
        peer = self.get_peer_by_id(peer_location)
        if not peer:
            log.warn("Received message but could not find peer: {}".format(peer_location))
            return
        msgtype = message.msgtype
        msgval = message.text
        if msgtype in LOCAL_CONTROL_MESSAGE_TYPES.values():
            self.process_control_message(peer_location, msgtype, msgval)
            # local control messages are processed first.
            # TODO this is a historical artifact, we can simplify.
            return

        if self.process_control_message(peer_location, msgtype, msgval):
            # will return True if it is, elsewise, a control message.
            return

        # ignore non-JM messages:
        if not msgtype in JM_MESSAGE_TYPES.values():
            log.debug("Invalid message type, ignoring: {}".format(msgtype))
            return

        # real JM message; should be: from_nick, to_nick, cmd, message
        try:
            nicks_msgs = msgval.split(COMMAND_PREFIX)
            from_nick, to_nick = nicks_msgs[:2]
            msg = COMMAND_PREFIX + COMMAND_PREFIX.join(nicks_msgs[2:])
            if to_nick == "PUBLIC":
                #log.debug("A pubmsg is being processed by {} from {}; it "
                #    "is {}".format(self.self_as_peer.nick, from_nick, msg))
                self.on_pubmsg(from_nick, msg)
                if self.self_as_peer.directory:
                    self.forward_pubmsg_to_peers(msg, from_nick)
            elif to_nick != self.nick:
                if not self.self_as_peer.directory:
                    log.debug("Ignoring message, not for us: {}".format(msg))
                else:
                    self.forward_privmsg_to_peer(to_nick, msg, from_nick)
            else:
                self.on_privmsg(from_nick, msg)
        except Exception as e:
            log.debug("Invalid joinmarket message: {}, error was: {}".format(
                msgval, repr(e)))
            return

    def forward_pubmsg_to_peers(self, msg: str, from_nick: str) -> None:
        """ Used by directory nodes currently. Takes a received
        message that was PUBLIC and broadcasts it to the non-directory
        peers.
        """
        assert self.self_as_peer.directory
        pubmsg = self.get_pubmsg(msg, source_nick=from_nick)
        msgtype = JM_MESSAGE_TYPES["pubmsg"]
        # NOTE!: Specifically with forwarding/broadcasting,
        # we introduce the danger of infinite re-broadcast,
        # if there is more than one party forwarding.
        # For now we are having directory nodes not talk to
        # each other (i.e. they are *required* to only configure
        # themselves, not other dns). But this could happen by
        # accident.
        encoded_msg = OnionCustomMessage(pubmsg, msgtype)
        for peer in self.get_connected_nondirectory_peers():
            # don't loop back to the sender:
            if peer.nick == from_nick:
                continue
            log.debug("Sending {}:{} to nondir peer {}".format(
                msgtype, pubmsg, peer.peer_location()))
            self._send(peer, encoded_msg)

    def forward_privmsg_to_peer(self, nick: str, message: str,
                                from_nick: str) -> None:
        assert self.self_as_peer.directory
        peerid = self.get_peerid_by_nick(nick)
        if not peerid:
            log.debug("We were asked to send a message from {} to {}, "
                      "but {} is not connected.".format(from_nick, nick, nick))
            return
        # The `message` passed in has format COMMAND_PREFIX||command||" "||msg
        # we need to parse out cmd, message for sending.
        _, cmdmsg = message.split(COMMAND_PREFIX)
        cmdmsglist = cmdmsg.split(" ")
        cmd = cmdmsglist[0]
        msg = " ".join(cmdmsglist[1:])
        privmsg = self.get_privmsg(nick, cmd, msg, source_nick=from_nick)
        #log.debug("Sending out privmsg: {} to peer: {}".format(privmsg, peerid))
        encoded_msg = OnionCustomMessage(privmsg,
                        JM_MESSAGE_TYPES["privmsg"])
        self._send(self.get_peer_by_id(peerid), encoded_msg)
        # If possible, we forward the from-nick's network location
        # to the to-nick peer, so they can just talk directly next time.
        peerid_from = self.get_peerid_by_nick(from_nick)
        if not peerid_from:
            return
        peer_to = self.get_peer_by_id(peerid)
        self.send_peers(peer_to, peerid_filter=[peerid_from])

    def process_control_message(self, peerid: str, msgtype: int,
                                msgval: str) -> bool:
        """ Triggered by a directory node feeding us
        peers, or by a connect/disconnect hook; this is our housekeeping
        to try to create, and keep track of, useful connections.
        """
        all_ctrl = list(LOCAL_CONTROL_MESSAGE_TYPES.values(
            )) + list(CONTROL_MESSAGE_TYPES.values())
        if msgtype not in all_ctrl:
            return False
        # this is too noisy, but TODO, investigate allowing
        # some kind of control message monitoring e.g. default-off
        # log-to-file (we don't currently have a 'TRACE' level debug).
        #log.debug("received control message: {},{}".format(msgtype, msgval))
        if msgtype == CONTROL_MESSAGE_TYPES["peerlist"]:
            # This is the base method of seeding connections;
            # a directory node can send this any time. We may well
            # need to control this; for now it just gets processed,
            # whereever it came from:
            try:
                peerlist = msgval.split(",")
                for peer in peerlist:
                    # defaults mean we just add the peer, not
                    # add or alter its connection status:
                    self.add_peer(peer, with_nick=True)
            except Exception as e:
                log.debug("Incorrectly formatted peer list: {}, "
                      "ignoring, {}".format(msgval, e))
                # returning True either way, because although it was an
                # invalid message, it *was* a control message, and should
                # not be processed as something else.
            return True
        elif msgtype == CONTROL_MESSAGE_TYPES["getpeerlist"]:
            # getpeerlist must be accompanied by a full node
            # locator, and nick;
            # add that peer before returning our peer list.
            p = self.add_peer(msgval, connection=True,
                              overwrite_connection=True, with_nick=True)
            try:
                self.send_peers(p)
            except OnionPeerConnectionError:
                pass
            # comment much as above; if we can't connect, it's none
            # of our business.
            return True
        elif msgtype == CONTROL_MESSAGE_TYPES["handshake"]:
            # sent by non-directory peers on startup
            self.process_handshake(peerid, msgval)
            return True
        elif msgtype == CONTROL_MESSAGE_TYPES["dn-handshake"]:
            self.process_handshake(peerid, msgval, dn=True)
            return True
        elif msgtype == LOCAL_CONTROL_MESSAGE_TYPES["connect"]:
            self.add_peer(msgval, connection=True,
                          overwrite_connection=True)
        elif msgtype == LOCAL_CONTROL_MESSAGE_TYPES["connect-in"]:
            self.add_peer(msgval, connection=True,
                          overwrite_connection=True)
        elif msgtype == LOCAL_CONTROL_MESSAGE_TYPES["disconnect"]:
            log.debug("We got a disconnect event: {}".format(msgval))
            if msgval in [x.peer_location() for x in self.get_connected_directory_peers()]:
                # we need to use the full peer locator string, so that
                # add_peer knows it can try to reconnect:
                msgval = self.get_peer_by_id(msgval).peer_location()
            self.add_peer(msgval, connection=False,
                          overwrite_connection=True)
        else:
            assert False
        # If we got here it is *not* a non-local control message;
        # so we must process it as a Joinmarket message.
        return False


    def process_handshake(self, peerid: str, message: str,
                          dn: bool=False) -> None:
        peer = self.get_peer_by_id(peerid)
        if not peer:
            # rando sent us a handshake?
            log.warn("Unexpected handshake from unknown peer: {}, "
                     "ignoring.".format(peerid))
            return
        assert isinstance(peer, OnionPeer)
        if not peer.status() == PEER_STATUS_CONNECTED:
            # we were not waiting for it:
            log.warn("Unexpected handshake from peer: {}, "
                     "ignoring. Peer's current status is: {}".format(
                         peerid, peer.status()))
            return
        if dn:
            print("We, {}, are processing a handshake with dn {} from peer {}".format(self.self_as_peer.peer_location(), dn, peerid))
            # it means, we are a non-dn and we are expecting
            # a returned `dn-handshake` message:
            # (currently dns don't talk to other dns):
            assert not self.self_as_peer.directory
            if not peer.directory:
                # got dn-handshake from non-dn:
                log.warn("Unexpected dn-handshake from non-dn "
                         "node: {}, ignoring.".format(peerid))
                return
            # we got the right message from the right peer;
            # check it is formatted correctly and represents
            # acceptance of the connection
            try:
                handshake_json = json.loads(message)
                app_name = handshake_json["app-name"]
                is_directory = handshake_json["directory"]
                proto_min = handshake_json["proto-ver-min"]
                proto_max = handshake_json["proto-ver-max"]
                features = handshake_json["features"]
                accepted = handshake_json["accepted"]
                nick = handshake_json["nick"]
                assert isinstance(proto_max, int)
                assert isinstance(proto_min, int)
                assert isinstance(features, dict)
                assert isinstance(nick, str)
            except Exception as e:
                log.warn("Invalid handshake message from: {}, exception: {}, message: {},"
                         "ignoring".format(peerid, repr(e), message))
                return
            # currently we are not using any features, but the intention
            # is forwards compatibility, so we don't check its contents
            # at all.
            if not accepted:
                log.warn("Directory: {} rejected our handshake.".format(peerid))
                return
            if not (app_name == JM_APP_NAME and is_directory and JM_VERSION \
                    <= proto_max and JM_VERSION >= proto_min and accepted):
                log.warn("Handshake from directory is incompatible or "
                         "rejected: {}".format(handshake_json))
                return
            # We received a valid, accepting dn-handshake. Update the peer.
            peer.update_status(PEER_STATUS_HANDSHAKED)
            peer.set_nick(nick)
        else:
            print("We, {}, are processing a handshake with dn {} from peer {}".format(self.self_as_peer.peer_location(), dn, peerid))
            # it means, we are receiving an initial handshake
            # message from a 'client' (non-dn) peer.
            # dns don't talk to each other:
            assert not peer.directory
            accepted = True
            try:
                handshake_json = json.loads(message)
                app_name = handshake_json["app-name"]
                is_directory = handshake_json["directory"]
                proto_ver = handshake_json["proto-ver"]
                features = handshake_json["features"]
                full_location_string = handshake_json["location-string"]
                nick = handshake_json["nick"]
                assert isinstance(proto_ver, int)
                assert isinstance(features, dict)
                assert isinstance(nick, str)
            except Exception as e:
                log.warn("(not dn) Invalid handshake message from: {}, exception: {}, message: {},"
                         "ignoring".format(peerid, repr(e), message))
                accepted = False
            if not (app_name == JM_APP_NAME and proto_ver == JM_VERSION \
                    and not is_directory):
                log.warn("Invalid handshake name/version data: {}, from peer: "
                         "{}, rejecting.".format(message, peerid))
                accepted = False
            # If accepted, we should update the peer to have the full
            # location which in general will not yet be present, so as to
            # allow publishing their location via `getpeerlist`:
            if not peer.set_location(full_location_string):
                accepted = False
            if not peerid == full_location_string:
                print("we are reading a handshake from location {} but they sent"
                      "us full location string {}, setting an alternate".format(
                          peerid, full_location_string))
                peer.set_alternate_location(peerid)
            peer.set_nick(nick)
            # client peer's handshake message was valid; send ours, and
            # then mark this peer as successfully handshaked:
            our_hs = copy.deepcopy(server_handshake_json)
            our_hs["nick"] = self.nick
            our_hs["accepted"] = accepted
            if self.self_as_peer.directory:
                self.handshake_as_directory(peer, our_hs)
            if accepted:
                peer.update_status(PEER_STATUS_HANDSHAKED)

    def get_peer_by_id(self, p: str) -> Union[OnionPeer, bool]:
        """ Returns the OnionPeer with peer location p,
        if it is in self.peers, otherwise returns False.
        """
        if p == "00":
            return self.self_as_peer
        for x in self.peers:
            if x.peer_location() == p:
                return x
            if x.alternate_location == p:
                return x
        return False

    def register_connection(self, peer_location: str, direction: int) -> None:
        """ We send ourselves a local control message indicating
        the new connection.
        If the connection is inbound, direction == 0, else 1.
        """
        assert direction in range(2)
        if direction == 1:
            msgtype = LOCAL_CONTROL_MESSAGE_TYPES["connect"]
        else:
            msgtype = LOCAL_CONTROL_MESSAGE_TYPES["connect-in"]
        msg = OnionCustomMessage(peer_location, msgtype)
        self.receive_msg(msg, "00")

    def register_disconnection(self, peer_location: str) -> None:
        """ We send ourselves a local control message indicating
        the disconnection.
        """
        msg = OnionCustomMessage(peer_location,
                    LOCAL_CONTROL_MESSAGE_TYPES["disconnect"])
        self.receive_msg(msg, "00")

    def add_peer(self, peerdata: str, connection: bool=False,
                overwrite_connection: bool=False, with_nick=False) -> None:
        """ add non-directory peer from (nick, peer) serialization `peerdata`,
        where "peer" is host:port;
        return the created OnionPeer object. Or, with_nick=False means
        that `peerdata` has only the peer location.
        If the peer is already in our peerlist it can be updated in
        one of these ways:
        * the nick can be added
        * it can be marked as 'connected' if it was previously unconnected,
        with this conditional on whether the flag `overwrite_connection` is
        set. Note that this peer removal, unlike the peer addition above,
        can also occur for directory nodes, if we lose connection (and then
        we persistently try to reconnect; see OnionDirectoryPeer).
        """
        if with_nick:
            try:
                nick, peer = peerdata.split(NICK_PEERLOCATOR_SEPARATOR)
            except Exception as e:
                # TODO: as of now, this is not an error, but expected.
                # Don't log? Do something else?
                log.debug("Received invalid peer identifier string: {}, {}".format(
                    peerdata, e))
                return
        else:
            peer = peerdata

        # assumed that it's passing a full string
        try:
            temp_p = OnionPeer.from_location_string(self, peer,
                        self.socks5_host, self.socks5_port,
                        handshake_callback=self.handshake_as_client)
        except Exception as e:
            # There are currently a few ways the location
            # parsing and Peer object construction can fail;
            # TODO specify exception types.
            log.warn("Failed to add peer: {}, exception: {}".format(peer, repr(e)))
            return
        if not self.get_peer_by_id(temp_p.peer_location()):
            if connection:
                log.info("Updating status of peer: {} to connected.".format(temp_p.peer_location()))
                temp_p.update_status(PEER_STATUS_CONNECTED)
            else:
                temp_p.update_status(PEER_STATUS_DISCONNECTED)
            if with_nick:
                temp_p.set_nick(nick)
            self.peers.add(temp_p)
            if not connection:
                # Here, we are not currently connected. We
                # try to connect asynchronously. We don't pay attention
                # to any return. This attempt is one-shot and opportunistic,
                # for non-dns, but will retry with exp-backoff for dns.
                # Notice this is only possible for non-dns to other non-dns,
                # since dns will never reach this point without an active
                # connection.
                reactor.callLater(0.0, temp_p.try_to_connect)
            return temp_p
        else:
            p = self.get_peer_by_id(temp_p.peer_location())
            if overwrite_connection:
                if connection:
                    log.info("Updating status to connected for peer {}.".format(temp_p.peer_location()))
                    p.update_status(PEER_STATUS_CONNECTED)
                else:
                    p.update_status(PEER_STATUS_DISCONNECTED)
            if with_nick:
                p.set_nick(nick)
            return p

    def get_all_connected_peers(self) -> list:
        return self.get_connected_directory_peers() + \
               self.get_connected_nondirectory_peers()

    def get_connected_directory_peers(self) -> list:
        return [p for p in self.peers if p.directory and p.status() == \
                PEER_STATUS_HANDSHAKED]

    def get_connected_nondirectory_peers(self) -> list:
        return [p for p in self.peers if (not p.directory) and p.status() == \
                PEER_STATUS_HANDSHAKED]

    def wait_for_directories(self) -> None:
        # Notice this is checking for *handshaked* dps;
        # the handshake will have been initiated once a
        # connection was seen:
        log.warn("in the wait for directories loop, this is the connected dps: {}".format(self.get_connected_directory_peers()))
        if len(self.get_connected_directory_peers()) == 0:
            return
        # This is what triggers the start of taker/maker workflows.
        if not self.on_welcome_sent:
            self.on_welcome(self)
            self.on_welcome_sent = True
            self.wait_for_directories_loop.stop()

    """ CONTROL MESSAGES SENT BY US
    """
    def send_peers(self, requesting_peer: OnionPeer,
                   peerid_filter: list=[]) -> None:
        """ This message is sent by directory peers on request
        by non-directory peers.
        If peerid_filter is specified, only peers whose peerid is in
        this list will be sent. (TODO this is inefficient).
        The peerlist message should have this format:
        (1) entries comma separated
        (2) each entry is serialized nick then the NICK_PEERLOCATOR_SEPARATOR
            then *either* 66 char hex peerid, *or* peerid@host:port
        (3) However this message might be long enough to exceed a 1300 byte limit,
            if we don't use a filter, so we may need to split it into multiple
            messages (TODO).
        """
        if not requesting_peer.status() == PEER_STATUS_HANDSHAKED:
            raise OnionPeerConnectionError(
                "Cannot send peer list to unhandshaked peer")
        peerlist = set()
        for p in self.get_connected_nondirectory_peers():
            # don't send a peer to itself
            if p.peer_location() == requesting_peer.peer_location():
                continue
            if len(peerid_filter) > 0 and p.peer_location() not in peerid_filter:
                continue
            if not p.status() == PEER_STATUS_HANDSHAKED:
                # don't advertise what is not online.
                continue
            # peers that haven't sent their nick yet are not
            # privmsg-reachable; don't send them
            if p.nick == "":
                continue
            peerlist.add(p.get_nick_peerlocation_ser())
        # For testing: dns won't usually participate:
        peerlist.add(self.self_as_peer.get_nick_peerlocation_ser())
        self._send(requesting_peer, OnionCustomMessage(",".join(
            peerlist), CONTROL_MESSAGE_TYPES["peerlist"]))
