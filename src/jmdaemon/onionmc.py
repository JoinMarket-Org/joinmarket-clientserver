from jmdaemon.message_channel import MessageChannel
from jmdaemon.protocol import COMMAND_PREFIX, JM_VERSION
from jmbase import get_log,  JM_APP_NAME, JMHiddenService, stop_reactor
import json
import copy
import random
from typing import Callable, Union, Tuple, List
from twisted.internet import reactor, task, protocol
from twisted.protocols import basic
from twisted.application.internet import ClientService
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.address import IPv4Address, IPv6Address
from txtorcon.socks import (TorSocksEndpoint, HostUnreachableError,
                            SocksError, GeneralServerFailureError)

log = get_log()


NOT_SERVING_ONION_HOSTNAME = "NOT-SERVING-ONION"

# LongLivedPort
ONION_VIRTUAL_PORT = 5222

# How many seconds to wait before treating an onion
# as unreachable
CONNECT_TO_ONION_TIMEOUT = 60

def location_tuple_to_str(t: Tuple[str, int]) -> str:
    return f"{t[0]}:{t[1]}"

def network_addr_to_string(location: Union[IPv4Address, IPv4Address]) -> str:
    if isinstance(location, (IPv4Address, IPv6Address)):
        host = location.host
        port = location.port
    else:
        # TODO handle other addr types
        assert False
    return location_tuple_to_str((host, port))

# module-level var to control whether we use Tor or not
# (specifically for tests)
testing_mode = False
def set_testing_mode(configdata: dict) -> None:
    """ Toggles testing mode which enables non-Tor
    network setup:
    """
    global testing_mode
    if "regtest_count" not in configdata:
        testing_mode = False
        return
    try:
        s, e = [int(x) for x in configdata["regtest_count"].split(",")]
    except Exception as e:
        log.info("Failed to get regtest count settings, error: {}".format(repr(e)))
        testing_mode = False
        return
    if s == e == 0:
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

# location_string, nick and network must be set before sending,
# otherwise invalid:
client_handshake_json = {"app-name": JM_APP_NAME,
 "directory": False,
 "location-string": "",
 "proto-ver": JM_VERSION,
 "features": {},
 "nick": "",
 "network": ""
}

# default acceptance false; code must switch it on:
server_handshake_json = {"app-name": JM_APP_NAME,
  "directory": True,
  "proto-ver-min": JM_VERSION,
  "proto-ver-max": JM_VERSION,
  "features": {},
  "accepted": False,
  "nick": "",
  "network": "",
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

class InvalidLocationStringError(Exception):
    pass

class OnionDirectoryPeerNotFound(Exception):
    pass

class OnionCustomMessage(object):
    """ Encapsulates the messages passed over the wire
    to and from other onion peers
    """
    def __init__(self, text: str, msgtype: int):
        self.text = text
        self.msgtype = msgtype

    def encode(self) -> bytes:
        self.encoded = json.dumps({"type": self.msgtype,
                        "line": self.text}).encode("utf-8")
        return self.encoded

    @classmethod
    def from_string_decode(cls, msg: bytes) -> 'OnionCustomMessage':
        """ Build a custom message from a json-ified string.
        """
        try:
            msg_obj = json.loads(msg)
            text = msg_obj["line"]
            msgtype = msg_obj["type"]
            # we insist on integer but not a valid msgtype,
            # crudely 'syntax, not semantics':
            # semantics is the job of the OnionMessageChannel object.
            assert isinstance(msgtype, int)
            assert isinstance(text, str)
        except:
            # this blanket catch and re-raise:
            # we must handle untrusted input bytes without
            # crashing under any circumstance.
            raise OnionCustomMessageDecodingError
        return cls(text, msgtype)

class OnionLineProtocol(basic.LineReceiver):
    # there are messages requiring more than LineReceiver's 16KB,
    # specifically, large coinjoin transaction `pushtx` messages.
    # 40K is finger in the air for: 500bytes per participant, 40
    # participants, and a double base64 expansion (x1.33 and x1.33)
    # which gives 35.5K, add a little breathing room.
    MAX_LENGTH = 40000

    def connectionMade(self):
        self.factory.register_connection(self)
        basic.LineReceiver.connectionMade(self)

    def connectionLost(self, reason):
        self.factory.register_disconnection(self)
        basic.LineReceiver.connectionLost(self, reason)

    def lineReceived(self, line: bytes) -> None:
        try:
            msg = OnionCustomMessage.from_string_decode(line)
        except OnionCustomMessageDecodingError:
            log.debug("Received invalid message: {}, "
                      "dropping connection.".format(line))
            self.transport.loseConnection()
            return
        self.factory.receive_message(msg, self)

    def message(self, message: OnionCustomMessage) -> None:
        self.sendLine(message.encode())

class OnionLineProtocolFactory(protocol.ServerFactory):
    """ This factory allows us to start up instances
    of the LineReceiver protocol that are instantiated
    towards us.
    """
    protocol = OnionLineProtocol

    def __init__(self, client: 'OnionMessageChannel'):
        self.client = client
        self.peers = {}

    def register_connection(self, p: OnionLineProtocol) -> None:
        # make a local control message registering
        # the new connection
        peer_location = network_addr_to_string(p.transport.getPeer())
        self.peers[peer_location] = p
        self.client.register_connection(peer_location, direction=0)

    def register_disconnection(self, p: OnionLineProtocol) -> None:
        # make a local control message registering
        # the disconnection
        peer_location = network_addr_to_string(p.transport.getPeer())
        self.client.register_disconnection(peer_location)
        if peer_location not in self.peers:
            log.warn("Disconnection event registered for non-existent peer.")
            return
        del self.peers[peer_location]

    def disconnect_inbound_peer(self, inbound_peer_str: str) -> None:
        if inbound_peer_str not in self.peers:
            log.warn("cannot disconnect peer at {}, not found".format(
                inbound_peer_str))
        proto = self.peers[inbound_peer_str]
        proto.transport.loseConnection()

    def receive_message(self, message: OnionCustomMessage,
                        p: OnionLineProtocol) -> None:
        self.client.receive_msg(message, network_addr_to_string(
            p.transport.getPeer()))

    def send(self, message: OnionCustomMessage, destination: str) -> bool:
        if destination not in self.peers:
            log.warn("sending message {}, destination {} was not in peers {}".format(
                message.encode(), destination, self.peers))
            return False
        proto = self.peers[destination]
        proto.message(message)
        return True

class OnionClientFactory(protocol.ClientFactory):
    """ We define a distinct protocol factory for outbound connections.
    Notably, this factory supports only *one* protocol instance at a time.
    """
    protocol = OnionLineProtocol

    def __init__(self, message_receive_callback: Callable,
                 connection_callback: Callable,
                 disconnection_callback: Callable,
                 message_not_sendable_callback: Callable,
                 directory: bool,
                 mc: 'OnionMessageChannel'):
        self.proto_client = None
        # callback takes OnionCustomMessage as arg and returns None
        self.message_receive_callback = message_receive_callback
        # connection callback, no args, returns None
        self.connection_callback = connection_callback
        # disconnection the same
        self.disconnection_callback = disconnection_callback
        # a callback that can be fired if we are not able to send messages,
        # no args, returns None
        self.message_not_sendable_callback = message_not_sendable_callback
        # is this connection to a directory?
        self.directory = directory
        # to keep track of state of overall messagechannel
        self.mc = mc

    def clientConnectionLost(self, connector, reason):
        log.debug('Onion client connection lost: ' + str(reason))
        # persistent reconnection is reserved for directories;
        # for makers, it isn't logical to keep trying; they may
        # well have just shut down the onion permanently, and we can
        # reach them via directory anyway.
        if self.directory and not self.mc.give_up:
            if reactor.running:
                log.info('Attempting to reconnect...')
                protocol.ClientFactory.clientConnectionLost(self,
                                                            connector, reason)

    def clientConnectionFailed(self, connector, reason):
        log.info('Onion client connection failed: ' + str(reason))
        # reasoning here exactly as for clientConnectionLost
        if self.directory and not self.mc.give_up:
            if reactor.running:
                log.info('Attempting to reconnect...')
                protocol.ClientFactory.clientConnectionFailed(self,
                                                              connector, reason)
    def register_connection(self, p: OnionLineProtocol) -> None:
        self.proto_client = p
        self.connection_callback()

    def register_disconnection(self, p: OnionLineProtocol) -> None:
        self.proto_client = None
        self.disconnection_callback()

    def send(self, msg: OnionCustomMessage) -> bool:
        # we may be sending at the time the counterparty
        # disconnected
        if not self.proto_client:
            self.message_not_sendable_callback()
            return False
        self.proto_client.message(msg)
        # Unlike the serving protocol, the client protocol
        # is never in a condition of not knowing the counterparty
        return True

    def receive_message(self, message: OnionCustomMessage,
                        p: OnionLineProtocol) -> None:
        self.message_receive_callback(message)

class OnionPeer(object):
    """ Class encapsulating a peer we connect to.
    """

    def __init__(self, messagechannel: 'OnionMessageChannel',
                 socks5_host: str, socks5_port: int,
                 location_tuple: Tuple[str, int],
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
        self.hostname = location_tuple[0]
        self.port = location_tuple[1]
        # alternate location strings are used for inbound
        # connections for this peer (these will be used by
        # directories and onion-serving peers, sending
        # messages backwards on a connection created towards them).
        self.alternate_location = ""
        if self.hostname != NOT_SERVING_ONION_HOSTNAME:
            # There is no harm in always setting it by default;
            # it only gets used if we don't have an outbound.
            self.set_alternate_location(location_tuple_to_str(
                location_tuple))
        if directory and not self.hostname:
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
        # the reconnecting service allows auto-reconnection to
        # some peers:
        self.reconnecting_service = None
        # don't try to connect more than once
        # TODO: prefer state machine update
        self.connecting = False

    def set_alternate_location(self, location_string: str) -> None:
        self.alternate_location = location_string

    def update_status(self, destn_status: int) -> None:
        """ Wrapping state updates to enforce:
        (a) that the handshake is triggered by connection
        outwards, and (b) to ensure no illegal state transitions.
        """
        assert destn_status in range(4)
        ignored_updates = []
        if self._status == PEER_STATUS_UNCONNECTED:
            allowed_updates = [PEER_STATUS_CONNECTED]
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
            log.debug("Attempt to update status of peer from {} "
                      "to {} ignored.".format(self._status, destn_status))
            return
        assert destn_status in allowed_updates, ("couldn't update state "
                        "from {} to {}".format(self._status, destn_status))
        self._status = destn_status
        # the handshakes are always initiated by a client:
        if destn_status == PEER_STATUS_CONNECTED:
            self.connecting = False
            log.info("We, {}, are calling the handshake callback as client.".format(
                self.messagechannel.self_as_peer.peer_location()))
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
        try:
            host, port = location.split(":")
            portint = int(port)
        except:
            raise InvalidLocationStringError(location)
        return cls(mc, socks5_host, socks5_port,
                   (host, portint), directory=directory,
                   handshake_callback=handshake_callback)

    def set_location(self, location_string: str) -> bool:
        """ Allows setting location from an unchecked
        input string argument.
        If the location is specified as the 'no serving' case,
        we put the currently existing inbound connection as the alternate
        location, and the NOT_SERVING const as the 'location', returning True.
        If the string does not have the required format, will return False,
        otherwise self.hostname, self.port are
        updated for future `peer_location` calls, and True is returned.
        """
        if location_string == NOT_SERVING_ONION_HOSTNAME:
            self.set_alternate_location(location_tuple_to_str(
                (self.hostname, self.port)))
            self.hostname = NOT_SERVING_ONION_HOSTNAME
            self.port = -1
            return True
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
        if self.hostname == NOT_SERVING_ONION_HOSTNAME:
            # special case for non-reachable peers, which can include
            # self_as_peer: we just return this string constant
            return NOT_SERVING_ONION_HOSTNAME
        # in every other case we need a sensible port/host combo:
        assert (self.port > 0 and self.hostname)
        return location_tuple_to_str((self.hostname, self.port))

    def send(self, message: OnionCustomMessage) -> bool:
        """ If the message can be sent on either an inbound or
        outbound connection, True is returned, else False.
        """
        if not self.factory:
            # we try to send via the overall message channel serving
            # protocol, i.e. we assume the connection was made inbound:
            return self.messagechannel.proto_factory.send(message,
                        self.alternate_location)
        return self.factory.send(message)

    def receive_message(self, message: OnionCustomMessage) -> None:
        self.messagechannel.receive_msg(message, self.peer_location())

    def notify_message_unsendable(self):
        """ Triggered by a failure to send a message on the network,
        by the encapsulated ClientFactory. Just used to notify calling
        code; no action is triggered.
        """
        name = "directory" if self.directory else "peer"
        log.warn("Failure to send message to {}: {}.".format(
            name, self.peer_location()))

    def connect(self) -> None:
        """ This method is called to connect, over Tor, to the remote
        peer at the given onion host/port.
        """
        if self.connecting:
            return
        self.connecting = True
        if self._status in [PEER_STATUS_HANDSHAKED, PEER_STATUS_CONNECTED]:
            return
        if not (self.hostname and self.port > 0):
            raise OnionPeerConnectionError(
                "Cannot connect without host, port info")

        self.factory = OnionClientFactory(self.receive_message,
            self.register_connection, self.register_disconnection,
            self.notify_message_unsendable, self.directory, self.messagechannel)
        if testing_mode:
            log.debug("{} is making a tcp connection to {}, {}, {},".format(
                self.messagechannel.self_as_peer.peer_location(), self.hostname,
                self.port, self.factory))
            self.tcp_connector = reactor.connectTCP(self.hostname, self.port,
                                                    self.factory)
        else:
            # non-default timeout; needs to be much lower than our
            # 'wait at least a minute for the IRC connections to come up',
            # which is used for *all* message channels, together.
            torEndpoint = TCP4ClientEndpoint(reactor, self.socks5_host,
                                             self.socks5_port,
                                             timeout=CONNECT_TO_ONION_TIMEOUT)
            onionEndpoint = TorSocksEndpoint(torEndpoint, self.hostname,
                                             self.port)
            self.reconnecting_service = ClientService(onionEndpoint, self.factory)
            # if we want to actually do something about an unreachable host,
            # we have to force t.a.i.ClientService to give up after the timeout
            d = self.reconnecting_service.whenConnected(failAfterFailures=1)
            d.addCallbacks(self.respond_to_connection_success,
                           self.respond_to_connection_failure)
            self.reconnecting_service.startService()

    def respond_to_connection_success(self, proto) -> None:
        self.connecting = False

    def respond_to_connection_failure(self, failure) -> None:
        self.connecting = False
        # the error will be one of these if we just fail
        # to connect to the other side.
        failure.trap(HostUnreachableError, SocksError, GeneralServerFailureError)
        comment = "" if self.directory else "; giving up."
        log.info(f"Failed to connect to peer {self.peer_location()}{comment}")
        self.reconnecting_service.stopService()

    def register_connection(self) -> None:
        self.messagechannel.register_connection(self.peer_location(),
                                                direction=1)

    def register_disconnection(self) -> None:
        # for non-directory peers, just stop
        self.reconnecting_service.stopService()
        self.messagechannel.register_disconnection(self.peer_location())

    def try_to_connect(self) -> None:
        """ This method wraps OnionPeer.connect and accepts
        any error if that fails.
        """
        try:
            self.connect()
        except OnionPeerConnectionError as e:
            # Note that this will happen naturally for non-serving peers.
            # TODO remove message or change it.
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
        if self.factory:
            d = self.reconnecting_service.stopService()
            d.addCallback(self.complete_disconnection)
        else:
            self.messagechannel.proto_factory.disconnect_inbound_peer(
                self.alternate_location)

    def complete_disconnection(self, r) -> None:
        log.debug("Disconnected from peer: {}".format(self.peer_location()))
        self.update_status(PEER_STATUS_DISCONNECTED)
        self.factory = None

class OnionPeerPassive(OnionPeer):
    """ a type of remote peer that we are
        not interested in connecting outwards to.
    """
    def try_to_connect(self) -> None:
        pass

class OnionDirectoryPeer(OnionPeer):
    delay = 4.0

    def try_to_connect(self) -> None:
        # Delay deliberately expands out to very
        # long times as yg-s tend to be very long
        # running bots:
        # We will only expand delay 20 times max
        # (4 * 1.5^19 = 8867.3)
        if self.delay < 8868:
            self.delay *= 1.5
        # randomize by a few seconds to minimize bursty-ness locally
        jitter = random.randint(-1, 5)
        log.info(f"Going to reattempt connection to {self.peer_location()} in "
                 f"{self.delay + jitter} seconds.")
        reactor.callLater(self.delay + jitter, self.connect)

    def register_connection(self) -> None:
        self.messagechannel.update_directory_map(self, connected=True)
        super().register_connection()

    def register_disconnection(self) -> None:
        self.messagechannel.update_directory_map(self, connected=False)
        super().register_disconnection()
        # for directory peers, we persist in trying to establish
        # a connection, but with backoff:
        self.try_to_connect()

    def respond_to_connection_failure(self, failure) -> None:
        super().respond_to_connection_failure(failure)
        # same logic as for register_disconnection
        self.try_to_connect()

class OnionMessageChannel(MessageChannel):
    """ Sends messages to other nodes of the same type over Tor
    via SOCKS5.
    *Optionally*: Receives messages via a Torv3 hidden/onion service.
    If no onion service, it means we only have connections outbound
    to other onion services (directory nodes first, others if and
    when they send us a privmsg.).
    Uses one or more configured "directory nodes" (which could be us)
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
        self.btc_network = configdata["btcnet"]
        # receives notification that we are shutting down
        self.give_up = False
        # for backwards compat: make sure MessageChannel log can refer to
        # this in dynamic switch message:
        self.serverport = self.hostid
        self.tor_control_host = configdata["tor_control_host"]
        self.tor_control_port = configdata["tor_control_port"]
        self.tor_control_password = configdata["tor_control_password"]
        self.onion_serving_host = configdata["onion_serving_host"]
        self.onion_serving = configdata["serving"]
        if self.onion_serving:
            self.onion_serving_port = configdata["onion_serving_port"]
            self.hidden_service_dir = configdata["hidden_service_dir"]
        # client side config:
        self.socks5_host = configdata["socks5_host"]
        self.socks5_port = configdata["socks5_port"]
        # passive configuration is for bots who never need/want to connect
        # to peers (apart from directories)
        self.passive = False
        if "passive" in configdata:
            self.passive = configdata["passive"]
        # we use the setting in the config sent over from
        # the client, to decide whether to set up our connections
        # over localhost (if testing), without Tor:
        set_testing_mode(configdata)
        # keep track of peers. the list will be instances
        # of OnionPeer:
        self.peers = set()
        for dn in [x.strip() for x in configdata["directory_nodes"].split(",")]:
            # note we don't use a nick for directories:
            try:
                self.peers.add(OnionDirectoryPeer.from_location_string(
                    self, dn, self.socks5_host, self.socks5_port,
                    directory=True, handshake_callback=self.handshake_as_client))
            except InvalidLocationStringError as e:
                log.error("Failed to load directory nodes: {}".format(repr(e)))
                stop_reactor()
                return
        # we can direct messages via the protocol factory, which
        # will index protocol connections by peer location:
        self.proto_factory = OnionLineProtocolFactory(self)
        if self.onion_serving:
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
                                          virtual_port=ONION_VIRTUAL_PORT,
                                          shutdown_callback=self.shutdown_callback,
                                          tor_control_password=self.tor_control_password,
                                          hidden_service_dir=self.hidden_service_dir)
                # this call will start bringing up the HS; when it's finished,
                # it will fire the `onion_hostname_callback`, or if it fails,
                # it'll fire the `setup_error_callback`.
                self.hs.start_tor()

                # This will serve as our unique identifier, indicating
                # that we are ready to communicate (in both directions) over Tor.
                self.onion_hostname = None
        else:
            # dummy 'hostname' to indicate we can start running immediately:
            self.onion_hostname = NOT_SERVING_ONION_HOSTNAME

        # intended to represent the special case of 'we are the
        # only directory node known', however for now dns don't interact
        # so this has no role. TODO probably remove it.
        self.genesis_node = False

        # waiting loop for all directories to have
        # connected (note we could use a deferred but
        # the rpc connection calls are not using twisted)
        self.wait_for_directories_loop = None

        # this dict plays the same role as `active_channels` in `MessageChannelCollection`.
        # it has structure {nick1: {}, nick2: {}, ...} where the inner dicts are:
        # {OnionDirectoryPeer1: bool, OnionDirectoryPeer2: bool, ...}.
        # Entries get updated with changing connection status of directories,
        # allowing us to decide where to send each message we want to send when we have no
        # direct connection.
        self.active_directories = {}

    def info_callback(self, msg: str) -> None:
        log.info(msg)

    def setup_error_callback(self, msg: str) -> None:
        log.error(msg)

    def shutdown_callback(self, msg: str) -> None:
        log.info("in shutdown callback: {}".format(msg))

    def onion_hostname_callback(self, hostname: str) -> None:
        """ This entrypoint marks the start of the OnionMessageChannel
        running, since we need this unique identifier as our name
        before we can start working (we need to compare it with the
        configured directory nodes).
        """
        log.info("setting onion hostname to : {}".format(hostname))
        self.onion_hostname = hostname

# ABC implementation section
    def run(self) -> None:
        self.hs_up_loop = task.LoopingCall(self.check_onion_hostname)
        self.hs_up_loop.start(0.5)

    def shutdown(self) -> None:
        self.give_up = True
        for p in self.peers:
            if p.reconnecting_service:
                p.reconnecting_service.stopService()

    def get_pubmsg(self, msg:str, source_nick:str ="") -> str:
        """ Converts a message into the known format for
        pubmsgs; if we are not sending this (because we
        are a directory, forwarding it), `source_nick` must be set.
        Note that pubmsg does NOT prefix the *message* with COMMAND_PREFIX.
        """
        nick = source_nick if source_nick else self.nick
        return nick + COMMAND_PREFIX + "PUBLIC" + msg
 
    def get_privmsg(self, nick: str, cmd: str, message: str,
                    source_nick=None) -> str:
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
        dps = self.get_directory_peers()
        msg = OnionCustomMessage(self.get_pubmsg(msg),
                                JM_MESSAGE_TYPES["pubmsg"])
        for dp in dps:
            # currently a directory node can send its own
            # pubmsgs (act as maker or taker); this will
            # probably be removed but is useful in testing:
            if dp == self.self_as_peer:
                self.receive_msg(msg, "00")
            else:
                self._send(dp, msg)

    def should_try_to_connect(self, peer: OnionPeer) -> bool:
        if not peer:
            return False
        if peer.peer_location() == NOT_SERVING_ONION_HOSTNAME:
            return False
        if peer.directory:
            return False
        if peer == self.self_as_peer:
            return False
        if peer.status() in [PEER_STATUS_CONNECTED, PEER_STATUS_HANDSHAKED]:
            return False
        return True

    def _privmsg(self, nick: str, cmd: str, msg:str) -> None:
        # in certain test scenarios the directory may try to transfer
        # commitments to itself:
        if nick == self.nick:
            log.debug("Not sending message to ourselves: {}, {}, {}".format(
                nick, cmd, msg))
            return
        encoded_privmsg = OnionCustomMessage(self.get_privmsg(nick, cmd, msg),
                            JM_MESSAGE_TYPES["privmsg"])
        peer_exists = self.get_peer_by_nick(nick, conn_only=False)
        peer_sendable = self.get_peer_by_nick(nick)
        # opportunistically connect to peers that have talked to us
        # (evidenced by the peer existing, which must be because we got
        # a `peerlist` message for it), and that we want to talk to
        # (evidenced by the call to this function)
        if self.should_try_to_connect(peer_exists):
            reactor.callLater(0.0, peer_exists.try_to_connect)
        if not peer_sendable:
            # If we are trying to message a peer via their nick, we
            # may not yet have a connection; then we just
            # forward via directory nodes.
            log.debug("Privmsg peer: {} but don't have peerid; "
                     "sending via directory.".format(nick))
            try:
                peer_sendable = self.get_directory_for_nick(nick)
            except OnionDirectoryPeerNotFound:
                log.warn("Failed to send privmsg because no "
                "directory peer is connected.")
                return
        self._send(peer_sendable, encoded_privmsg)

    def _announce_orders(self, offerlist: list) -> None:
        for offer in offerlist:
            self._pubmsg(offer)

# End ABC implementation section

    def check_onion_hostname(self) -> None:
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

    def get_my_location_tuple(self) -> Tuple[str, int]:
        if self.onion_hostname == NOT_SERVING_ONION_HOSTNAME:
            return (self.onion_hostname, -1)
        elif testing_mode:
            return (self.onion_hostname, self.onion_serving_port)
        else:
            return (self.onion_hostname, ONION_VIRTUAL_PORT)

    def get_our_peer_info(self) -> None:
        """ Create a special OnionPeer object,
        outside of our peerlist, to refer to ourselves.
        """
        dps = self.get_directory_peers()
        self_dir = False
        # only for publicly exposed onion does the 'virtual port' exist;
        # for local tests we always connect to an actual machine port:
        my_location_tuple = self.get_my_location_tuple()
        my_location_str = location_tuple_to_str(my_location_tuple)
        if [my_location_str] == [d.peer_location() for d in dps]:
            log.info("This is the genesis node: {}".format(self.onion_hostname))
            self.genesis_node = True
            self_dir = True
        elif my_location_str in dps:
            # Here we are just one of many directory nodes,
            # which should be fine, we should just be careful
            # to not query ourselves.
            self_dir = True
        self.self_as_peer = OnionPeer(self, self.socks5_host, self.socks5_port,
                                      my_location_tuple,
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
        self.directory_wait_counter = 0
        self.wait_for_directories_loop = task.LoopingCall(
            self.wait_for_directories)
        self.wait_for_directories_loop.start(2.0)

    def handshake_as_client(self, peer: OnionPeer) -> None:
        assert peer.status() == PEER_STATUS_CONNECTED
        if self.self_as_peer.directory:
            log.debug("Not sending client handshake to {} because we "
                      "are directory.".format(peer.peer_location()))
            return
        our_hs = copy.deepcopy(client_handshake_json)
        our_hs["location-string"] = self.self_as_peer.peer_location()
        our_hs["nick"] = self.nick
        our_hs["network"] = self.btc_network
        our_hs_json = json.dumps(our_hs)
        log.info("Sending this handshake: {} to peer {}".format(
            our_hs_json, peer.peer_location()))
        self._send(peer, OnionCustomMessage(our_hs_json,
                                    CONTROL_MESSAGE_TYPES["handshake"]))

    def handshake_as_directory(self, peer: OnionPeer, our_hs: dict) -> None:
        assert peer.status() == PEER_STATUS_CONNECTED
        our_hs["network"] = self.btc_network
        our_hs_json = json.dumps(our_hs)
        log.info("Sending this handshake as directory: {}".format(
            our_hs_json))
        self._send(peer, OnionCustomMessage(our_hs_json,
                    CONTROL_MESSAGE_TYPES["dn-handshake"]))

    def get_directory_peers(self) -> list:
        return [p for p in self.peers if p.directory is True]

    def get_peer_by_nick(self, nick:str, conn_only:bool=True) -> Union[OnionPeer, None]:
        """ Return an OnionPeer object matching the given Joinmarket
        nick; if `conn_only` is True, we restrict to only those peers
        in state PEER_STATUS_HANDSHAKED, else we allow any peer.
        If no such peer can be found, return None.
        """
        plist = self.get_all_connected_peers() if conn_only else self.peers
        for p in plist:
            if p.nick == nick:
                return p

    def _send(self, peer: OnionPeer, message: OnionCustomMessage) -> bool:
        try:
            return peer.send(message)
        except Exception as e:
            # This can happen when a peer disconnects, depending
            # on the timing:
            log.warn("Failed to send message to: {}, error: {}".format(
                peer.peer_location(), repr(e)))
            return False

    def receive_msg(self, message: OnionCustomMessage, peer_location: str) -> None:
        """ Messages from peers and also connection related control
        messages. These messages either come via OnionPeer or via
        the main OnionLineProtocolFactory instance that handles all
        inbound connections.
        """
        if self.self_as_peer.directory:
            # TODO remove, useful while testing
            log.debug("received message as directory: {}".format(message.encode()))
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
        if msgtype not in JM_MESSAGE_TYPES.values():
            log.debug("Invalid message type, ignoring: {}".format(msgtype))
            return

        # real JM message; should be: from_nick, to_nick, cmd, message
        try:
            nicks_msgs = msgval.split(COMMAND_PREFIX)
            from_nick, to_nick = nicks_msgs[:2]
            msg = COMMAND_PREFIX + COMMAND_PREFIX.join(nicks_msgs[2:])
            if to_nick == "PUBLIC":
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
            log.debug("Invalid Joinmarket message: {}, error was: {}".format(
                msgval, repr(e)))
        # add the nick to the directories map, whether pubmsg or privmsg, but
        # only if it passed the above syntax Exception catch:
        if peer.directory and not self.self_as_peer.directory:
            if from_nick not in self.active_directories:
                self.active_directories[from_nick] = {}
            self.active_directories[from_nick][peer] = True

    def update_directory_map(self, p: OnionDirectoryPeer, connected: bool) -> None:
        nicks = []
        for nick in self.active_directories:
            if p in self.active_directories[nick]:
                nicks.append(nick)
        for nick in nicks:
            self.active_directories[nick][p] = connected

    def get_directory_for_nick(self, nick: str) -> OnionDirectoryPeer:
        if nick not in self.active_directories:
            raise OnionDirectoryPeerNotFound
        adn = self.active_directories[nick]
        if len(adn) == 0:
            raise OnionDirectoryPeerNotFound
        candidates = [x for x in list(adn) if adn[x] is True]
        if len(candidates) == 0:
            raise OnionDirectoryPeerNotFound
        return random.choice(candidates)

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
        peer = self.get_peer_by_nick(nick)
        if not peer:
            log.debug("We were asked to send a message from {} to {}, "
                      "but {} is not connected.".format(from_nick, nick, nick))
            return
        # The `message` passed in has format COMMAND_PREFIX||command||" "||msg
        # we need to parse out cmd, message for sending.
        # second argument for split means only one split allowed.
        cmdsmsgs = message.split(COMMAND_PREFIX, 1)[1]
        cmdmsglist = cmdsmsgs.split(" ")
        cmd = cmdmsglist[0]
        msg = " ".join(cmdmsglist[1:])
        privmsg = self.get_privmsg(nick, cmd, msg, source_nick=from_nick)
        encoded_msg = OnionCustomMessage(privmsg,
                        JM_MESSAGE_TYPES["privmsg"])
        self._send(peer, encoded_msg)
        # If possible, we forward the from-nick's network location
        # to the to-nick peer, so they can just talk directly next time.
        peer_from = self.get_peer_by_nick(from_nick)
        if not peer_from:
            return
        self.send_peers(peer, peer_filter=[peer_from])

    def on_nick_leave_directory(self, nick: str, dir_peer: OnionPeer) -> None:
        """ This is called in response to a disconnection control
        message from a directory, telling us that a certain nick has left.
        We update this connection status in the active_directories map,
        and fire the MessageChannel.on_nick_leave when we see all the
        connections are lost.
        Note that `on_nick_leave` can be triggered in two ways; both here,
        and also via `self.register_disconnection`, which occurs for peers
        to whom we are directly connected. Calling it multiple times is not
        harmful, but remember that the on_nick_leave event only bubbles up
        above the message channel layer once *all* message channels trigger
        on_nick_leave (in case we are using another message channel as well
        as this one, like IRC).
        """
        if not nick in self.active_directories:
            return
        if not dir_peer in self.active_directories[nick]:
            log.debug("Directory {} is telling us that {} has left, but we "
                      "didn't know about them. Ignoring.".format(
                         dir_peer.peer_location(), nick))
            return
        log.debug("Directory {} has lost connection to: {}".format(
            dir_peer.peer_location(), nick))
        self.active_directories[nick][dir_peer] = False
        if not any(self.active_directories[nick].values()):
            self.on_nick_leave(nick, self)

    def process_control_message(self, peerid: str, msgtype: int,
                                msgval: str) -> bool:
        """ Triggered by a directory node feeding us
        peers, or by a connect/disconnect hook; this is our housekeeping
        to try to create, and keep track of, useful connections.
        The returned boolean indicates whether we succeeded in processing
        the message or whether it must be analyzed again (note e.g. that
        we return True for a rejected message!)
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
            # a directory node can send this any time.
            # These messages can only be accepted from directory peers
            # (which we have configured ourselves):
            peer = self.get_peer_by_id(peerid)
            if not peer or not peer.directory:
                return True
            try:
                peerlist = msgval.split(",")
                for peer_in_list in peerlist:
                    # directories should send us peerstrings that include
                    # nick;host:port;D where "D" indicates that the directory
                    # is signalling this peer as having left. Otherwise, without
                    # the third field, we treat it as a "join" event.
                    try:
                        nick, hostport, disconnect_code = peer_in_list.split(
                            NICK_PEERLOCATOR_SEPARATOR)
                        if disconnect_code != "D":
                            continue
                        self.on_nick_leave_directory(nick, peer)
                        continue
                    except ValueError:
                        # just means this message is not of the 'disconnect' type
                        pass
                    # defaults mean we just add the peer, not
                    # add or alter its connection status:
                    self.add_peer(peer_in_list, with_nick=True)
            except Exception as e:
                log.debug("Incorrectly formatted peer list: {}, "
                      "ignoring, {}".format(msgval, e))
            # returning True whether raised or not - see docstring
            return True
        elif msgtype == CONTROL_MESSAGE_TYPES["getpeerlist"]:
            log.warn("getpeerlist request received, currently not supported.")
            return True
        elif msgtype == CONTROL_MESSAGE_TYPES["handshake"]:
            # sent by non-directory peers on startup, also to
            # other non-dn peers during tx flow
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
            if self.self_as_peer.directory:
                # We propagate the control message as a "peerlist" with
                # the "D" flag:
                disconnected_peer = self.get_peer_by_id(msgval)
                for p in self.get_connected_nondirectory_peers():
                    self.send_peers(p, peer_filter=[disconnected_peer],
                                    disconnect=True)
            # bubble up the disconnection event to the abstract
            # message channel logic:
            if self.on_nick_leave:
                p = self.get_peer_by_id(msgval)
                if p and p.nick:
                    reactor.callLater(0.0, self.on_nick_leave, p.nick, self)
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
                net = handshake_json["network"]
                assert isinstance(proto_max, int)
                assert isinstance(proto_min, int)
                assert isinstance(features, dict)
                assert isinstance(nick, str)
                assert isinstance(net, str)
            except Exception as e:
                log.warn("Invalid handshake message from: {},"
                " exception: {}, message: {},ignoring".format(
                    peerid, repr(e), message))
                return
            # currently we are not using any features, but the intention
            # is forwards compatibility, so we don't check its contents
            # at all.
            if not accepted:
                log.warn("Directory: {} rejected our handshake.".format(peerid))
                # explicitly choose to disconnect (if other side already did,
                # this is no-op).
                peer.disconnect()
                return
            if not (app_name == JM_APP_NAME and is_directory and JM_VERSION \
                    <= proto_max and JM_VERSION >= proto_min and accepted):
                log.warn("Handshake from directory is incompatible or "
                         "rejected: {}".format(handshake_json))
                peer.disconnect()
                return
            if not net == self.btc_network:
                log.warn("Handshake from directory is on an incompatible "
                         "network: {}".format(net))
                return
            # We received a valid, accepting dn-handshake. Update the peer.
            peer.update_status(PEER_STATUS_HANDSHAKED)
            peer.set_nick(nick)
        else:
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
                net = handshake_json["network"]
                assert isinstance(proto_ver, int)
                assert isinstance(features, dict)
                assert isinstance(nick, str)
                assert isinstance(net, str)
            except Exception as e:
                log.warn("(not dn) Invalid handshake message from: {}, "
                         "exception: {}, message: {}, ignoring".format(
                             peerid, repr(e), message))
                # just ignore, since a syntax failure could lead to a crash
                return
            if not (app_name == JM_APP_NAME and proto_ver == JM_VERSION \
                    and not is_directory):
                log.warn("Invalid handshake name/version data: {}, from peer: "
                         "{}, rejecting.".format(message, peerid))
                accepted = False
            if not net == self.btc_network:
                log.warn("Handshake from peer is on an incompatible "
                         "network: {}".format(net))
                accepted = False
            # If accepted, we should update the peer to have the full
            # location which in general will not yet be present, so as to
            # allow publishing their location via `getpeerlist`. Note
            # that if the peer declares itself as not serving, we do
            # nothing here:
            if not peer.set_location(full_location_string):
                accepted = False
            if peerid != full_location_string:
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
            if x.peer_location() == p and p != NOT_SERVING_ONION_HOSTNAME:
                return x
            # non-reachable peers can only match on their inbound
            # connection port
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
                overwrite_connection: bool=False, with_nick=False) -> Union[OnionPeer, None]:
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
                # old code does not recognize messages with "D" as a third
                # field; they will swallow the message here, ignoring
                # the message as invalid because it has three fields
                # instead of two.
                # (We still use the catch-all `Exception`, for the usual reason
                # of not wanting to make assumptions about external input).
                log.debug("Received invalid peer identifier string: {}, {}".format(
                    peerdata, e))
                return
        else:
            peer = peerdata

        cls = OnionPeerPassive if self.passive else OnionPeer
        # assumed that it's passing a full string
        try:
            temp_p = cls.from_location_string(self, peer,
                        self.socks5_host, self.socks5_port,
                        handshake_callback=self.handshake_as_client)
        except Exception as e:
            # There are currently a few ways the location
            # parsing and Peer object construction can fail;
            # TODO specify exception types.
            log.warn("Failed to add peer: {}, exception: {}".format(peer, repr(e)))
            return
        if not self.get_peer_by_id(temp_p.peer_location()):
            self.peers.add(temp_p)
            if connection:
                log.info("Updating status of peer: {} to connected.".format(temp_p.peer_location()))
                temp_p.update_status(PEER_STATUS_CONNECTED)
            else:
                if overwrite_connection:
                    temp_p.update_status(PEER_STATUS_DISCONNECTED)
            if with_nick:
                temp_p.set_nick(nick)
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

    def get_connected_nondirectory_peers(self) -> List[OnionPeer]:
        return [p for p in self.peers if (not p.directory) and p.status() == \
                PEER_STATUS_HANDSHAKED]

    def wait_for_directories(self) -> None:
        # Notice this is checking for *handshaked* dps;
        # the handshake will have been initiated once a
        # connection was seen.
        # Note also that this is *only* called on startup,
        # so we are guaranteed to have only directory peers.
        if len(self.get_connected_directory_peers()) < len(self.peers):
            self.directory_wait_counter += 1
            # Keep trying until the timeout.
            # Note RHS need not be an integer.
            if self.directory_wait_counter < CONNECT_TO_ONION_TIMEOUT/2 + 1:
                return
        if len(self.get_connected_directory_peers()) == 0:
            # at least one handshake must have succeeded, for us
            # to continue.
            log.error("We failed to connect and handshake with "
                      "ANY directories; onion messaging is not functioning.")
            self.wait_for_directories_loop.stop()
            # notice that in this failure mode, we do *not* shut down
            # the entire process, as this is only a failure to connect
            # to one message channel, and others (e.g. IRC) may be working.
            return
        # This is what triggers the start of taker/maker workflows.
        # Note that even if the preceding (max) 50 seconds failed to
        # connect all our configured dps, we will keep trying and they
        # can still be used.
        if not self.on_welcome_sent:
            self.on_welcome(self)
            self.on_welcome_sent = True
            self.wait_for_directories_loop.stop()

    """ CONTROL MESSAGES SENT BY US
    """
    def send_peers(self, requesting_peer: OnionPeer,
                   peer_filter: List[OnionPeer], disconnect: bool=False) -> None:
        """ This message is sent by directory peers, currently
        only when a privmsg has to be forwarded to them, or a peer has
        disconnected. It could also be sent by directories to non-directory
        peers according to some other algorithm.
        The message is sent *to* `requesting_peer`.
        If `peer_filter` is specified, only those peers will be sent.
        If `disconnect` is True, we append "D" to every entry, which
        indicates to the receiver that the peer being sent has left,
        not that that peer is available.
        The peerlist message should have this format:
        (1) entries comma separated
        (2) each entry a two- or three- element list, separated by NICK_PEERLOCATOR_SEPARATOR,
            [nick, host:port] or same with ["D"] added at the end.
        For the case disconnect=False, peers that do not have a reachable location are not sent.
        """
        if not requesting_peer.status() == PEER_STATUS_HANDSHAKED:
            raise OnionPeerConnectionError(
                "Cannot send peer list to unhandshaked peer")
        peerlist = set()
        peer_filter_exists = len(peer_filter) > 0
        if disconnect is False:
            for p in self.get_connected_nondirectory_peers():
                # don't send a peer to itself
                if p == requesting_peer:
                    continue
                if peer_filter_exists and p not in peer_filter:
                    continue
                if p.status() != PEER_STATUS_HANDSHAKED:
                    # don't advertise what is not online.
                    continue
                # peers that haven't sent their nick yet are not
                # privmsg-reachable; don't send them
                if p.nick == "":
                    continue
                if p.peer_location() == NOT_SERVING_ONION_HOSTNAME:
                    # if a connection has no reachable destination,
                    # don't forward it
                    continue
                peerlist.add(p.get_nick_peerlocation_ser())
        else:
            # since the peer may already be removed from self.peers,
            # we don't limit except by filter:
            for p in peer_filter:
                try:
                    peerlist.add(p.get_nick_peerlocation_ser(
                        ) + NICK_PEERLOCATOR_SEPARATOR + "D")
                except OnionPeerError:
                    pass
        # For testing: dns won't usually participate:
        peerlist.add(self.self_as_peer.get_nick_peerlocation_ser())
        # don't send an empty set (will not be possible unless
        # above dn add is removed).
        if len(peerlist) == 0:
            return
        self._send(requesting_peer, OnionCustomMessage(",".join(
            peerlist), CONTROL_MESSAGE_TYPES["peerlist"]))
