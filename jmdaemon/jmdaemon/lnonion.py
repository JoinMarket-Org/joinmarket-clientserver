from jmdaemon.message_channel import MessageChannel
from jmdaemon.protocol import COMMAND_PREFIX, JM_VERSION
from jmbase import get_log, bintohex, hextobin, JM_APP_NAME
from pyln.client import LightningRpc, RpcError
import json
import copy
from typing import Callable, Union
from twisted.internet import reactor, task
from twisted.internet.protocol import ServerFactory
from twisted.protocols.basic import LineReceiver
log = get_log()

"""
Messaging protocol (which wraps the underlying Joinmarket
messaging protocol) used here is documented in:
Joinmarket-Docs/lightning-messaging.md
"""

LOCAL_CONTROL_MESSAGE_TYPES = {"connect": 785, "disconnect": 787, "connect-in": 797}
CONTROL_MESSAGE_TYPES = {"peerlist": 789, "getpeerlist": 791,
                         "handshake": 793, "dn-handshake": 795}
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


""" this passthrough protocol allows
    the joinmarket daemon to receive messages
    from some outside process, instead of from
    a client connection created in this process.
    We use a LineReceiver as the app-layer distinguisher
    of individual messages.
"""
class TCPPassThroughProtocol(LineReceiver):
    def __init__(self, factory):
        self.factory = factory

    def connectionMade(self):
        print("connection made in lnonion passthrough")

    def connectionLost(self, reason):
        print("connection lost in lnonion passthrough")

    def lineReceived(self, line):
        """ Data passed over this TCP socket
        is assumed to be JSON encoded, only.
        """
        try:
            data = line.decode("utf-8")
        except UnicodeDecodeError:
            log.warn("Received invalid data over the wire, ignoring.")
            return
        if len(self.factory.listeners) == 0:
            log.msg("WARNING! We received: {} but there "
                    "were no listeners.".format(data))
        for listener in self.factory.listeners:
            try:
                listener.receive_msg(json.loads(data))
            except json.decoder.JSONDecodeError as e:
                log.warn("Received invalid data: {}, {}. ignoring.".format(
                    data, repr(e)))


class TCPPassThroughFactory(ServerFactory):
    # the protocol created here is a singleton,
    # global to the joinmarket(d) process;
    # we interact with it from multiple Joinmarket
    # protocol instantiations by adding listeners
    # (because all it does is listen).
    # Listeners are added to the factory, not the
    # protocol instance as that won't exist until
    # someone connects.
    def __init__(self):
        # listeners will all receive
        # all messages; they must have
        # a `receive_msg` method that
        # processes messages in JSON.
        self.listeners = []

    def buildProtocol(self, addr):
        self.p = TCPPassThroughProtocol(self)
        return self.p

    def add_tcp_listener(self, listener):
        self.listeners.append(listener)

    def remove_tcp_listener(self, listener):
        try:
            self.listeners.remove(listener)
        except ValueError:
            pass

class LNOnionPeerError(Exception):
    pass

class LNOnionPeerIDError(LNOnionPeerError):
    pass

class LNOnionPeerDirectoryWithoutHostError(LNOnionPeerError):
    pass

class LNOnionPeerConnectionError(LNOnionPeerError):
    pass

class LNCustomMsgFormatError(Exception):
    pass

class LNOnionPeer(object):

    def __init__(self, peerid: str, hostname: str=None,
                 port: int=-1, directory: bool=False,
                 nick: str="", handshake_callback: Callable=None):
        if not len(peerid) == 66:
            # TODO: check valid pubkey without jmbitcoin?
            raise LNOnionPeerIDError()
        self.peerid = peerid
        self.nick = nick
        self.hostname = hostname
        self.port = port
        if directory and not (self.hostname):
            raise LNOnionPeerDirectoryWithoutHostError()
        self.directory = directory
        self._status = PEER_STATUS_UNCONNECTED
        #A function to be called to initiate a handshake;
        # it should take a single argument, an LNOnionPeer object,
        #and return None.
        self.handshake_callback = handshake_callback

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
            log.info("We are calling the handshake callback as client.")
            self.handshake_callback(self)

    def status(self) -> int:
        """ Simple getter function for the wrapped _status:
        """
        return self._status

    def set_nick(self, nick: str) -> None:
        self.nick = nick

    def get_nick_peerlocation_ser(self) -> str:
        if not self.nick:
            raise LNOnionPeerError("Cannot serialize "
                "identifier string without nick.")
        return self.nick + NICK_PEERLOCATOR_SEPARATOR + \
               self.peer_location_or_id()

    @classmethod
    def from_location_string(cls, locstr: str,
                directory: bool=False,
                handshake_callback: Callable=None) -> 'LNOnionPeer':
        peerid, hostport = locstr.split("@")
        host, port = hostport.split(":")
        port = int(port)
        return cls(peerid, host, port, directory,
                   handshake_callback=handshake_callback)

    def set_host_port(self, hostname: str, port: int) -> None:
        """ If the connection info is discovered
        after this peer was already added to our list,
        we can set it with this method.
        """
        self.hostname = hostname
        self.port = port

    def peer_location_or_id(self) -> str:
        try:
            return self.peer_location()
        except AssertionError:
            return self.peerid

    def set_location(self, full_location_string: str) -> bool:
        """ Allows setting location from an unchecked
        input string argument; if the string does not have
        the required format, or its peerid does not match this peer,
        will return False, otherwise self.hostname, self.port are
        updated for future `peer_location` calls, and True is returned.
        """
        try:
            peerid, hostport = full_location_string.split("@")
            assert peerid == self.peerid
            host, port = hostport.split(":")
            portint = int(port)
            assert portint > 0
        except Exception as e:
            log.debug("Failed to update host and port of this peer ({}), "
                      "error: {}".format(self.peerid, repr(e)))
            return False
        self.hostname = host
        self.port = portint
        return True

    def peer_location(self) -> str:
        assert (self.hostname and self.port > 0)
        return self.peerid + "@" + self.hostname + ":" + str(self.port)

    def connect(self, rpcclient: LightningRpc) -> None:
        """ This method is called to fire the RPC `connect`
        call to the LN peer associated with this instance.
        """
        if self._status in [PEER_STATUS_HANDSHAKED, PEER_STATUS_CONNECTED]:
            return
        if not (self.hostname and self.port > 0):
            raise LNOnionPeerConnectionError(
                "Cannot connect without host, port info")
        try:
            rpcclient.call("connect", [self.peer_location()])
        except RpcError as e:
            raise LNOnionPeerConnectionError(
                "Connection to: {}failed with error: {}".format(
                    self.peer_location(), repr(e)))

    def try_to_connect(self, rpcclient: LightningRpc) -> None:
        """ This method wraps LNOnionPeer.connect and accepts
        any error if that fails.
        """
        try:
            self.connect(rpcclient=rpcclient)
        except LNOnionPeerConnectionError as e:
            log.debug("Tried to connect but failed: {}".format(repr(e)))
        except Exception as e:
            log.warn("Got unexpected exception in connect attempt: {}".format(
                repr(e)))

    def disconnect(self, rpcclient: LightningRpc) -> None:
        if self._status in [PEER_STATUS_UNCONNECTED, PEER_STATUS_DISCONNECTED]:
            return
        if not (self.hostname and self.port > 0):
            raise LNOnionPeerConnectionError(
                "Cannot disconnect without host, port info")
        try:
            rpcclient.call("disconnect", [self.peer_location()])
        except RpcError as e:
            raise LNOnionPeerConnectionError("Disconnection from {} failed "
                "with error: {}".format(self.peer_location(), repr(e)))
        self.update_status(PEER_STATUS_DISCONNECTED)

class LNOnionDirectoryPeer(LNOnionPeer):
    delay = 4.0
    def try_to_connect(self, rpcclient: LightningRpc) -> None:
        # Delay deliberately expands out to very
        # long times as yg-s tend to be very long
        # running bots:
        self.delay *= 1.5
        if self.delay > 10000:
            log.warn("Cannot connect to directory node peer: {} "
                     "after 20 attempts, giving up.".format(self.peerid))
            return
        try:
            self.connect(rpcclient)
        except LNOnionPeerConnectionError:
            reactor.callLater(self.delay, self.try_to_connect)

class LNCustomMessage(object):
    """ Encapsulates the messages passed over the wire
    to and from c-lightning using the `sendcustommsg` rpc.
    """
    def __init__(self, text: str, msgtype: int):
        self.text = text
        self.msgtype = msgtype

    def encode(self) -> str:
        bintext = self.text.encode("utf-8")
        hextext = bintohex(bintext)
        hextype = "%0.4x" % self.msgtype
        self.encoded = hextype + hextext
        return self.encoded

    @classmethod
    def from_sendcustommsg_decode(cls, msg:
                                     str) -> 'LNCustomMessage':
        """ This is ~ the reverse operation to encode,
        but note that we receive, via the plugin hook,
        to the receive_msg event.
        """
        try:
            type_hex = msg[:4]
            message_hex = msg[4:]
        except:
            raise LNCustomMsgFormatError
        msgtype = int(type_hex, 16)
        text = hextobin(message_hex).decode("utf-8")
        return cls(text, msgtype)

class LNOnionMessageChannel(MessageChannel):
    """ Uses the plugin architecture to hook
    the `sendcustommsg` feature of c-lightning
    to receive messages over the LN onion network,
    and the provided RPC client LightningRPC to send
    messages using the same command.
    See the file jmcl.py for the actual Lightning plugin,
    which must be loaded in a running instance of c-lightning,
    for this to work.
    Uses one or more configured "directory nodes"
    to access a list of current active nodes, and updates
    dynamically from messages seen.
    """

    def __init__(self,
                 configdata,
                 daemon=None):
        MessageChannel.__init__(self, daemon=daemon)
        # configures access to c-lightning RPC over the unix socket.
        self.clnrpc_socket_path = configdata["lightning-rpc"]
        # hostid is a feature to avoid replay attacks across message channels;
        # TODO investigate, but for now, treat LN as one "server".
        self.hostid = "lightning-network"
        # keep track of peers. the list will be instances
        # of LNOnionPeer:
        self.peers = set()
        for dn in configdata["directory-nodes"].split(","):
            # note we don't use a nick for directories:
            self.peers.add(LNOnionDirectoryPeer.from_location_string(dn,
                directory=True, handshake_callback=self.handshake_as_client))
        # the protocol factory for receiving TCP message for us:
        self.tcp_passthrough_factory = TCPPassThroughFactory()
        port = configdata["passthrough-port"]
        self.tcp_passthrough_listener = reactor.listenTCP(port,
                                    self.tcp_passthrough_factory)
        log.info("LNOnionMessageChannel is now listening on TCP port: {}".format(port))
        # will be needed to send messages:
        self.rpc_client = None

        # intended to represent the special case of 'we are the
        # only directory node known', however for now dns don't interact
        # so this has no role. TODO probably remove it.
        self.genesis_node = False

        # waiting loop for all directories to have
        # connected (note we could use a deferred but
        # the rpc connection calls are not using twisted)
        self.wait_for_directories_loop = None

    def get_rpc_client(self, path):
        return LightningRpc(path)

# ABC implementation section
    def run(self) -> None:
        self.rpc_client = self.get_rpc_client(self.clnrpc_socket_path)
        # now the RPC is up, let's find out our own details,
        # so we can forward them to peers:
        self.get_our_peer_info()
        # Next, tell the server routing Lightning messages *to* us
        # that we're ready to listen:
        self.tcp_passthrough_factory.add_tcp_listener(self)
        # at this point the only peers added are directory
        # nodes from config; we try to connect to all.
        # We will get other peers to add to our list once they
        # start sending us messages.
        reactor.callLater(0.0, self.connect_to_directories)

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
        msg = LNCustomMessage(self.get_pubmsg(msg),
                                JM_MESSAGE_TYPES["pubmsg"]).encode()
        for peerid in peerids:
            # currently a directory node can send its own
            # pubmsgs (act as maker or taker); this will
            # probably be removed but is useful in testing:
            if peerid == self.self_as_peer.peerid:
                self.receive_msg({"peer_id": "00", "payload": msg})
            else:
                self._send(peerid, msg)

    def _privmsg(self, nick: str, cmd: str, msg:str) -> None:
        log.debug("Privmsging to: {}, {}, {}".format(nick, cmd, msg))
        encoded_privmsg = LNCustomMessage(self.get_privmsg(nick, cmd, msg),
                            JM_MESSAGE_TYPES["privmsg"]).encode()
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
                peerid = self.get_connected_directory_peers()[0].peerid
            except Exception as e:
                log.warn("Failed to send privmsg because no "
                "directory peer is connected. Error: {}".format(repr(e)))
                return
        self._send(peerid, encoded_privmsg)

    def _announce_orders(self, offerlist: list) -> None:
        for offer in offerlist:
            self._pubmsg(offer)

# End ABC implementation section


    def get_our_peer_info(self) -> None:
        """ Create a special LNOnionPeer object,
        outside of our peerlist, to refer to ourselves.
        """
        resp = self.rpc_client.call("getinfo")
        log.debug("Response from LN rpc getinfo: {}".format(resp))
        # See: https://lightning.readthedocs.io/lightning-getinfo.7.html
        # for the syntax of the response.
        #
        # TODO handle an error response.
        peerid = resp["id"]
        dp = self.get_directory_peers()
        self_dir = False
        if [peerid] == dp:
            log.info("This is the genesis node: {}".format(peerid))
            self.genesis_node = True
            self_dir = True
        elif peerid in dp:
            # Here we are just one of many directory nodes,
            # which should be fine, we should just be careful
            # to not query ourselves.
            self_dir = True

        # TODO ; any obvious way to process multiple addresses,
        # other than just take the first?
        if len(resp["address"]) > 0:
            a = resp["address"][0]
        else:
            # special case regtest: we just use local, no
            # address, only binding:
            a = resp["binding"][0]
        addrtype = a["type"]
        if addrtype not in ["ipv4", "ipv6", "torv3"]:
            raise LNOnionPeerError("Unsupported internet address type: "
                                   "{}".format(addrtype))
        hostname = a["address"]
        port = a["port"]
        # TODO probably need to parse version, alias and network info
        # TODO: could make class LNOnionDirectoryPeer if we are directory,
        # but not needed for now.
        self.self_as_peer = LNOnionPeer(peerid, hostname, port,
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
            log.info("Trying to connect to node: {}".format(p.peerid))
            try:
                p.connect(self.rpc_client)
            except LNOnionPeerConnectionError:
                pass
        # do not trigger on_welcome event until all directories
        # configured are ready:
        self.on_welcome_sent = False
        self.wait_for_directories_loop = task.LoopingCall(
            self.wait_for_directories)
        self.wait_for_directories_loop.start(10.0)

    def handshake_as_client(self, peer: LNOnionPeer) -> None:
        assert peer.status() == PEER_STATUS_CONNECTED
        if self.self_as_peer.directory:
            log.debug("Not sending client handshake because we are directory.")
            return
        our_hs = copy.deepcopy(client_handshake_json)
        our_hs["location-string"] = self.self_as_peer.peer_location()
        our_hs["nick"] = self.nick
        # We fire and forget the handshake; successful setting
        # of the `is_handshaked` var in the Peer object will depend
        # on a valid/success return via the custommsg hook in the plugin.
        log.info("Sending this handshake: {}".format(json.dumps(our_hs)))
        self._send(peer.peerid,
                   LNCustomMessage(json.dumps(our_hs),
                    CONTROL_MESSAGE_TYPES["handshake"]).encode())

    def handshake_as_directory(self, peer: LNOnionPeer, our_hs: dict) -> None:
        assert peer.status() == PEER_STATUS_CONNECTED
        log.info("Sending this handshake: {}".format(json.dumps(our_hs)))
        self._send(peer.peerid,
                   LNCustomMessage(json.dumps(our_hs),
                    CONTROL_MESSAGE_TYPES["dn-handshake"]).encode())

    def get_directory_peers(self) -> list:
        return [ p.peerid for p in self.peers if p.directory is True]

    def get_peerid_by_nick(self, nick:str) -> Union[LNOnionPeer, None]:
        for p in self.get_all_connected_peers():
            if p.nick == nick:
                return p.peerid
        return None

    def _send(self, peerid: str, message: bytes) -> bool:
        """
        This method is "raw" in that it only respects
        c-lightning's sendcustommsg syntax; it does
        not manage the syntax of the underlying Joinmarket
        message in any way.
        Sends a message to a peer on the message channel,
        identified by `peerid`, in hex format, with two byte
        type prepended.
        To encode the `message` field use `LNCustomMessage.encode`.
        Arguments:
        peerid: hex-encoded string.
        message: raw bytes, encoded as per above.
        Returns:
        False if RpcError is raised by a failed RPC call,
        or True otherwise.
        """
        # TODO handle return:
        try:
            self.rpc_client.sendcustommsg(peerid, message)
        except RpcError as e:
            # This can happen when a peer disconnects, depending
            # on the timing:
            log.warn("Failed RPC call to: " + peerid + \
                     ", error: " + repr(e))
            return False
        return True

    def shutdown(self):
        """ TODO
        """

    def receive_msg(self, data: dict) -> None:
        """ The entry point for all data coming over LN into our process.
        This includes control messages from the plugin that inform
        us about updates to peers. Our local messages will come in with
        peer_id 00, and our message types are always two bytes long, these
        two aspects are to conform with the current `sendcustommsg` RPC format.
        """
        try:
            peer = data["peer_id"]
            msgobj = LNCustomMessage.from_sendcustommsg_decode(data["payload"])
            log.debug("Receiving type: {}, message: {}".format(msgobj.msgtype, msgobj.text))
        except LNCustomMsgFormatError:
            log.warn("Incorrect custom message format: {}".format(data["payload"]))
            return
        except Exception as e:
            log.warn("Ill formed message received: {}, exception: {}".format(
                data, e))
            return
        msgtype = msgobj.msgtype
        msgval = msgobj.text
        if msgtype in LOCAL_CONTROL_MESSAGE_TYPES.values():
            self.process_control_message(peer, msgtype, msgval)
            # local control messages are processed first, as their "value"
            # field is not in the onion-TLV format.
            return

        if self.process_control_message(peer, msgtype, msgval):
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
                log.debug("A pubmsg is being processed by {} from {}; it "
                    "is {}".format(self.self_as_peer.nick, from_nick, msg))
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
        encoded_msg = LNCustomMessage(pubmsg, msgtype).encode()
        for peer in self.get_connected_nondirectory_peers():
            # don't loop back to the sender:
            if peer.nick == from_nick:
                continue
            log.debug("Sending {}:{} to nondir peer {}".format(
                msgtype, pubmsg, peer.peerid))
            self._send(peer.peerid, encoded_msg)

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
        log.debug("Sending out privmsg: {} to peer: {}".format(privmsg, peerid))
        encoded_msg = LNCustomMessage(privmsg,
                        JM_MESSAGE_TYPES["privmsg"]).encode()
        self._send(peerid, encoded_msg)
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
        peers, or by a connect/disconnect hook
        in the c-lightning plugin; this is our housekeeping
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
            except LNOnionPeerConnectionError:
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
            # in this case we don't have network connection info;
            # just add the peer as a peerid:
            self.add_peer(msgval.split("@")[0], connection=True,
                          overwrite_connection=True)
        elif msgtype == LOCAL_CONTROL_MESSAGE_TYPES["disconnect"]:
            log.debug("We got a disconnect event: {}".format(msgval))
            if msgval in [x.peerid for x in self.get_connected_directory_peers()]:
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
        assert isinstance(peer, LNOnionPeer)
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
            peer.set_nick(nick)
            # client peer's handshake message was valid; send ours, and
            # then mark this peer as successfully handshaked:
            our_hs = copy.deepcopy(server_handshake_json)
            our_hs["nick"] = self.nick
            our_hs["accepted"] = accepted
            self.handshake_as_directory(peer, our_hs)
            if accepted:
                peer.update_status(PEER_STATUS_HANDSHAKED)

    def get_peer_by_id(self, p: str) -> Union[LNOnionPeer, bool]:
        """ Returns the LNOnionPeer with peerid p,
        if it is in self.peers, otherwise returns False.
        """
        for x in self.peers:
            if x.peerid == p:
                return x
        return False

    def add_peer(self, peerdata: str, connection: bool=False,
                overwrite_connection: bool=False, with_nick=False) -> None:
        """ add non-directory peer from (nick, peer) serialization `peerdata`,
        where "peer" is peerid or full peerid@host:port;
        return the created LNOnionPeer object. Or, with_nick=False means
        that `peerdata` has only the peer location.
        If the peer is already in our peerlist it can be updated in
        one of these ways:
        * the nick can be added
        * it can be marked as 'connected' if it was previously unconnected,
        with this conditional on whether the flag `overwrite_connection` is
        set. Note that this peer removal, unlike the peer addition above,
        can also occur for directory nodes, if we lose connection (and then
        we persistently try to reconnect; see LNOnionDirectoryPeer).
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
        if len(peer) == 66:
            p = self.get_peer_by_id(peer)
            if not p:
                # no address info here
                p = LNOnionPeer(peer, handshake_callback=self.handshake_as_client)
                if connection:
                    log.info("Updating status to connected.")
                    p.update_status(PEER_STATUS_CONNECTED)
                self.peers.add(p)
            elif overwrite_connection:
                if connection:
                    log.info("Updating status to connected.")
                    p.update_status(PEER_STATUS_CONNECTED)
                else:
                    p.update_status(PEER_STATUS_DISCONNECTED)
            if with_nick:
                p.set_nick(nick)
            return p
        elif len(peer) > 66:
            # assumed that it's passing a full string
            try:
                temp_p = LNOnionPeer.from_location_string(peer,
                            handshake_callback=self.handshake_as_client)
            except Exception as e:
                # There are currently a few ways the location
                # parsing and Peer object construction can fail;
                # TODO specify exception types.
                log.warn("Failed to add peer: {}, exception: {}".format(peer, repr(e)))
                return
            if not self.get_peer_by_id(temp_p.peerid):
                if connection:
                    log.info("Updating status to connected.")
                    temp_p.update_status(PEER_STATUS_CONNECTED)
                else:
                    temp_p.update_status(PEER_STATUS_DISCONNECTED)
                if with_nick:
                    temp_p.set_nick(nick)
                self.peers.add(temp_p)
                if not connection:
                    # Here, we have a full location string,
                    # and we are not currently connected. We
                    # try to connect asynchronously. We don't pay attention
                    # to any return. This attempt is one-shot and opportunistic,
                    # for non-dns, but will retry with exp-backoff for dns.
                    # Notice this is only possible for non-dns to other non-dns,
                    # since dns will never reach this point without an active
                    # connection.
                    reactor.callLater(0.0, temp_p.try_to_connect, self.rpc_client)
                return temp_p
            else:
                p = self.get_peer_by_id(temp_p.peerid)
                if overwrite_connection:
                    if connection:
                        log.info("Updating status to connected.")
                        p.update_status(PEER_STATUS_CONNECTED)
                    else:
                        p.update_status(PEER_STATUS_DISCONNECTED)
                if with_nick:
                    p.set_nick(nick)
                return p
        else:
            raise LNOnionPeerError(
            "Invalid peer location string: {}".format(peer))

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
        # connection was seen in the plugin:
        if len(self.get_connected_directory_peers()) == 0:
            return
        # This is what triggers the start of taker/maker workflows.
        if not self.on_welcome_sent:
            self.on_welcome(self)
            self.on_welcome_sent = True
            self.wait_for_directories_loop.stop()

    """ CONTROL MESSAGES SENT BY US
    """
    def send_peers(self, requesting_peer: LNOnionPeer,
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
            raise LNOnionPeerConnectionError(
                "Cannot send peer list to unhandshaked peer")
        peerlist = set()
        for p in self.get_connected_nondirectory_peers():
            # don't send a peer to itself
            if p.peerid == requesting_peer.peerid:
                continue
            if len(peerid_filter) > 0 and p.peerid not in peerid_filter:
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
        self._send(requesting_peer.peerid, LNCustomMessage(",".join(
            peerlist), CONTROL_MESSAGE_TYPES["peerlist"]).encode())


