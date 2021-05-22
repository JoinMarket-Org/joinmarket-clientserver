import random
from jmbase import (get_tor_agent, JMHiddenService,
                    JMHTTPResource, is_hs_uri, HTTPPassThrough)
from .message_channel import MessageChannel

class JMP2PHTTPResource(JMHTTPResource):
    """ Implements the message-receiving side of the
    onion-based P2P network, for each node.
    """
    def __init__(self, info_callback, shutdown_callback, post_request_handler):
        """ The POST request handling callback has function signature:
        args: (request-body-content-in-bytes,)
        returns: (errormsg, errcode, httpcode, response-in-bytes)
        If the request was successful, errormsg should be true and response
        should be in bytes, to be sent in the return value of render_POST().
        """
        self.post_request_handler = post_request_handler
        super().__init__(info_callback, shutdown_callback)

    def jmp2p_error(self, request, error_meaning,
                    error_code="unavailable", http_code=400):
        """
        We return, to the sender, stringified json in the body.
        """
        request.setResponseCode(http_code)
        request.setHeader(b"content-type", b"text/html; charset=utf-8")
        print("Returning an error: " + str(
            error_code) + ": " + str(error_meaning))
        return json.dumps({"errorCode": error_code,
                           "message": error_meaning}).encode("utf-8")

    def render_POST(self, request):
        """ All incoming communications are POST requests;
        GET is only a placeholder (see parent class).
        """
        print("The server got this POST request: ")
        # unfortunately the twisted Request object is not
        # easily serialized:
        print(request)
        print(request.method)
        print(request.uri)
        print(request.args)
        sender_parameters = request.args
        print(request.path)
        # defer logging of raw request content:
        incoming_msg = request.content
        if not isinstance(incoming_msg, BytesIO):
            return self.jmp2p_error(request, "invalid P2P message format",
                                    "message rejected")
        incoming_msg_ascii = incoming_msg.read().decode("ascii")
        reactor.callLater(0.0, self.post_request_handler, request,
                          incoming_msg_ascii)
        return server.NOT_DONE_YET

    def end_failure(self):
        # TODO is this useful for anything?
        self.info_callback("Shutting down onion due to failure.")
        self.shutdown_callback()

class OnionPeer(HTTPPassThrough):
    """ Encapsulates the ability to *outwardly*
    communicate with peers over the P2P network, but
    also (trivially) inbound connections will be related
    to an instance of this class (via the hostname property).
    Also keeps (at process level) a memory of what has been
    communicated to avoid spam/redundant messages either way.
    """
    def __init__(self, hostname, port, nick, netconfig):
        # identifying information
        self.hostname = hostname
        self.port = port
        self.loc = hostname + ":" + str(self.port)
        self.nick = nick
        # note that this is the netconfig of the *local*
        # entity, not the remote peer, allowing to connect
        # to the remote peer:
        self.on_INIT(netconfig)

        # TODO add code at peer level to ban or
        # throttle based on message volume:
        self.banscore = 0

    def send(self, msgbody, cb):
        # sends msgbody as the body of a POST request
        # to / on the remote peer's onion service, and
        # success fires callback cb with the response.
        self.postRequest(msgbody, self.loc,
                         cb)

class OnionMessageChannel(MessageChannel):

    """ Implementation of a Joinmarket message channel
    as a P2P node in a network of hidden services/onions.
    As such, it needs to act as both client and server in
    communication.
    """
    N = 2

    def __init__(self,
                 configdata,
                 daemon=None, realname=None): #note "realname" currently unused
        MessageChannel.__init__(self, daemon=daemon)
        self.socks5_host = configdata["socks5_host"]
        self.socks5_port = int(configdata["socks5_port"])
        self.tor_control_host = configdata["tor_control_host"]
        self.tor_control_port = int(configdata["tor_control_port"])
        self.serving_port = int(configdata["port"])
        self.configdata = configdata
        self.onion = None
        self.resource = JMP2PHTTPResource(self.info_callback, self.shutdown,
                                          self.incoming_message_handler)
        self.nodes = [OnionPeer(hostname, port, nick,
            self.configdata) for hostname, port, nick in configdata["seeds"]]
        # we are not ready to handle messages in or out until our HS is up:
        self.active = False
        print("at end of onionmc, self.nodes is: ", self.nodes)

    def info_callback(self, msg):
        print(msg)

    def onion_ready_callback(self, hostname):
        print("Message channel ready to start operation, hostname is: ", hostname)
        # We start operations with peers only once the Tor onion
        # service is fully active:
        self.active = True

    def setup_error_callback(self, errormsg):
        print("Failed to setup the hidden service, reason: ", errormsg)

    def send_msg_to_peer(self, peer, msg, cb):
        """ Sends message msg to peer peer, as the body
        of a POST request, with a successful response firing
        callback cb.
        Note that this transparently drops the message if it's
        a repeat; this may have implications for callback TODO
        """
        assert isinstance(peer, OnionPeer)
        if msg not in peer.sent_messages:
            peer.send(msg, cb)

    def rate_limiter(self, request, msg):
        """
        TODO
        Control incoming messages.
        Note: we need to know the node
        this is coming from to handle it properly,
        and it also needs to be verified (otherwise
        they could lie about "from" nick).
        """
        return False

    def incoming_message_handler(self, request, msg):
        """ Messages received from a counterparty in the P2P
        network are routed as follows:
        First check for rate limiting violations, if nothing
        is flagged:
        If to us specifically, handle by MessageChannel code as
        privmsg.
        If to ALL:
          * handle in P2P gossip logic
          * AND handle in MessageChannel code as pubmsg.
        If to some other nick, handle as a routing message
        (e.g. is valid for pushtx, but not for others).
        """
        if self.rate_limiter(request, msg):
            return
        from_nick, to_nick, msg = msg.split(":")
        if to_nick == self.nick:
            # special case: we want to allow (one-time)
            # handshake messages to establish existence:
            # TODO what kind of authentication applies?
            if msg[:9] == "HANDSHAKE":
                self.handle_handshake(from_nick, msg[9:])
                return
            # in case the message is for us, we transparently
            # handle it in the existing message channel logic:
            self.on_privmsg(from_nick, msg)
            return
        if to_nick == "ALL":
            self.on_pubmsg(from_nick, msg)
        print("Message to other or all; handling as p2p.")
        self.handle_to_other_message(to_nick, msg)

    def handle_handshake(self, nick, msg):
        """ TODO: way to authenticate that
        the request is from the claimed location?
        """
        hostname, port = msg[1:].split(",")
        self.add_node(hostname, port, nick)

    def handle_to_other_message(self, to_nick, msg):
        if to_nick == "ALL":
            # we have already processed this pubmsg,
            # but we want to gossip it.
            # We only send the same message once
            # (TODO check: what if repeated offer messages?)
            for node in self.nodes:
                self.send_msg_to_peer(node, msg, None)
        else:
            # this is a private message being sent to another
            # peer, we are routing (usually e2e encrypted b64).
            node = self.get_node_by_nick(to_nick)
            if not node:
                return
            self.send_msg_to_peer(node, msg, None)

    def run(self):
        """Main running loop of the message channel"""
        self.onion = JMHiddenService(self.resource, self.info_callback,
                                     self.setup_error_callback,
                                     self.onion_ready_callback,
                                     self.tor_control_host,
                                     self.tor_control_port,
                                     self.serving_port,
                                     None) # currently no shutdown callback
        self.onion.start_tor()

    def shutdown(self):
        """ Shuts down the onion and fires a callback,
        if required.
        """
        self.onion.shutdown()

    def _pubmsg(self, msg):
        """Send a message onto the shared, public
        channel (the joinmarket pit)."""
        # In P2P this will mean sending exactly once
        # to every connection, and relying on gossip.
        # Note that the question of ensuring full gossip
        # is currently not addressed in this code.
        for node in self.nodes:
            otw_message = ":".join([self.nick, "ALL", msg])
            # TODO: generic acceptance callbacks
            self.send_msg_to_peer(node, otw_message, None)

    def _privmsg(self, nick, cmd, message):
        """Send a message to a specific counterparty"""
        msg = cmd + " " + message
        otw_message = ":".join([self.nick, nick, msg])
        node = self.get_node_by_nick(nick)
        if node:
            self.send_msg_to_peer(node, otw_message, None)
            return
        # if we don't have this node in our list yet:
        # (1) try to add it
        # (2) send it for forwarding to N peers (note: if it's not
        #     encrypted then it's public, so fine to send to others)
        self.request_node(nick)
        for node in random.sample(self.nodes, self.N):
            self.send_msg_to_peer(node, otw_message, None)

    def _announce_orders(self, offerlist):
        """Send orders defined in list orderlist to the shared public
        channel (pit)."""
        # TODO: newlines or not?
        self.pubmsg("\n".join(offerlist))
        pass

    def change_nick(self, new_nick):
        """Change the nick/username for this message channel
        instance to new_nick.
        TODO I don't think we have a use-case here,
        leaving empty for now.
        """
        pass

    def add_node(self, hostname, nick, port=80):
        assert is_hs_uri(hostname)
        if self.get_node_by_nick(nick):
            print("Not creating another peer for nick: ", nick)
            return
        self.nodes.append(OnionPeer(hostname,
                            port, nick, self.configdata))
        # announce our existence TODO consider what if the node
        # is not available

    def send_handshake(self, nick):
        # see above re: handshake needs some authentication
        self.send_msg_to_peer(self.get_node_by_nick(nick),
                              "HANDSHAKE", None)

    def add_nodes(self, nodes):
        assert all([isinstance(x, OnionPeer) for x in nodes])
        self.nodes.extend(nodes)

    def get_node_by_nick(self, nick):
        """ Returns the OnionPeer object corresponding
        to the nick if it exists, else None.
        TODO Assumes only 1 per nick.
        """
        for node in self.nodes:
            if node.nick == nick:
                return node
        return None
