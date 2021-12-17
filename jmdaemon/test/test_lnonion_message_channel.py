#! /usr/bin/env python
'''Tests of LNOnionMessageChannel function '''

import copy
from twisted.trial import unittest
from twisted.internet import reactor, defer
from jmdaemon import LNOnionMessageChannel, MessageChannelCollection, COMMAND_PREFIX
from jmclient import (load_test_config, get_mchannels, jm_single)
from jmbase import get_log
from ln_test_data import *

""" We need to spoof both incoming and outcoming.
Incoming is from lightningd -> sendonionmessage trigger -> jmcl plugin -> tcp-passthrough
Outgoing is from here to lightningd via LightningRpc.
Creating a full test of the lightningd backend, which necessarily requires multiple nodes,
is a large project, so here we are less ambitious. We make a pretend version of the
LightningRpc client which stores the received messages, indexed by nick.
Then that same object sends back the messages in tcp-passthrough messages.
"""

log = get_log()

# The "daemon" here is specifically the daemon protocol in
# jmdaemon; we just make sure that the usual nick signature
# verification alawys passes:
class DummyDaemon(object):
    def request_signature_verify(self, a, b, c, d, e,
            f, g, h):
        return True

# wrapper class allows us to set a nick
# initially without jmclient interaction:
class DummyMC(LNOnionMessageChannel):
    def __init__(self, configdata, nick, daemon):
        super().__init__(configdata, daemon=daemon)
        self.daemon = daemon
        self.set_nick(nick)

    def get_rpc_client(self, path):
        return DummyRpcClient(path)

class DummyRpcClient(object):
    def __init__(self, path):
        self.path = path

    def call(self, method, obj=None):
        print("Call of method {} with data {} occurred in "
              "DummyRpcClient".format(method, obj))
        if method == "getinfo":
            return mock_getinfo_result
        else:
            return {}

    def sendcustommsg(self, peerid, msg):
        print("simulating send of msg to peer: {}".format(
            peerid))
        return self.call("sendcustommsg", obj=msg)

def on_connect(x):
    print('simulated on-connect')

def on_welcome(mc):
    print('simulated on-welcome')
def on_disconnect(x):
    print('simulated on-disconnect')

def on_order_seen(dummy, counterparty, oid, ordertype, minsize,
                                           maxsize, txfee, cjfee):
    global yg_name
    yg_name = counterparty

def on_pubkey(pubkey):
    print("received pubkey: " + pubkey)

def junk_pubmsgs(mc):
    mc.request_orderbook()
    #now try directly
    mc.pubmsg("!orderbook")
    #should be ignored; can we check?
    mc.pubmsg("!orderbook!orderbook")

def junk_longmsgs(mc):
    # TODO: not currently using real `sendcustommsg`,
    # so testing a longer than expected message is pointless.
    # in future mock or use the real lightning rpc call.
    # Leaving here for now as it doesn't hurt.
    mc.pubmsg("junk and crap"*15)

def junk_announce(mc):
    #try a long order announcement in public
    #because we don't want to build a real orderbook,
    #TODO: how to test that the sent format was correct?
    mc._announce_orders(["!abc def gh 0001"]*15)

def junk_fill(mc):
    #send a fill with an invalid pubkey to the existing yg;
    #this should trigger a NaclError but should NOT kill it.
    mc._privmsg(nick2, "fill", "0 10000000 abcdef")
    #Try with ob flag
    mc._pubmsg("!reloffer stuff")
    # TODO: What happens if we send messages larger than the onion
    # packet size limit? As per above, need real LN parsing.
    mc._privmsg(nick2, "tx", "aa"*500)
    mc.send_error(nick2, "fly you fools!")
    return mc

def getmc(nick):
    dm = DummyDaemon()
    mc = DummyMC(get_mchannels()[0], nick, dm)
    mc.register_orderbookwatch_callbacks(on_order_seen=on_order_seen)
    mc.register_taker_callbacks(on_pubkey=on_pubkey)
    mc.on_connect = on_connect
    mc.on_disconnect = on_disconnect
    mc.on_welcome = on_welcome
    mcc = MessageChannelCollection([mc])
    mc.on_pubmsg_trigger = mcc.see_nick
    return dm, mc, mcc

class LNOnionTest(unittest.TestCase):

    def setUp(self):
        # add a config section dynamically, specifically
        # for this purpose:
        load_test_config()
        self.old_config = copy.deepcopy(jm_single().config)
        jm_single().config.remove_section("MESSAGING:server1")
        jm_single().config.remove_section("MESSAGING:server2")
        if "MESSAGING:lightning1" in jm_single().config.sections():
            jm_single().config.remove_section("MESSAGING:lightning1")
        jm_single().config.add_section("MESSAGING:lightning1")
        jm_single().config.set("MESSAGING:lightning1", "type", "ln-onion")
        jm_single().config.set("MESSAGING:lightning1", "directory-nodes",
            "03df15dbd9e20c811cc5f4155745e89540a0b83f33978317cebe9dfc46c5253c55@127.0.0.1:9835")
        jm_single().config.set("MESSAGING:lightning1", "passthrough-port", str(49100))
        jm_single().config.set("MESSAGING:lightning1", "lightning-port", "9835")
        jm_single().config.set("MESSAGING:lightning1", "lightning-rpc", "mock-rpc-socket-file")
        print(get_mchannels()[0])
        jm_single().maker_timeout_sec = 1
        self.dm, self.mc, self.mcc = getmc("irc_publisher")
        self.mcc.run()

    def test_all(self):
        # it's slightly simpler to test each functionality in series
        # in one test function (so we can preserve order).
        self.mc.on_welcome(self.mc)
        tm = "testmessage"
        assert self.mc.get_pubmsg(tm, source_nick=nick1) == \
               nick1 + COMMAND_PREFIX + "PUBLIC" + tm
        assert self.mc.get_privmsg(nick2, "ioauth", tm,
                source_nick=nick1) == nick1 + COMMAND_PREFIX + \
               nick2 + COMMAND_PREFIX + "ioauth " + tm
        self.mcc.pubmsg(tm)
        # in order for us to privmsg a counterparty we need to think
        # it's visible *and* connected, because *we* are the only
        # directory. To do that we mock a control message from the dn
        # telling us that he's there:
        self.mc.receive_msg(mock_control_message1)
        self.mc.receive_msg(mock_control_connected_message)
        # since LN connections require a handshake before we can accept
        # messages or talk to peers, as clients, we simulate the reception
        # of the client handshake from this peer:
        self.mc.receive_msg(mock_client_handshake_message)
        # note that we should send out our 'server' handshake back to him,
        # but this is outside the simulation.
        # Next, we mock him sending out a pubmsg; this is needed,
        # because msgchans only register nicks 'active' on that mc via
        # the on_pubmsg_trigger; otherwise they might be connected, and
        # they might be handshaked, but they are not 'active'!:
        self.mc.receive_msg(mock_receiver_pubmsg)
        # absence of 'peer not found' in response to this
        # privmsg will mean the above worked:
        self.mc._privmsg(nick2, "ioauth", tm)
        # check our peerinfo is right:
        sap = self.mc.self_as_peer       
        assert sap.peerid == '03df15dbd9e20c811cc5f4155745e89540a0b83f33978317cebe9dfc46c5253c55'
        assert sap.hostname == '127.0.0.1'
        assert sap.port == 9835
        # we have no directory or non-directory peers right now:
        assert self.mc.get_connected_directory_peers() == []
        assert len(self.mc.get_connected_nondirectory_peers()) == 1
        junk_pubmsgs(self.mc)
        junk_longmsgs(self.mc)
        junk_announce(self.mc)
        junk_fill(self.mc)


    def tearDown(self):
        jm_single().config = self.old_config
        for dc in reactor.getDelayedCalls():
            dc.cancel()
        # only fire if everything is finished:
        return defer.maybeDeferred(self.mc.tcp_passthrough_listener.stopListening)






