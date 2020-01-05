#! /usr/bin/env python
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401
'''Tests of joinmarket bots end-to-end (including IRC and bitcoin) '''

import time
from twisted.trial import unittest
from twisted.internet import reactor, task
from jmdaemon import IRCMessageChannel, MessageChannelCollection
#needed for test framework
from jmclient import (load_program_config, get_irc_mchannels, jm_single)

si = 1
class DummyDaemon(object):
    def request_signature_verify(self, a, b, c, d, e,
            f, g, h):
        return True
    
class DummyMC(IRCMessageChannel):
    def __init__(self, configdata, nick, daemon):
        super(DummyMC, self).__init__(configdata, daemon=daemon)
        self.daemon = daemon
        self.set_nick(nick)

def on_connect(x):
    print('simulated on-connect')
def on_welcome(mc):
    print('simulated on-welcome')
    mc.tx_irc_client.lineRate = 0.2
    if mc.nick == "irc_publisher":
        d = task.deferLater(reactor, 3.0, junk_pubmsgs, mc)
        d.addCallback(junk_longmsgs)
        d.addCallback(junk_announce)
        d.addCallback(junk_fill)

def on_disconnect(x):
    print('simulated on-disconnect')

def on_order_seen(dummy, counterparty, oid, ordertype, minsize,
                                           maxsize, txfee, cjfee):
    global yg_name
    yg_name = counterparty

def on_pubkey(pubkey):
    print("received pubkey: " + pubkey)

def junk_pubmsgs(mc):
    #start a raw IRCMessageChannel instance in a thread;
    #then call send_* on it with various errant messages
    time.sleep(si)
    mc.request_orderbook()
    time.sleep(si)
    #now try directly
    mc.pubmsg("!orderbook")
    time.sleep(si)
    #should be ignored; can we check?
    mc.pubmsg("!orderbook!orderbook")
    return mc

def junk_longmsgs(mc):
    #assuming MAX_PRIVMSG_LEN is not something crazy
    #big like 550, this should fail
    #with pytest.raises(AssertionError) as e_info:
    mc.pubmsg("junk and crap"*40)
    time.sleep(si)
    #assuming MAX_PRIVMSG_LEN is not something crazy
    #small like 180, this should succeed
    mc.pubmsg("junk and crap"*15)
    time.sleep(si)
    return mc

def junk_announce(mc):
    #try a long order announcement in public
    #because we don't want to build a real orderbook,
    #call the underlying IRC announce function.
    #TODO: how to test that the sent format was correct?
    print('got here')
    mc._announce_orders(["!abc def gh 0001"]*30)
    time.sleep(si)
    return mc

def junk_fill(mc):
    cpname = "irc_receiver"
    #send a fill with an invalid pubkey to the existing yg;
    #this should trigger a NaclError but should NOT kill it.
    mc._privmsg(cpname, "fill", "0 10000000 abcdef")
    #Try with ob flag
    mc._pubmsg("!reloffer stuff")
    time.sleep(si)
    #Trigger throttling with large messages
    mc._privmsg(cpname, "tx", "aa"*5000)
    time.sleep(si)
    #with pytest.raises(CJPeerError) as e_info:
    mc.send_error(cpname, "fly you fools!")
    time.sleep(si)
    return mc

def getmc(nick):
    dm = DummyDaemon()
    mc = DummyMC(get_irc_mchannels()[0], nick, dm)
    mc.register_orderbookwatch_callbacks(on_order_seen=on_order_seen)
    mc.register_taker_callbacks(on_pubkey=on_pubkey)
    mc.on_connect = on_connect
    mc.on_disconnect = on_disconnect
    mc.on_welcome = on_welcome
    mcc = MessageChannelCollection([mc])
    return dm, mc, mcc

class TrialIRC(unittest.TestCase):

    def setUp(self):
        load_program_config()
        print(get_irc_mchannels()[0])
        jm_single().maker_timeout_sec = 1
        dm, mc, mcc = getmc("irc_publisher")
        dm2, mc2, mcc2 = getmc("irc_receiver")
        mcc.run()
        mcc2.run()
        def cb(m):
            #don't try to reconnect
            m.give_up = True
            m.tcp_connector.disconnect()
        self.addCleanup(cb, mc)
        self.addCleanup(cb, mc2)
        #test_junk_messages()
        print("Got here")

    def test_waiter(self):
        print("test_main()")
        #reactor.callLater(1.0, junk_messages, self.mcc)
        return task.deferLater(reactor, 30, self._called_by_deffered)

    def _called_by_deffered(self):
        pass





