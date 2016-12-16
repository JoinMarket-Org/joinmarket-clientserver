#! /usr/bin/env python
from __future__ import absolute_import
'''Tests of joinmarket bots end-to-end (including IRC and bitcoin) '''

import subprocess
import signal
import os
import pytest
import time
import threading
import hashlib
import jmbitcoin as btc
from jmdaemon import (JOINMARKET_NICK_HEADER, NICK_HASH_LENGTH,
                      NICK_MAX_ENCODED, IRCMessageChannel)
from jmdaemon.message_channel import CJPeerError
import jmdaemon
#needed for test framework
from jmclient import (load_program_config, get_irc_mchannels, jm_single)

python_cmd = "python2"
yg_cmd = "yield-generator-basic.py"
yg_name = "ygtest"
si = 3
class DummyDaemon(object):
    def request_signature_verify(self, a, b, c, d, e,
            f, g, h):
        return True
    
class DummyMC(IRCMessageChannel):
    def __init__(self, configdata, nick, daemon):
        super(DummyMC, self).__init__(configdata, daemon=daemon)
        """
        #hacked in here to allow auth without mc-collection
        nick_priv = hashlib.sha256(os.urandom(16)).hexdigest() + '01'
        nick_pubkey = btc.privtopub(nick_priv)
        nick_pkh_raw = hashlib.sha256(nick_pubkey).digest()[
            :NICK_HASH_LENGTH]
        nick_pkh = btc.changebase(nick_pkh_raw, 256, 58)
        #right pad to maximum possible; b58 is not fixed length.
        #Use 'O' as one of the 4 not included chars in base58.
        nick_pkh += 'O' * (NICK_MAX_ENCODED - len(nick_pkh))
        #The constructed length will be 1 + 1 + NICK_MAX_ENCODED
        nick = JOINMARKET_NICK_HEADER + str(
            jm_single().JM_VERSION) + nick_pkh
        jm_single().nickname = nick
        """
        self.daemon = daemon
        self.set_nick(nick)

def on_connect(x):
    print('simulated on-connect')
def on_welcome(x):
    print('simulated on-welcome')
def on_disconnect(x):
    print('simulated on-disconnect')

def on_order_seen(dummy, counterparty, oid, ordertype, minsize,
                                           maxsize, txfee, cjfee):
    global yg_name
    yg_name = counterparty

def on_pubkey(pubkey):
    print "received pubkey: " + pubkey

class RawIRCThread(threading.Thread):

    def __init__(self, ircmsgchan):
        threading.Thread.__init__(self, name='RawIRCThread')
        self.daemon = True
        self.ircmsgchan = ircmsgchan
    
    def run(self):
        self.ircmsgchan.run()

def test_junk_messages(setup_messaging):
    #start a yg bot just to receive messages
    """
    wallets = make_wallets(1,
                           wallet_structures=[[1,0,0,0,0]],
                           mean_amt=1)
    wallet = wallets[0]['wallet']
    ygp = local_command([python_cmd, yg_cmd,\
                             str(wallets[0]['seed'])], bg=True)
    """
    #time.sleep(90)
    #start a raw IRCMessageChannel instance in a thread;
    #then call send_* on it with various errant messages
    dm = DummyDaemon()
    mc = DummyMC(get_irc_mchannels()[0], "irc_ping_test", dm)
    mc.register_orderbookwatch_callbacks(on_order_seen=on_order_seen)
    mc.register_taker_callbacks(on_pubkey=on_pubkey)
    mc.on_connect = on_connect
    mc.on_disconnect = on_disconnect
    mc.on_welcome = on_welcome
    RawIRCThread(mc).start()
    #start up a fake counterparty
    mc2 = DummyMC(get_irc_mchannels()[0], yg_name, dm)
    RawIRCThread(mc2).start()
    time.sleep(si)
    mc.request_orderbook()
    time.sleep(si)
    #now try directly
    mc.pubmsg("!orderbook")
    time.sleep(si)
    #should be ignored; can we check?
    mc.pubmsg("!orderbook!orderbook")
    time.sleep(si)
    #assuming MAX_PRIVMSG_LEN is not something crazy
    #big like 550, this should fail
    with pytest.raises(AssertionError) as e_info:
        mc.pubmsg("junk and crap"*40)
    time.sleep(si)
    #assuming MAX_PRIVMSG_LEN is not something crazy
    #small like 180, this should succeed
    mc.pubmsg("junk and crap"*15)
    time.sleep(si)
    #try a long order announcement in public
    #because we don't want to build a real orderbook,
    #call the underlying IRC announce function.
    #TODO: how to test that the sent format was correct?
    mc._announce_orders(["!abc def gh 0001"]*30)
    time.sleep(si)
    #send a fill with an invalid pubkey to the existing yg;
    #this should trigger a NaclError but should NOT kill it.
    mc._privmsg(yg_name, "fill", "0 10000000 abcdef")
    #Test that null privmsg does not cause crash; TODO check maker log?
    mc.send_raw("PRIVMSG " + yg_name + " :")
    time.sleep(si)
    #Try with ob flag
    mc._pubmsg("!reloffer stuff")
    time.sleep(si)
    #Trigger throttling with large messages
    mc._privmsg(yg_name, "tx", "aa"*5000)
    time.sleep(si)
    #with pytest.raises(CJPeerError) as e_info:
    mc.send_error(yg_name, "fly you fools!")
    time.sleep(si)
    #Test the effect of shutting down the connection
    mc.set_reconnect_interval(si-1)
    mc.close()
    mc._announce_orders(["!abc def gh 0001"]*30)
    time.sleep(si+2)
    #kill the connection at socket level
    mc.shutdown()

@pytest.fixture(scope="module")
def setup_messaging():
    #Trigger PING LAG sending artificially
    jmdaemon.irc.PING_INTERVAL = 3
    load_program_config()




