#!/usr/bin/env python

import pytest

from jmdaemon.orderbookwatch import OrderbookWatch
from jmdaemon import IRCMessageChannel
from jmclient import get_irc_mchannels, load_test_config
from jmdaemon.protocol import JM_VERSION, ORDER_KEYS
class DummyDaemon(object):
    def request_signature_verify(self, a, b, c, d, e,
            f, g, h):
        return True

class DummyMC(IRCMessageChannel):
    def __init__(self, configdata, nick, daemon):
        super().__init__(configdata, daemon=daemon)
        self.daemon = daemon
        self.set_nick(nick)

def on_welcome(x):
    print("Simulated on-welcome")

def get_ob():
    load_test_config()
    dm = DummyDaemon()
    mc = DummyMC(get_irc_mchannels()[0], "test", dm)
    ob = OrderbookWatch()
    ob.on_welcome = on_welcome
    ob.set_msgchan(mc)
    return ob

@pytest.mark.parametrize(
    "badtopic",
    [("abc|"),
     ("abcd|def"),
     ("abc| 0 a qvd"),
     ])
def test_ob(badtopic):
    ob = get_ob()
    topic = ("JoinMarket open outcry pit. /r/joinmarket Discussion in #joinmarket"
             "| 0 5 LATEST RELEASE v0.2.2. Useful new features. Update ASAP, and "
             "do not use pre-0.2.0! https://bitcointalk.org/index.php?topic=91911"
             "6.msg16714124#msg16714124")
    ob.on_set_topic(topic)
    #should not throw:
    ob.on_set_topic(badtopic)
    #test old version
    future_ver = str(JM_VERSION + 2)
    
    deprecated = topic.replace("| 0 5", "| 0 "+future_ver)
    ob.on_set_topic(deprecated)

@pytest.mark.parametrize(
    "counterparty, oid, ordertype, minsize, maxsize, txfee, cjfee, expected",
    [
        #good absoffer
        ("test", "0", "absoffer", "3000", "4000", "2", "300", True),
        #good reloffer
        ("test", "0", "reloffer", "3000", "4000", "2", "0.3", True),
        #dusty minsize OK
        ("test", "0", "reloffer", "1000", "4000", "2", "0.3", True),
        #invalid oid
        ("test", "-2", "reloffer", "3000", "4000", "2", "0.3", False),
        #invalid minsize
        ("test", "2", "reloffer", "-3000", "4000", "2", "0.3", False),
        #invalid maxsize
        ("test", "2", "reloffer", "3000", "2200000000000000", "2", "0.3", False),
        #invalid txfee
        ("test", "2", "reloffer", "3000", "4000", "-1", "0.3", False),
        #min bigger than max
        ("test", "2", "reloffer", "4000", "3000", "2", "0.3", False),
        #non-integer absoffer
        ("test", "2", "absoffer", "3000", "4000", "2", "0.3", False),
        #invalid syntax for cjfee
        ("test", "2", "reloffer", "3000", "4000", "2", "0.-1", False),
        #invalid type for oid
        ("test", "xxx", "reloffer", "3000", "4000", "2", "0.3", False),
    ])
def test_order_seen_cancel(counterparty, oid, ordertype, minsize, maxsize, txfee,
                           cjfee, expected):
    ob = get_ob()
    ob.on_order_seen(counterparty, oid, ordertype, minsize, maxsize,
                              txfee, cjfee)
    if expected:
        #offer should now be in the orderbook
        rows = ob.db.execute('SELECT * FROM orderbook;').fetchall()
        orderbook = [dict([(k, o[k]) for k in ORDER_KEYS]) for o in rows]
        assert len(orderbook) == 1
        #test it can be removed
        ob.on_order_cancel(counterparty, oid)
        rows = ob.db.execute('SELECT * FROM orderbook;').fetchall()
        orderbook = [dict([(k, o[k]) for k in ORDER_KEYS]) for o in rows]
        assert len(orderbook) == 0

def test_disconnect_leave():
    ob = get_ob()
    t_orderbook = [{u'counterparty': u'J5FA1Gj7Ln4vSGne', u'ordertype': u'reloffer', u'oid': 0,
      u'minsize': 7500000, u'txfee': 1000, u'maxsize': 599972700, u'cjfee': u'0.0002'},
     {u'counterparty': u'J5CFffuuewjG44UJ', u'ordertype': u'reloffer', u'oid': 0,
      u'minsize': 7500000, u'txfee': 1000, u'maxsize': 599972700, u'cjfee': u'0.0002'},
     {u'counterparty': u'J55z23xdjxJjC7er', u'ordertype': u'reloffer', u'oid': 0,
      u'minsize': 7500000, u'txfee': 1000, u'maxsize': 599972700, u'cjfee': u'0.0002'},
     {u'counterparty': u'J54Ghp5PXCdY9H3t', u'ordertype': u'reloffer', u'oid': 0,
      u'minsize': 7500000, u'txfee': 1000, u'maxsize': 599972700, u'cjfee': u'0.0002'},
     {u'counterparty': u'J559UPUSLLjHJpaB', u'ordertype': u'reloffer', u'oid': 0,
      u'minsize': 7500000, u'txfee': 1000, u'maxsize': 599972700, u'cjfee': u'0.0002'},
     {u'counterparty': u'J5cBx1FwUVh9zzoO', u'ordertype': u'reloffer', u'oid': 0,
      u'minsize': 7500000, u'txfee': 1000, u'maxsize': 599972700, u'cjfee': u'0.0002'}]
    for o in t_orderbook:
        ob.on_order_seen(o['counterparty'], o['oid'], o['ordertype'],
                         o['minsize'], o['maxsize'], o['txfee'], o['cjfee'])
    rows = ob.db.execute('SELECT * FROM orderbook;').fetchall()
    orderbook = [dict([(k, o[k]) for k in ORDER_KEYS]) for o in rows]
    assert len(orderbook) == 6
    #simulate one cp leaves:
    ob.on_nick_leave("J5cBx1FwUVh9zzoO")
    rows = ob.db.execute('SELECT * FROM orderbook;').fetchall()
    orderbook = [dict([(k, o[k]) for k in ORDER_KEYS]) for o in rows]
    assert len(orderbook) == 5
    #simulate quit
    ob.on_disconnect()
    rows = ob.db.execute('SELECT * FROM orderbook;').fetchall()
    orderbook = [dict([(k, o[k]) for k in ORDER_KEYS]) for o in rows]
    assert len(orderbook) == 0
    
    

    
