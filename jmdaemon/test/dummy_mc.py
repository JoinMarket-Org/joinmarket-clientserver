from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import *

import time



from jmdaemon.message_channel import MessageChannel
from jmdaemon.protocol import *
from jmclient import get_log
from msgdata import *

log = get_log()

# handle one channel at a time
class DummyMessageChannel(MessageChannel):

    def __init__(self,
                 configdata,
                 username='username',
                 realname='realname',
                 password=None,
                 daemon=None,
                 hostid=None):
        MessageChannel.__init__(self, daemon=daemon)
        self.give_up = False
        self.counterparties = [x['counterparty'] for x in t_orderbook]
        self.hostid = "dummy"
        if hostid:
            self.hostid = hostid
        self.serverport = self.hostid

    def __str__(self):
        return self.hostid

    def run(self):
        """Simplest possible event loop."""
        i = 0
        while True:
            if self.give_up:
                break
            time.sleep(0.5)
            if i == 1:
                if self.on_welcome:
                    log.debug("Calling on welcome")
                    self.on_welcome(self)
            i += 1
    
    def shutdown(self):
        self.give_up = True
    
    def close(self):
        self.shutdown()

    def _pubmsg(self, msg):
        pass
    def _privmsg(self, nick, cmd, message):
        """As for pubmsg
        """
    def _announce_orders(self, orderlist):
        pass
    def change_nick(self, new_nick):
        print("Changing nick supposedly")
    
