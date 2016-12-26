from __future__ import absolute_import, print_function

import base64
import random
import socket
import ssl
#TODO: SSL support (can it be done without back-end openssl?)
import threading
import time
from twisted.internet import reactor, protocol
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.ssl import ClientContextFactory
from twisted.logger import Logger
from twisted.words.protocols import irc
from jmdaemon.message_channel import MessageChannel
from jmbase.support import get_log, chunks
from txsocksx.client import SOCKS5ClientEndpoint
from txsocksx.tls import TLSWrapClientEndpoint
from jmdaemon.protocol import *
MAX_PRIVMSG_LEN = 450

log = get_log()

def wlog(*x):
    """Simplifier to add lists to the debug log
    """
    msg = " ".join([str(a) for a in x])
    log.debug(msg)

def get_irc_text(line):
    return line[line[1:].find(':') + 2:]


def get_irc_nick(source):
    full_nick = source[0:source.find('!')]
    return full_nick[:NICK_MAX_ENCODED+2]


def get_config_irc_channel(chan_name, btcnet):
    channel = "#" + chan_name
    if btcnet == "testnet":
        channel += "-test"
    return channel

class TxIRCFactory(protocol.ClientFactory):
    def __init__(self, wrapper):
        self.wrapper = wrapper
        self.channel = self.wrapper.channel

    def buildProtocol(self, addr):
        p = txIRC_Client(self.wrapper)
        p.factory = self
        self.wrapper.set_tx_irc_client(p)
        return p

    def clientConnectionLost(self, connector, reason):
        log.info('IRC connection lost: ' + str(reason))
        if not self.wrapper.give_up:
            if reactor.running:
                log.info('Attempting to reconnect...')
                reactor.callLater(self.wrapper.reconnect_interval,
                                  connector.connect())

    def clientConnectionFailed(self, connector, reason):
        log.info('IRC connection failed: ' + reason)

class IRCMessageChannel(MessageChannel):

    def __init__(self,
                 configdata,
                 username='username',
                 realname='realname',
                 password=None,
                 daemon=None):
        MessageChannel.__init__(self, daemon=daemon)
        self.give_up = True
        self.serverport = (configdata['host'], configdata['port'])
        #default hostid for use with miniircd which doesnt send NETWORK
        self.hostid = configdata['host'] + str(configdata['port'])
        self.socks5 = configdata["socks5"]
        self.usessl = configdata["usessl"]
        self.socks5_host = configdata["socks5_host"]
        self.socks5_port = int(configdata["socks5_port"])
        self.channel = get_config_irc_channel(configdata["channel"],
                                              configdata["btcnet"])
        self.userrealname = (username, realname)
        if password and len(password) == 0:
            password = None
        self.password = password
        
        self.tx_irc_client = None
        #TODO can be configuration var, how long between reconnect attempts:
        self.reconnect_interval = 10
    #implementation of abstract base class methods;
    #these are mostly but not exclusively acting as pass through
    #to the wrapped twisted IRC client protocol
    def run(self):
        self.give_up = False
        self.build_irc()

    def shutdown(self):
        self.tx_irc_client.quit()
        self.give_up = True

    def _pubmsg(self, msg):
        self.tx_irc_client._pubmsg(msg)

    def _privmsg(self, nick, cmd, msg):
        self.tx_irc_client._privmsg(nick, cmd, msg)

    def change_nick(self, new_nick):
        self.tx_irc_client.setNick(new_nick)

    def _announce_orders(self, offerlist):
        self.tx_irc_client._announce_orders(offerlist)
    #end ABC impl.

    def set_tx_irc_client(self, txircclt):
        self.tx_irc_client = txircclt

    def build_irc(self):
        """The main starting method that creates a protocol object
        according to the config variables, ready for whenever
        the reactor starts running.
        """
        wlog('building irc')
        if self.tx_irc_client:
            raise Exception('irc already built')
        if self.usessl.lower() == 'true':
            factory = TxIRCFactory(self)
            ctx = ClientContextFactory()
            reactor.connectSSL(self.serverport[0], self.serverport[1],
                               factory, ctx)
        elif self.socks5.lower() == 'true':
            #TODO not yet tested! to say it needs to be is a slight understatement.
            factory = TxIRCFactory(self)
            torEndpoint = TCP4ClientEndpoint(reactor, self.socks5_host,
                                             self.socks5_port)
            ircEndpoint = SOCKS5ClientEndpoint(self.serverport[0],
                                               self.serverport[1], torEndpoint)
            if self.usessl:
                ctx = ClientContextFactory()
                tlsEndpoint = TLSWrapClientEndpoint(ctx, ircEndpoint)
                tlsEndpoint.connect(factory)
            else:
                ircEndpoint.connect(factory)
        else:
            try:
                factory = TxIRCFactory(self)
                wlog('build_irc: ', self.serverport[0], self.serverport[1],
                     self.channel)
                self.tcp_connector = reactor.connectTCP(
                        self.serverport[0], self.serverport[1], factory)
            except Exception as e:
                wlog('error in buildirc: ' + repr(e))

class txIRC_Client(irc.IRCClient, object):
    """
    lineRate is a class variable in the superclass used to limit
    messages / second.  heartbeat is what you'd think
    TODO check this handles throttling as necessary, should do.
    """
    lineRate = 0.5
    heartbeatinterval = 60

    def __init__(self, wrapper):
        self.wrapper = wrapper
        self.channel = self.wrapper.channel
        self.nickname = self.wrapper.nick
        self.password = self.wrapper.password
        self.hostname = self.wrapper.serverport[0]
        self.built_privmsg = {}
        # todo: build pong timeout watchdot

    def irc_unknown(self, prefix, command, params):
        pass

    def irc_PONG(self, *args, **kwargs):
        # todo: pong called getattr() style. use for health
        pass

    def connectionMade(self):
        return irc.IRCClient.connectionMade(self)

    def connectionLost(self, reason=protocol.connectionDone):
        wlog('connectionLost:')
        if self.wrapper.on_disconnect:
            reactor.callLater(0.0, self.wrapper.on_disconnect, self.wrapper)
        return irc.IRCClient.connectionLost(self, reason)

    def send(self, send_to, msg):
        # todo: use proper twisted IRC support (encoding + sendCommand)
        omsg = 'PRIVMSG %s :' % (send_to,) + msg
        self.sendLine(omsg.encode('ascii'))

    def _pubmsg(self, message):
        self.send(self.channel, message)

    def _privmsg(self, nick, cmd, message):
        header = "PRIVMSG " + nick + " :"
        max_chunk_len = MAX_PRIVMSG_LEN - len(header) - len(cmd) - 4
        # 1 for command prefix 1 for space 2 for trailer
        if len(message) > max_chunk_len:
            message_chunks = chunks(message, max_chunk_len)
        else:
            message_chunks = [message]
        for m in message_chunks:
            trailer = ' ~' if m == message_chunks[-1] else ' ;'
            if m == message_chunks[0]:
                m = COMMAND_PREFIX + cmd + ' ' + m
            self.send(nick, m + trailer)

    def _announce_orders(self, offerlist):
        """This publishes orders to the pit and to
        counterparties. Note that it does *not* use chunking.
        So, it tries to optimise space usage thusly:
        As many complete orderlines are fit onto one line
        as possible, and overflow goes onto another line.
        Each list entry in orderlist must have format:
        !ordername <parameters>

        Then, what is published is lines of form:
        !ordername <parameters>!ordername <parameters>..

        fitting as many list entries as possible onto one line,
        up to the limit of the IRC parameters (see MAX_PRIVMSG_LEN).

        Order announce in private is handled by privmsg/_privmsg
        using chunking, no longer using this function.
        """
        header = 'PRIVMSG ' + self.channel + ' :'
        offerlines = []
        for i, offer in enumerate(offerlist):
            offerlines.append(offer)
            line = header + ''.join(offerlines) + ' ~'
            if len(line) > MAX_PRIVMSG_LEN or i == len(offerlist) - 1:
                if i < len(offerlist) - 1:
                    line = header + ''.join(offerlines[:-1]) + ' ~'
                self.sendLine(line)
                offerlines = [offerlines[-1]]        
    # ---------------------------------------------
    # general callbacks from superclass
    # ---------------------------------------------

    def signedOn(self):
        wlog('signedOn:')
        self.join(self.factory.channel)

    def joined(self, channel):
        wlog('joined: ', channel)
        #Use as trigger for start to mcc:
        reactor.callLater(0.0, self.wrapper.on_welcome, self.wrapper)

    def privmsg(self, userIn, channel, msg):
        reactor.callLater(0.0, self.handle_privmsg,
                          userIn, channel, msg)

    def __on_privmsg(self, nick, msg):
        self.wrapper.on_privmsg(nick, msg)

    def __on_pubmsg(self, nick, msg):
        self.wrapper.on_pubmsg(nick, msg)

    def handle_privmsg(self, sent_from, sent_to, message):
        try:
            nick = get_irc_nick(sent_from)
            # todo: kludge - we need this elsewhere. rearchitect!!
            self.from_to = (nick, sent_to)
            if sent_to == self.wrapper.nick:
                if nick not in self.built_privmsg:
                    if message[0] != COMMAND_PREFIX:
                        wlog('bad command ', message[0])
                        return
    
                    # new message starting
                    cmd_string = message[1:].split(' ')[0]
                    self.built_privmsg[nick] = [cmd_string, message[:-2]]
                else:
                    self.built_privmsg[nick][1] += message[:-2]
                if message[-1] == ';':
                    pass
                elif message[-1] == '~':
                    parsed = self.built_privmsg[nick][1]
                    # wipe the message buffer waiting for the next one
                    del self.built_privmsg[nick]
                    self.__on_privmsg(nick, parsed)
                else:
                    # drop the bad nick
                    del self.built_privmsg[nick]
            elif sent_to == self.channel:
                self.__on_pubmsg(nick, message)
            else:
                wlog('what is this?: ', sent_from, sent_to, message[:80])
        except:
            wlog('unable to parse privmsg, msg: ', message)

    def action(self, user, channel, msg):
        wlog('unhandled action: ', user, channel, msg)

    def alterCollidedNick(self, nickname):
        """
        Generate an altered version of a nickname that caused a collision in an
        effort to create an unused related name for subsequent registration.
        :param nickname:
        """
        newnick = nickname + '_'
        wlog('nickname collision, changed to ', newnick)
        return newnick

    def modeChanged(self, user, channel, _set, modes, args):
        wlog('(unhandled) modeChanged: ', user, channel, _set, modes, args)

    def pong(self, user, secs):
        wlog('pong: ', user, secs)

    def userJoined(self, user, channel):
        wlog('user joined: ', user, channel)

    def userKicked(self, kickee, channel, kicker, message):
        wlog('kicked: ', kickee, channel, kicker, message)
        if self.wrapper.on_nick_leave:
            reactor.callLater(0.0, self.wrapper.on_nick_leave, kickee, self.wrapper)

    def userLeft(self, user, channel):
        wlog('left: ', user, channel)
        if self.wrapper.on_nick_leave:
            reactor.callLater(0.0, self.wrapper.on_nick_leave, user, self.wrapper)

    def userRenamed(self, oldname, newname):
        wlog('rename: ', oldname, newname)
        #TODO nick change handling

    def userQuit(self, user, quitMessage):
        wlog('userQuit: ', user, quitMessage)
        if self.wrapper.on_nick_leave:
            reactor.callLater(0.0, self.wrapper.on_nick_leave, user, self.wrapper)

    def topicUpdated(self, user, channel, newTopic):
        wlog('topicUpdated: ', user, channel, newTopic)
        if self.wrapper.on_set_topic:
            reactor.callLater(0.0, self.wrapper.on_set_topic, newTopic)

    def receivedMOTD(self, motd):
        wlog('motd: ', motd)

    def created(self, when):
        wlog('(unhandled) created: ', when)

    def yourHost(self, info):
        wlog('(unhandled) yourhost: ', info)

    def isupport(self, options):
        """Used to set the name of the IRC *network*
        (as distinct from the individual server), used
        for signature replay defence (see signing code in message_channel.py).
        If this option ("NETWORK") is not found, we fallback to the default
        hostid = servername+port as shown in IRCMessageChannel (should only
        happen in testing).
        """
        for o in options:
            try:
                k, v = o.split('=')
                if k == 'NETWORK':
                    self.wrapper.hostid = v
            except Exception as e:
                wlog('failed to parse isupport option, ignoring')

    def myInfo(self, servername, version, umodes, cmodes):
        wlog('(unhandled) myInfo: ', servername, version, umodes, cmodes)

    def luserChannels(self, channels):
        wlog('(unhandled) luserChannels: ', channels)

    def bounce(self, info):
        wlog('(unhandled) bounce: ', info)

    def left(self, channel):
        wlog('(unhandled) left: ', channel)

    def noticed(self, user, channel, message):
        wlog('(unhandled) noticed: ', user, channel, message)