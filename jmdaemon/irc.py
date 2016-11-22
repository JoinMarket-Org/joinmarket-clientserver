from __future__ import absolute_import, print_function

import base64
import random
import socket
import ssl
import threading
import time
import Queue


from daemon.message_channel import MessageChannel
from jmbase.support import get_log, chunks
from daemon.socks import socksocket, setdefaultproxy, PROXY_TYPE_SOCKS5
from daemon.protocol import *
MAX_PRIVMSG_LEN = 450
PING_INTERVAL = 300
PING_TIMEOUT = 60

#Throttling parameters; data from
#tests by @chris-belcher:
##worked (bytes per sec/bytes per sec interval / counterparties / max_privmsg_len)
#300/4 / 6 / 400
#600/4 / 6 / 400
#450/4 / 10 / 400
#450/4 / 10 / 450
#525/4 / 10 / 450
##didnt work
#600/4 / 10 / 450
#600/4 / 10 / 400
#2000/2 / 10 / 400
#450/4 / 10 / 475
MSG_INTERVAL = 0.001
B_PER_SEC = 450
B_PER_SEC_INTERVAL = 4.0

def get_config_irc_channel(chan_name, btcnet):
    channel = "#" + chan_name
    if btcnet == "testnet":
        channel += "-test"
    return channel

log = get_log()

def get_irc_text(line):
    return line[line[1:].find(':') + 2:]


def get_irc_nick(source):
    full_nick = source[1:source.find('!')]
    return full_nick[:NICK_MAX_ENCODED+2]


class ThrottleThread(threading.Thread):

    def __init__(self, irc):
        threading.Thread.__init__(self, name='ThrottleThread')
        self.daemon = True
        self.irc = irc
        self.msg_buffer = []

    def run(self):
        log.debug("starting throttle thread")
        last_msg_time = 0
        print_throttle_msg = True
        while not self.irc.give_up:
            self.irc.lockthrottle.acquire()
            while not (self.irc.throttleQ.empty() and self.irc.obQ.empty()
                       and self.irc.pingQ.empty()):
                time.sleep(0.0001) #need to avoid cpu spinning if throttled
                try:
                    pingmsg = self.irc.pingQ.get(block=False)
                    #ping messages are not counted to throttling totals,
                    #so send immediately
                    self.irc.sock.sendall(pingmsg + '\r\n')
                    continue
                except Queue.Empty:
                    pass
                except:
                    log.warn("failed to send ping message on socket")
                    break
                #First throttling mechanism: no more than 1 line
                #per MSG_INTERVAL seconds.
                x = time.time() - last_msg_time
                if  x < MSG_INTERVAL:
                    continue
                #Second throttling mechanism: limited kB/s rate
                #over the most recent period.
                q = time.time() - B_PER_SEC_INTERVAL
                #clean out old messages
                self.msg_buffer = [_ for _ in self.msg_buffer if _[1] > q]
                bytes_recent = sum(len(i[0]) for i in self.msg_buffer)
                if bytes_recent > B_PER_SEC * B_PER_SEC_INTERVAL:
                    if print_throttle_msg:
                        log.debug("Throttling triggered, with: "+str(
                            bytes_recent)+ " bytes in the last "+str(
                                B_PER_SEC_INTERVAL)+" seconds.")
                    print_throttle_msg = False
                    continue
                print_throttle_msg = True
                try:
                    throttled_msg = self.irc.throttleQ.get(block=False)
                except Queue.Empty:
                    try:
                        throttled_msg = self.irc.obQ.get(block=False)
                    except Queue.Empty:
                        #this code *should* be unreachable.
                        continue
                try:
                    self.irc.sock.sendall(throttled_msg+'\r\n')
                    last_msg_time = time.time()
                    self.msg_buffer.append((throttled_msg, last_msg_time))
                except:
                    log.error("failed to send on socket")
                    try:
                        self.irc.fd.close()
                    except: pass
                    break
            self.irc.lockthrottle.wait()
            self.irc.lockthrottle.release()

        log.debug("Ended throttling thread.")

class PingThread(threading.Thread):

    def __init__(self, irc):
        threading.Thread.__init__(self, name='PingThread')
        self.daemon = True
        self.irc = irc

    def run(self):
        log.debug('starting ping thread')
        while not self.irc.give_up:
            time.sleep(PING_INTERVAL)
            try:
                self.irc.ping_reply = False
                # maybe use this to calculate the lag one day
                self.irc.lockcond.acquire()
                self.irc.send_raw('PING LAG' + str(int(time.time() * 1000)))
                self.irc.lockcond.wait(PING_TIMEOUT)
                self.irc.lockcond.release()
                if not self.irc.ping_reply:
                    log.warn('irc ping timed out')
                    try:
                        self.irc.close()
                    except:
                        pass
                    try:
                        self.irc.fd.close()
                    except:
                        pass
                    try:
                        self.irc.sock.shutdown(socket.SHUT_RDWR)
                        self.irc.sock.close()
                    except:
                        pass
            except IOError as e:
                log.debug('ping thread: ' + repr(e))
        log.debug('ended ping thread')


# handle one channel at a time
class IRCMessageChannel(MessageChannel):
    # close implies it will attempt to reconnect
    def close(self):
        try:
            self.sock.sendall("QUIT\r\n")
        except IOError as e:
            log.info('errored while trying to quit: ' + repr(e))

    def shutdown(self):
        self.close()
        self.give_up = True

    # Maker callbacks
    def _announce_orders(self, orderlist):
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
        orderlines = []
        for i, order in enumerate(orderlist):
            orderlines.append(order)
            line = header + ''.join(orderlines) + ' ~'
            if len(line) > MAX_PRIVMSG_LEN or i == len(orderlist) - 1:
                if i < len(orderlist) - 1:
                    line = header + ''.join(orderlines[:-1]) + ' ~'
                self.send_raw(line)
                orderlines = [orderlines[-1]]

    def _pubmsg(self, message):
        line = "PRIVMSG " + self.channel + " :" + message
        assert len(line) <= MAX_PRIVMSG_LEN
        ob = False
        if any([x in line for x in offername_list]):
            ob = True
        self.send_raw(line, ob)

    def _privmsg(self, nick, cmd, message):
        """Send a privmsg to an irc counterparty,
        using chunking as appropriate for long messages.
        """
        ob = True if cmd in offername_list else False
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
            self.send_raw(header + m + trailer, ob)

    def change_nick(self, new_nick):
        self.nick = new_nick
        self.send_raw('NICK ' + self.nick)

    def send_raw(self, line, ob=False):
        # Messages are queued and prioritised.
        # This is an addressing of github #300
        if line.startswith("PING") or line.startswith("PONG"):
            self.pingQ.put(line)
        elif ob:
                self.obQ.put(line)
        else:
            self.throttleQ.put(line)
        self.lockthrottle.acquire()
        self.lockthrottle.notify()
        self.lockthrottle.release()

    def __handle_privmsg(self, source, target, message):
        nick = get_irc_nick(source)
        #ensure return value 'parsed' is length > 2
        if len(message) < 4:
            return
        if target == self.nick:
            if message[0] == '\x01':
                endindex = message[1:].find('\x01')
                if endindex == -1:
                    return
                ctcp = message[1:endindex + 1]
                if ctcp.upper() == 'VERSION':
                    self.send_raw('PRIVMSG ' + nick +
                                  ' :\x01VERSION xchat 2.8.8 Ubuntu\x01')
                    return

            if nick not in self.built_privmsg:
                self.built_privmsg[nick] = message[:-2]
            else:
                self.built_privmsg[nick] += message[:-2]
            if message[-1] == '~':
                parsed = self.built_privmsg[nick]
                # wipe the message buffer waiting for the next one
                del self.built_privmsg[nick]
                log.debug("<<privmsg on %s: " %
                (self.hostid) + "nick=%s message=%s" % (nick, parsed))
                self.on_privmsg(nick, parsed)
            elif message[-1] != ';':
                # drop the bad nick
                del self.built_privmsg[nick]
        elif target == self.channel:
            log.info("<<pubmsg on %s: " %
            (self.hostid) + "nick=%s message=%s" %
            (nick, message))
            self.on_pubmsg(nick, message)
        else:
            log.debug("what is this? privmsg on %s: " %
            (self.hostid) + "src=%s target=%s message=%s;" %
                      (source, target, message))

    def __handle_line(self, line):
        line = line.rstrip()
        # log.debug('<< ' + line)
        if line.startswith('PING '):
            self.send_raw(line.replace('PING', 'PONG'))
            return

        _chunks = line.split(' ')
        if _chunks[1] == 'QUIT':
            nick = get_irc_nick(_chunks[0])
            if nick == self.nick:
                raise IOError('we quit')
            else:
                if self.on_nick_leave:
                    self.on_nick_leave(nick, self)
        elif _chunks[1] == '433':  # nick in use
            # helps keep identity constant if just _ added
            #request new nick on *all* channels via callback
            if self.on_nick_change:
                self.on_nick_change(self.nick + '_')
        if self.password:
            if _chunks[1] == 'CAP':
                if _chunks[3] != 'ACK':
                    log.warn("server %s " %
                    (self.hostid) + "does not support SASL, quitting")
                    self.shutdown()
                self.send_raw('AUTHENTICATE PLAIN')
            elif _chunks[0] == 'AUTHENTICATE':
                self.send_raw('AUTHENTICATE ' + base64.b64encode(
                    self.nick + '\x00' + self.nick + '\x00' + self.password))
            elif _chunks[1] == '903':
                log.info("Successfully authenticated on %s" %
                (self.hostid))
                self.password = None
                self.send_raw('CAP END')
            elif _chunks[1] == '904':
                log.warn("Failed authentication %s " %
                (self.hostid) + ", wrong password")
                self.shutdown()
            return

        if _chunks[1] == 'PRIVMSG':
            self.__handle_privmsg(_chunks[0], _chunks[2], get_irc_text(line))
        if _chunks[1] == 'PONG':
            self.ping_reply = True
            self.lockcond.acquire()
            self.lockcond.notify()
            self.lockcond.release()
        elif _chunks[1] == '376':  # end of motd
            self.built_privmsg = {}
            if self.on_connect:
                self.on_connect(self)
            if self.hostid == 'agora-irc':
                self.send_raw('PART #AGORA')
            self.send_raw('JOIN ' + self.channel)
            self.send_raw(
                'MODE ' + self.nick + ' +B')  # marks as bots on unreal
            self.send_raw(
                'MODE ' + self.nick + ' -R')  # allows unreg'd private messages
        elif _chunks[1] == '366':  # end of names list
            log.info("Connected to IRC and joined channel on %s " %
                (self.hostid))
            if self.on_welcome:
                self.on_welcome(self) #informs mc-collection that we are ready for use
        elif _chunks[1] == '332' or _chunks[1] == 'TOPIC':  # channel topic
            topic = get_irc_text(line)
            self.on_set_topic(topic)
        elif _chunks[1] == 'KICK':
            target = _chunks[3]
            if target == self.nick:
                self.give_up = True
                fmt = '{} has kicked us from the irc channel! Reason= {}'.format
                raise IOError(fmt(get_irc_nick(_chunks[0]), get_irc_text(line)))
            else:
                if self.on_nick_leave:
                    self.on_nick_leave(target, self)
        elif _chunks[1] == 'PART':
            nick = get_irc_nick(_chunks[0])
            if self.on_nick_leave:
                self.on_nick_leave(nick, self)
        elif _chunks[1] == '005':
            '''
            :port80b.se.quakenet.org 005 J5BzJGGfyw5GaPc MAXNICKLEN=15
            TOPICLEN=250 AWAYLEN=160 KICKLEN=250 CHANNELLEN=200
            MAXCHANNELLEN=200 CHANTYPES=#& PREFIX=(ov)@+ STATUSMSG=@+
            CHANMODES=b,k,l,imnpstrDducCNMT CASEMAPPING=rfc1459
            NETWORK=QuakeNet :are supported by this server
            '''
            for chu in _chunks[3:]:
                if chu[0] == ':':
                    break
                if chu.lower().startswith('network='):
                    self.hostid = chu[8:]
                    log.debug('found network name: ' + self.hostid + ';')

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
        self.given_password = password
        self.pingQ = Queue.Queue()
        self.throttleQ = Queue.Queue()
        self.obQ = Queue.Queue()

    def run(self):
        self.give_up = False
        self.ping_reply = True
        self.lockcond = threading.Condition()
        self.lockthrottle = threading.Condition()
        PingThread(self).start()
        ThrottleThread(self).start()

        while not self.give_up:
            try:
                log.info("connecting to host %s" %
                              (self.hostid))
                if self.socks5.lower() == 'true':
                    log.debug("Using socks5 proxy %s:%d" %
                              (self.socks5_host, self.socks5_port))
                    setdefaultproxy(PROXY_TYPE_SOCKS5,
                                          self.socks5_host, self.socks5_port,
                                          True)
                    self.sock = socksocket()
                else:
                    self.sock = socket.socket(socket.AF_INET,
                                              socket.SOCK_STREAM)
                self.sock.connect(self.serverport)
                if self.usessl.lower() == 'true':
                    self.sock = ssl.wrap_socket(self.sock)
                self.fd = self.sock.makefile()
                self.password = None
                if self.given_password:
                    self.password = self.given_password
                    self.send_raw('CAP REQ :sasl')
                self.send_raw('USER %s b c :%s' % self.userrealname)
                self.nick = self.given_nick
                self.send_raw('NICK ' + self.nick)
                while 1:
                    try:
                        line = self.fd.readline()
                    except AttributeError as e:
                        raise IOError(repr(e))
                    if line is None:
                        log.debug("line returned null from %s" %
                            (self.hostid))
                        break
                    if len(line) == 0:
                        log.debug("line was zero length from %s" %
                            (self.hostid))
                        break
                    self.__handle_line(line)
            except IOError as e:
                import traceback
                log.debug("logging traceback from %s: \n" %
                    (self.hostid) + traceback.format_exc())
            finally:
                try:
                    self.fd.close()
                    self.sock.close()
                except Exception as e:
                    pass
            if self.on_disconnect:
                self.on_disconnect(self)
            log.info("disconnected from irc host %s" %
                (self.hostid))
            if not self.give_up:
                time.sleep(30)
        log.info('ending irc')
        self.give_up = True
