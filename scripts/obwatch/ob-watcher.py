#!/usr/bin/env python3
from future.utils import iteritems
from past.builtins import cmp
from functools import cmp_to_key

import http.server
import base64
import io
import json
import threading
import time
import hashlib
import os
import sys
from future.moves.urllib.parse import parse_qs
from decimal import Decimal
from optparse import OptionParser
from twisted.internet import reactor

from jmbase.support import EXIT_FAILURE

from jmbase import get_log
log = get_log()

try:
    import matplotlib
except:
    log.warning("matplotlib not found, charts will not be available. "
                "Do `pip install matplotlib` in the joinmarket virtualenv.")

if 'matplotlib' in sys.modules:
    # https://stackoverflow.com/questions/2801882/generating-a-png-with-matplotlib-when-display-is-undefined
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

from jmclient import jm_single, load_program_config, calc_cj_fee, \
     get_irc_mchannels, add_base_options
from jmdaemon import OrderbookWatch, MessageChannelCollection, IRCMessageChannel
#TODO this is only for base58, find a solution for a client without jmbitcoin
import jmbitcoin as btc
from jmdaemon.protocol import *

#Initial state: allow only SW offer types
swoffers = list(filter(lambda x: x[0:2] == 'sw', offername_list))
pkoffers = list(filter(lambda x: x[0:2] != 'sw', offername_list))
filtered_offername_list = swoffers

shutdownform = '<form action="shutdown" method="post"><input type="submit" value="Shutdown" /></form>'
shutdownpage = '<html><body><center><h1>Successfully Shut down</h1></center></body></html>'
toggleSWform = '<form action="toggleSW" method="post"><input type="submit" value="Toggle non-segwit" /></form>'
refresh_orderbook_form = '<form action="refreshorderbook" method="post"><input type="submit" value="Check for timed-out counterparties" /></form>'
sorted_units = ('BTC', 'mBTC', '&#956;BTC', 'satoshi')
unit_to_power = {'BTC': 8, 'mBTC': 5, '&#956;BTC': 2, 'satoshi': 0}
sorted_rel_units = ('%', '&#8241;', 'ppm')
rel_unit_to_factor = {'%': 100, '&#8241;': 1e4, 'ppm': 1e6}


def calc_depth_data(db, value):
    pass


def get_graph_html(fig):
    imbuf = io.BytesIO()
    fig.savefig(imbuf, format='png')
    b64 = base64.b64encode(imbuf.getvalue()).decode('utf-8')
    return '<img src="data:image/png;base64,' + b64 + '" />'


# callback functions for displaying order data
def do_nothing(arg, order, btc_unit, rel_unit):
    return arg


def ordertype_display(ordertype, order, btc_unit, rel_unit):
    ordertypes = {'swabsoffer': 'SW Absolute Fee', 'swreloffer': 'SW Relative Fee',
                  'absoffer': 'Absolute Fee', 'reloffer': 'Relative Fee'}
    return ordertypes[ordertype]


def cjfee_display(cjfee, order, btc_unit, rel_unit):
    if order['ordertype'] in ['absoffer', 'swabsoffer']:
        return satoshi_to_unit(cjfee, order, btc_unit, rel_unit)
    elif order['ordertype'] in ['reloffer', 'swreloffer']:
        return str(Decimal(cjfee) * rel_unit_to_factor[rel_unit]) + rel_unit


def satoshi_to_unit(sat, order, btc_unit, rel_unit):
    power = unit_to_power[btc_unit]
    return ("%." + str(power) + "f") % float(
        Decimal(sat) / Decimal(10 ** power))


def order_str(s, order, btc_unit, rel_unit):
    return str(s)


def create_table_heading(btc_unit, rel_unit):
    col = '  <th>{1}</th>\n'  # .format(field,label)
    tableheading = '<table class="tftable sortable" border="1">\n <tr>' + ''.join(
            [
                col.format('ordertype', 'Type'), col.format(
                    'counterparty', 'Counterparty'),
                col.format('oid', 'Order ID'),
                col.format('cjfee', 'Fee'), col.format(
                    'txfee', 'Miner Fee Contribution / ' + btc_unit),
                col.format(
                        'minsize', 'Minimum Size / ' + btc_unit), col.format(
                    'maxsize', 'Maximum Size / ' + btc_unit)
            ]) + ' </tr>'
    return tableheading


def create_choose_units_form(selected_btc, selected_rel):
    choose_units_form = (
        '<form method="get" action="">' +
        '<select name="btcunit" onchange="this.form.submit();">' +
        ''.join(('<option>' + u + ' </option>' for u in sorted_units)) +
        '</select><select name="relunit" onchange="this.form.submit();">' +
        ''.join(('<option>' + u + ' </option>' for u in sorted_rel_units)) +
        '</select></form>')
    choose_units_form = choose_units_form.replace(
            '<option>' + selected_btc,
            '<option selected="selected">' + selected_btc)
    choose_units_form = choose_units_form.replace(
            '<option>' + selected_rel,
            '<option selected="selected">' + selected_rel)
    return choose_units_form


class OrderbookPageRequestHeader(http.server.SimpleHTTPRequestHandler):
    def __init__(self, request, client_address, base_server):
        self.taker = base_server.taker
        self.base_server = base_server
        http.server.SimpleHTTPRequestHandler.__init__(
                self, request, client_address, base_server)

    def create_orderbook_obj(self):
        try:
            self.taker.dblock.acquire(True)
            rows = self.taker.db.execute('SELECT * FROM orderbook;').fetchall()
        finally:
            self.taker.dblock.release()
        if not rows:
            return []

        result = []
        for row in rows:
            o = dict(row)
            if 'cjfee' in o:
                o['cjfee'] = int(o['cjfee']) if o['ordertype']\
                             == 'swabsoffer' else str(Decimal(o['cjfee']))
            result.append(o)
        return result

    def create_depth_chart(self, cj_amount, args=None):
        if 'matplotlib' not in sys.modules:
            return 'matplotlib not installed, charts not available'

        if args is None:
            args = {}
        try:
            self.taker.dblock.acquire(True)
            rows = self.taker.db.execute('SELECT * FROM orderbook;').fetchall()
        finally:
            self.taker.dblock.release()
        sqlorders = [o for o in rows if o["ordertype"] in filtered_offername_list]
        orderfees = sorted([calc_cj_fee(o['ordertype'], o['cjfee'], cj_amount) / 1e8
                            for o in sqlorders
                            if o['minsize'] <= cj_amount <= o[
                                'maxsize']])

        if len(orderfees) == 0:
            return 'No orders at amount ' + str(cj_amount / 1e8)
        fig = plt.figure()
        scale = args.get("scale")
        if (scale is not None) and (scale[0] == "log"):
            orderfees = [float(fee) for fee in orderfees]
            if orderfees[0] > 0:
                ratio = orderfees[-1] / orderfees[0]
                step = ratio ** 0.0333  # 1/30
                bins = [orderfees[0] * (step ** i) for i in range(30)]
            else:
                ratio = orderfees[-1] / 1e-8  # single satoshi placeholder
                step = ratio ** 0.0333  # 1/30
                bins = [1e-8 * (step ** i) for i in range(30)]
                bins[0] = orderfees[0]  # replace placeholder
            plt.xscale('log')
        else:
            bins = 30
        if len(orderfees) == 1:  # these days we have liquidity, but just in case...
            plt.hist(orderfees, bins, rwidth=0.8, range=(0, orderfees[0] * 2))
        else:
            plt.hist(orderfees, bins, rwidth=0.8)
        plt.grid()
        plt.title('CoinJoin Orderbook Depth Chart for amount=' + str(cj_amount /
                                                                     1e8) + 'btc')
        plt.xlabel('CoinJoin Fee / btc')
        plt.ylabel('Frequency')
        return get_graph_html(fig)

    def create_size_histogram(self, args):
        if 'matplotlib' not in sys.modules:
            return 'matplotlib not installed, charts not available'

        try:
            self.taker.dblock.acquire(True)
            rows = self.taker.db.execute('SELECT maxsize, ordertype FROM orderbook;').fetchall()
        finally:
            self.taker.dblock.release()
        rows = [o for o in rows if o["ordertype"] in filtered_offername_list]
        ordersizes = sorted([r['maxsize'] / 1e8 for r in rows])

        fig = plt.figure()
        scale = args.get("scale")
        if (scale is not None) and (scale[0] == "log"):
            ratio = ordersizes[-1] / ordersizes[0]
            step = ratio ** 0.0333  # 1/30
            bins = [ordersizes[0] * (step ** i) for i in range(30)]
        else:
            bins = 30
        plt.hist(ordersizes, bins, histtype='bar', rwidth=0.8)
        if bins != 30:
            fig.axes[0].set_xscale('log')
        plt.grid()
        plt.xlabel('Order sizes / btc')
        plt.ylabel('Frequency')
        return get_graph_html(fig) + ("<br/><a href='?scale=log'>log scale</a>" if
                                      bins == 30 else "<br/><a href='?'>linear</a>")

    def create_orderbook_table(self, btc_unit, rel_unit):
        result = ''
        try:
            self.taker.dblock.acquire(True)
            rows = self.taker.db.execute('SELECT * FROM orderbook;').fetchall()
        finally:
            self.taker.dblock.release()
        if not rows:
            return 0, result
        #print("len rows before filter: " + str(len(rows)))
        rows = [o for o in rows if o["ordertype"] in filtered_offername_list]
        order_keys_display = (('ordertype', ordertype_display),
                              ('counterparty', do_nothing), ('oid', order_str),
                              ('cjfee', cjfee_display), ('txfee', satoshi_to_unit),
                              ('minsize', satoshi_to_unit),
                              ('maxsize', satoshi_to_unit))

        # somewhat complex sorting to sort by cjfee but with swabsoffers on top

        def orderby_cmp(x, y):
            if x['ordertype'] == y['ordertype']:
                return cmp(Decimal(x['cjfee']), Decimal(y['cjfee']))
            return cmp(offername_list.index(x['ordertype']),
                       offername_list.index(y['ordertype']))

        for o in sorted(rows, key=cmp_to_key(orderby_cmp)):
            result += ' <tr>\n'
            for key, displayer in order_keys_display:
                result += '  <td>' + displayer(o[key], o, btc_unit,
                                               rel_unit) + '</td>\n'
            result += ' </tr>\n'
        return len(rows), result

    def get_counterparty_count(self):
        try:
            self.taker.dblock.acquire(True)
            counterparties = self.taker.db.execute(
                'SELECT DISTINCT counterparty FROM orderbook WHERE ordertype=? OR ordertype=?;',
                filtered_offername_list).fetchall()
        finally:
            self.taker.dblock.release()
        return str(len(counterparties))

    def do_GET(self):
        # http.server.SimpleHTTPRequestHandler.do_GET(self)
        # print 'httpd received ' + self.path + ' request'
        self.path, query = self.path.split('?', 1) if '?' in self.path else (
            self.path, '')
        args = parse_qs(query)
        pages = ['/', '/ordersize', '/depth', '/orderbook.json']
        if self.path not in pages:
            return
        fd = open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
            'orderbook.html'), 'r')
        orderbook_fmt = fd.read()
        fd.close()
        alert_msg = ''
        if jm_single().joinmarket_alert[0]:
            alert_msg = '<br />JoinMarket Alert Message:<br />' + \
                        jm_single().joinmarket_alert[0]
        if self.path == '/':
            btc_unit = args['btcunit'][
                0] if 'btcunit' in args else sorted_units[0]
            rel_unit = args['relunit'][
                0] if 'relunit' in args else sorted_rel_units[0]
            if btc_unit not in sorted_units:
                btc_unit = sorted_units[0]
            if rel_unit not in sorted_rel_units:
                rel_unit = sorted_rel_units[0]
            ordercount, ordertable = self.create_orderbook_table(
                    btc_unit, rel_unit)
            choose_units_form = create_choose_units_form(btc_unit, rel_unit)
            table_heading = create_table_heading(btc_unit, rel_unit)
            replacements = {
                'PAGETITLE': 'JoinMarket Browser Interface',
                'MAINHEADING': 'JoinMarket Orderbook',
                'SECONDHEADING':
                    (str(ordercount) + ' orders found by ' +
                     self.get_counterparty_count() + ' counterparties' + alert_msg),
                'MAINBODY': (
                    toggleSWform + refresh_orderbook_form + choose_units_form +
                    table_heading + ordertable + '</table>\n')
            }
        elif self.path == '/ordersize':
            replacements = {
                'PAGETITLE': 'JoinMarket Browser Interface',
                'MAINHEADING': 'Order Sizes',
                'SECONDHEADING': 'Order Size Histogram' + alert_msg,
                'MAINBODY': self.create_size_histogram(args)
            }
        elif self.path.startswith('/depth'):
            # if self.path[6] == '?':
            #	quantity =
            cj_amounts = [10 ** cja for cja in range(4, 12, 1)]
            mainbody = [self.create_depth_chart(cja, args) \
                        for cja in cj_amounts] + \
                       ["<br/><a href='?'>linear</a>" if args.get("scale") \
                            else "<br/><a href='?scale=log'>log scale</a>"]
            replacements = {
                'PAGETITLE': 'JoinMarket Browser Interface',
                'MAINHEADING': 'Depth Chart',
                'SECONDHEADING': 'Orderbook Depth' + alert_msg,
                'MAINBODY': '<br />'.join(mainbody)
            }
        elif self.path == '/orderbook.json':
            replacements = {}
            orderbook_fmt = json.dumps(self.create_orderbook_obj())
        orderbook_page = orderbook_fmt
        for key, rep in iteritems(replacements):
            orderbook_page = orderbook_page.replace(key, rep)
        self.send_response(200)
        if self.path.endswith('.json'):
            self.send_header('Content-Type', 'application/json')
        else:
            self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', len(orderbook_page))
        self.end_headers()
        self.wfile.write(orderbook_page.encode('utf-8'))

    def do_POST(self):
        global filtered_offername_list
        pages = ['/shutdown', '/refreshorderbook', '/toggleSW']
        if self.path not in pages:
            return
        if self.path == '/shutdown':
            self.taker.msgchan.shutdown()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', len(shutdownpage))
            self.end_headers()
            self.wfile.write(shutdownpage)
            self.base_server.__shutdown_request = True
        elif self.path == '/refreshorderbook':
            self.taker.msgchan.request_orderbook()
            time.sleep(5)
            self.path = '/'
            self.do_GET()
        elif self.path == '/toggleSW':
            if filtered_offername_list == swoffers:
                filtered_offername_list = pkoffers
            else:
                filtered_offername_list = swoffers
            self.path = '/'
            self.do_GET()

class HTTPDThread(threading.Thread):
    def __init__(self, taker, hostport):
        threading.Thread.__init__(self, name='HTTPDThread')
        self.daemon = True
        self.taker = taker
        self.hostport = hostport

    def run(self):
        # hostport = ('localhost', 62601)
        try:
            httpd = http.server.HTTPServer(self.hostport,
                                          OrderbookPageRequestHeader)
        except Exception as e:
            print("Failed to start HTTP server: " + str(e))
            os._exit(EXIT_FAILURE)
        httpd.taker = self.taker
        print('\nstarted http server, visit http://{0}:{1}/\n'.format(
                *self.hostport))
        httpd.serve_forever()


class ObBasic(OrderbookWatch):
    """Dummy orderbook watch class
    with hooks for triggering orderbook request"""
    def __init__(self, msgchan, hostport):
        self.hostport = hostport
        self.set_msgchan(msgchan)

    def on_welcome(self):
        """TODO: It will probably be a bit
        simpler, and more consistent, to use
        a twisted http server here instead
        of a thread."""
        HTTPDThread(self, self.hostport).start()
        self.request_orderbook()

    def request_orderbook(self):
        self.msgchan.request_orderbook()

class ObIRCMessageChannel(IRCMessageChannel):
    """A customisation of the message channel
    to allow receipt of privmsgs without the
    verification hooks in client-daemon communication."""
    def on_privmsg(self, nick, message):
        if len(message) < 2:
            return
        
        if message[0] != COMMAND_PREFIX:
            log.debug('message not a cmd')
            return
        cmd_string = message[1:].split(' ')[0]
        if cmd_string not in offername_list:
            log.debug('non-offer ignored')
            return
        #Ignore sigs (TODO better to include check)
        sig = message[1:].split(' ')[-2:]
        #reconstruct original message without cmd pref
        rawmessage = ' '.join(message[1:].split(' ')[:-2])
        for command in rawmessage.split(COMMAND_PREFIX):
            _chunks = command.split(" ")
            try:
                self.check_for_orders(nick, _chunks)
            except:
                pass

        
def get_dummy_nick():
    """In Joinmarket-CS nick creation is negotiated
    between client and server/daemon so as to allow
    client to sign for messages; here we only ever publish
    an orderbook request, so no such need, but for better
    privacy, a conformant nick is created based on a random
    pseudo-pubkey."""
    nick_pkh_raw = hashlib.sha256(os.urandom(10)).digest()[:NICK_HASH_LENGTH]
    nick_pkh = btc.base58.encode(nick_pkh_raw)
    #right pad to maximum possible; b58 is not fixed length.
    #Use 'O' as one of the 4 not included chars in base58.
    nick_pkh += 'O' * (NICK_MAX_ENCODED - len(nick_pkh))
    #The constructed length will be 1 + 1 + NICK_MAX_ENCODED
    nick = JOINMARKET_NICK_HEADER + str(JM_VERSION) + nick_pkh
    jm_single().nickname = nick
    return nick

def main():
    parser = OptionParser(
            usage='usage: %prog [options]',
            description='Runs a webservice which shows the orderbook.')
    add_base_options(parser)
    parser.add_option('-H',
                      '--host',
                      action='store',
                      type='string',
                      dest='host',
                      default='localhost',
                      help='hostname or IP to bind to, default=localhost')
    parser.add_option('-p',
                      '--port',
                      action='store',
                      type='int',
                      dest='port',
                      help='port to listen on, default=62601',
                      default=62601)
    (options, args) = parser.parse_args()
    load_program_config(config_path=options.datadir)
    hostport = (options.host, options.port)
    mcs = [ObIRCMessageChannel(c) for c in get_irc_mchannels()]
    mcc = MessageChannelCollection(mcs)
    mcc.set_nick(get_dummy_nick())
    taker = ObBasic(mcc, hostport)
    log.info("Starting ob-watcher")
    mcc.run()



if __name__ == "__main__":
    main()
    reactor.run()
    print('done')
