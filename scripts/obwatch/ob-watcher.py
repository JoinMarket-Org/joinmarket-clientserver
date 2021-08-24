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
from datetime import datetime, timedelta

if sys.version_info < (3, 7):
    print("ERROR: this script requires at least python 3.7")
    exit(1)

from jmbase.support import EXIT_FAILURE
from jmbase import bintohex
from jmclient import FidelityBondMixin, get_interest_rate
from jmclient.fidelity_bond import FidelityBondProof

import sybil_attack_calculations as sybil

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
     get_mchannels, add_base_options
from jmdaemon import OrderbookWatch, MessageChannelCollection, IRCMessageChannel
#TODO this is only for base58, find a solution for a client without jmbitcoin
import jmbitcoin as btc
from jmdaemon.protocol import *

#Initial state: allow only SW offer types
sw0offers = list(filter(lambda x: x[0:3] == 'sw0', offername_list))
swoffers = list(filter(lambda x: x[0:3] == 'swa' or x[0:3] == 'swr', offername_list))
filtered_offername_list = sw0offers

rotateObform = '<form action="rotateOb" method="post"><input type="submit" value="Rotate orderbooks"/></form>'
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
    ordertypes = {'sw0absoffer': 'Native SW Absolute Fee', 'sw0reloffer': 'Native SW Relative Fee',
                  'swabsoffer': 'SW Absolute Fee', 'swreloffer': 'SW Relative Fee'}
    return ordertypes[ordertype]


def cjfee_display(cjfee, order, btc_unit, rel_unit):
    if order['ordertype'] in ['swabsoffer', 'sw0absoffer']:
        return satoshi_to_unit(cjfee, order, btc_unit, rel_unit)
    elif order['ordertype'] in ['reloffer', 'swreloffer', 'sw0reloffer']:
        return str(Decimal(cjfee) * Decimal(rel_unit_to_factor[rel_unit])) + rel_unit


def satoshi_to_unit_power(sat, power):
    return ("%." + str(power) + "f") % float(
        Decimal(sat) / Decimal(10 ** power))

def satoshi_to_unit(sat, order, btc_unit, rel_unit):
    return satoshi_to_unit_power(sat, unit_to_power[btc_unit])

def order_str(s, order, btc_unit, rel_unit):
    return str(s)


def create_offerbook_table_heading(btc_unit, rel_unit):
    col = '  <th>{1}</th>\n'  # .format(field,label)
    tableheading = '<table class="tftable sortable" border="1">\n <tr>' + ''.join(
            [
                col.format('ordertype', 'Type'),
                col.format('counterparty', 'Counterparty'),
                col.format('oid', 'Order ID'),
                col.format('cjfee', 'Fee'),
                col.format('txfee', 'Miner Fee Contribution / ' + btc_unit),
                col.format('minsize', 'Minimum Size / ' + btc_unit),
                col.format('maxsize', 'Maximum Size / ' + btc_unit),
                col.format('bondvalue', 'Bond value / ' + btc_unit + '&#xb2;')
            ]) + ' </tr>'
    return tableheading

def create_bonds_table_heading(btc_unit):
    tableheading = ('<table class="tftable sortable" border="1"><tr>'
        + '<th>Counterparty</th>'
        + '<th>UTXO</th>'
        + '<th>Bond value / ' + btc_unit + '&#xb2;</th>'
        + '<th>Locktime</th>'
        + '<th>Locked coins / ' + btc_unit + '</th>'
        + '<th>Confirmation time</th>'
        + '<th>Signature expiry height</th>'
        + '<th>Redeem script</th>'
        + '</tr>'
    )
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

def get_fidelity_bond_data(taker):
    with taker.dblock:
        fbonds = taker.db.execute("SELECT * FROM fidelitybonds;").fetchall()

    blocks = jm_single().bc_interface.get_current_block_height()
    mediantime = jm_single().bc_interface.get_best_block_median_time()
    interest_rate = get_interest_rate()

    bond_utxo_set = set()
    fidelity_bond_data = []
    bond_outpoint_conf_times = []
    fidelity_bond_values = []
    for fb in fbonds:
        try:
            parsed_bond = FidelityBondProof.parse_and_verify_proof_msg(fb["counterparty"],
                fb["takernick"], fb["proof"])
        except ValueError:
            continue
        bond_utxo_data = FidelityBondMixin.get_validated_timelocked_fidelity_bond_utxo(
            parsed_bond.utxo, parsed_bond.utxo_pub, parsed_bond.locktime, parsed_bond.cert_expiry,
            blocks)
        if bond_utxo_data == None:
            continue
        #check for duplicated utxos i.e. two or more makers using the same UTXO
        # which is obviously not allowed, a fidelity bond must only be usable by one maker nick
        utxo_str = parsed_bond.utxo[0] + b":" + str(parsed_bond.utxo[1]).encode("ascii")
        if utxo_str in bond_utxo_set:
            continue
        bond_utxo_set.add(utxo_str)

        fidelity_bond_data.append((parsed_bond, bond_utxo_data))
        conf_time = jm_single().bc_interface.get_block_time(
            jm_single().bc_interface.get_block_hash(
                blocks - bond_utxo_data["confirms"] + 1
            )
        )
        bond_outpoint_conf_times.append(conf_time)

        bond_value = FidelityBondMixin.calculate_timelocked_fidelity_bond_value(
            bond_utxo_data["value"],
            conf_time,
            parsed_bond.locktime,
            mediantime,
            interest_rate)
        fidelity_bond_values.append(bond_value)
    return (fidelity_bond_data, fidelity_bond_values, bond_outpoint_conf_times)

class OrderbookPageRequestHeader(http.server.SimpleHTTPRequestHandler):
    def __init__(self, request, client_address, base_server):
        self.taker = base_server.taker
        self.base_server = base_server
        http.server.SimpleHTTPRequestHandler.__init__(
                self, request, client_address, base_server,
                directory=os.path.dirname(os.path.realpath(__file__)))

    def create_orderbook_obj(self):
        with self.taker.dblock:
            rows = self.taker.db.execute('SELECT * FROM orderbook;').fetchall()
            fbonds = self.taker.db.execute("SELECT * FROM fidelitybonds;").fetchall()
        if not rows or not fbonds:
            return []

        fidelitybonds = []
        if jm_single().bc_interface != None:
            (fidelity_bond_data, fidelity_bond_values, bond_outpoint_conf_times) =\
                get_fidelity_bond_data(self.taker)
            fidelity_bond_values_dict = dict([(bond_data.maker_nick, bond_value)
                for (bond_data, _), bond_value in zip(fidelity_bond_data, fidelity_bond_values)])
            for ((parsed_bond, bond_utxo_data), fidelity_bond_value, bond_outpoint_conf_time)\
                    in zip(fidelity_bond_data, fidelity_bond_values, bond_outpoint_conf_times):
                fb = {
                    "counterparty": parsed_bond.maker_nick,
                    "utxo": {"txid": bintohex(parsed_bond.utxo[0]),
                        "vout": parsed_bond.utxo[1]},
                    "bond_value": fidelity_bond_value,
                    "locktime": parsed_bond.locktime,
                    "amount":  bond_utxo_data["value"],
                    "address": bond_utxo_data["address"],
                    "utxo_confirmations": bond_utxo_data["confirms"],
                    "utxo_confirmation_timestamp": bond_outpoint_conf_time,
                    "utxo_pub": bintohex(parsed_bond.utxo_pub),
                    "cert_expiry": parsed_bond.cert_expiry
                }
                fidelitybonds.append(fb)
        else:
            fidelity_bond_values_dict = {}

        offers = []
        for row in rows:
            o = dict(row)
            if 'cjfee' in o:
                if o['ordertype'] == 'swabsoffer'\
                   or o['ordertype'] == 'sw0absoffer':
                    o['cjfee'] = int(o['cjfee'])
                else:
                    o['cjfee'] = str(Decimal(o['cjfee']))
            o["fidelity_bond_value"] = fidelity_bond_values_dict.get(o["counterparty"], 0)
            offers.append(o)

        return {"offers": offers, "fidelitybonds": fidelitybonds}

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

    def create_fidelity_bond_table(self, btc_unit):
        if jm_single().bc_interface == None:
            with self.taker.dblock:
                fbonds = self.taker.db.execute("SELECT * FROM fidelitybonds;").fetchall()
            fidelity_bond_data = []
            for fb in fbonds:
                try:
                    proof = FidelityBondProof.parse_and_verify_proof_msg(
                        fb["counterparty"],
                        fb["takernick"],
                        fb["proof"])
                except ValueError:
                    proof = None
                fidelity_bond_data.append((proof, None))
            fidelity_bond_values = [-1]*len(fidelity_bond_data) #-1 means no data
            bond_outpoint_conf_times = [-1]*len(fidelity_bond_data)
            total_btc_committed_str = "unknown"
        else:
            (fidelity_bond_data, fidelity_bond_values, bond_outpoint_conf_times) =\
                get_fidelity_bond_data(self.taker)
            total_btc_committed_str = satoshi_to_unit(
                sum([utxo_data["value"] for _, utxo_data in fidelity_bond_data]),
                None, btc_unit, 0)

        RETARGET_INTERVAL = 2016
        elem = lambda e: "<td>" + e + "</td>"
        bondtable = ""
        for (bond_data, utxo_data), bond_value, conf_time in zip(
                fidelity_bond_data, fidelity_bond_values, bond_outpoint_conf_times):

            if bond_value == -1 or conf_time == -1 or utxo_data == None:
                bond_value_str = "No data"
                conf_time_str = "No data"
                utxo_value_str = "No data"
            else:
                bond_value_str = satoshi_to_unit_power(bond_value, 2*unit_to_power[btc_unit])
                conf_time_str = str(datetime.utcfromtimestamp(0) + timedelta(seconds=conf_time))
                utxo_value_str = satoshi_to_unit(utxo_data["value"], None, btc_unit, 0)
            bondtable += ("<tr>"
                + elem(bond_data.maker_nick)
                + elem(bintohex(bond_data.utxo[0]) + ":" + str(bond_data.utxo[1]))
                + elem(bond_value_str)
                + elem((datetime.utcfromtimestamp(0) + timedelta(seconds=bond_data.locktime)).strftime("%Y-%m-%d"))
                + elem(utxo_value_str)
                + elem(conf_time_str)
                + elem(str(bond_data.cert_expiry*RETARGET_INTERVAL))
                + elem(bintohex(btc.mk_freeze_script(bond_data.utxo_pub,
                    bond_data.locktime)))
                + "</tr>"
            )

        heading2 = (str(len(fidelity_bond_data)) + " fidelity bonds found with "
            + total_btc_committed_str + " " + btc_unit
            + " total locked up")
        choose_units_form = (
            '<form method="get" action="">' +
            '<select name="btcunit" onchange="this.form.submit();">' +
            ''.join(('<option>' + u + ' </option>' for u in sorted_units)) +
            '</select></form>')
        choose_units_form = choose_units_form.replace(
                '<option>' + btc_unit,
                '<option selected="selected">' + btc_unit)

        decodescript_tip = ("<br/>Tip: try running the RPC <code>decodescript "
            + "&lt;redeemscript&gt;</code> as proof that the fidelity bond address matches the "
            + "locktime.<br/>Also run <code>gettxout &lt;utxo_txid&gt; &lt;utxo_vout&gt;</code> "
            + "as proof that the fidelity bond UTXO is real.")

        return (heading2,
            choose_units_form + create_bonds_table_heading(btc_unit) + bondtable + "</table>"
            + decodescript_tip)

    def create_sybil_resistance_page(self, btc_unit):
        if jm_single().bc_interface == None:
            return "", "Calculations unavailable, requires configured bitcoin node."

        (fidelity_bond_data, fidelity_bond_values, bond_outpoint_conf_times) =\
            get_fidelity_bond_data(self.taker)

        choose_units_form = (
            '<form method="get" action="">' +
            '<select name="btcunit" onchange="this.form.submit();">' +
            ''.join(('<option>' + u + ' </option>' for u in sorted_units)) +
            '</select></form>')
        choose_units_form = choose_units_form.replace(
                '<option>' + btc_unit,
                '<option selected="selected">' + btc_unit)
        mainbody = choose_units_form

        honest_weight = sum(fidelity_bond_values)
        mainbody += ("Assuming the makers in the offerbook right now are not sybil attackers, "
            + "how much would a sybil attacker starting now have to sacrifice to succeed in their"
            + " attack with 95% probability. Honest weight="
            + satoshi_to_unit_power(honest_weight, 2*unit_to_power[btc_unit]) + " " + btc_unit
            + "&#xb2;<br/>Also assumes that takers are not price-sensitive and that their max "
            + "coinjoin fee is configured high enough that they dont exclude any makers.")
        heading2 = "Sybil attacks from external enemies."

        mainbody += ('<table class="tftable" border="1"><tr>'
            + '<th>Maker count</th>'
            + '<th>6month locked coins / ' + btc_unit + '</th>'
            + '<th>1y locked coins / ' + btc_unit + '</th>'
            + '<th>2y locked coins / ' + btc_unit + '</th>'
            + '<th>5y locked coins / ' + btc_unit + '</th>'
            + '<th>10y locked coins / ' + btc_unit + '</th>'
            + '<th>Required burned coins / ' + btc_unit + '</th>'
            + '</tr>'
        )

        timelocks = [0.5, 1.0, 2.0, 5.0, 10.0, None]
        interest_rate = get_interest_rate()
        for makercount, unit_success_sybil_weight in sybil.successful_attack_95pc_sybil_weight.items():
            success_sybil_weight = unit_success_sybil_weight * honest_weight
            row = "<tr><td>" + str(makercount) + "</td>"
            for timelock in timelocks:
                if timelock != None:
                    coins_per_sybil = sybil.weight_to_locked_coins(success_sybil_weight,
                        interest_rate, timelock)
                else:
                    coins_per_sybil = sybil.weight_to_burned_coins(success_sybil_weight)
                row += ("<td>" + satoshi_to_unit(coins_per_sybil*makercount, None, btc_unit, 0)
                    + "</td>")
            row += "</tr>"
            mainbody += row
        mainbody += "</table>"

        mainbody += ("<h2>Sybil attacks from enemies within</h2>Assume a sybil attack is ongoing"
            + " right now and that the counterparties with the most valuable fidelity bonds are "
            + " actually controlled by the same entity. Then, what is the probability of a "
            + " successful sybil attack for a given makercount, and what is the fidelity bond "
            + " value being foregone by not putting all bitcoins into just one maker.")
        mainbody += ('<table class="tftable" border="1"><tr>'
            + '<th>Maker count</th>'
            + '<th>Success probability</th>'
            + '<th>Foregone value / ' + btc_unit + '&#xb2;</th>'
            + '</tr>'
        )

        #limited because calculation is slow, so this avoids server being too slow to respond
        MAX_MAKER_COUNT_INTERNAL = 10
        weights = sorted(fidelity_bond_values)[::-1]
        for makercount in range(1, MAX_MAKER_COUNT_INTERNAL+1):
            makercount_str = (str(makercount) + " - " + str(MAX_MAKER_COUNT_INTERNAL)
                if makercount == len(fidelity_bond_data) and len(fidelity_bond_data) !=
                MAX_MAKER_COUNT_INTERNAL else str(makercount))
            success_prob = sybil.calculate_top_makers_sybil_attack_success_probability(weights,
                makercount)
            total_sybil_weight = sum(weights[:makercount])
            sacrificed_values = [sybil.weight_to_burned_coins(w) for w in weights[:makercount]]
            foregone_value = (sybil.coins_burned_to_weight(sum(sacrificed_values))
                - total_sybil_weight)
            mainbody += ("<tr><td>" + makercount_str + "</td><td>" + str(round(success_prob*100.0, 5))
                + "%</td><td>" + satoshi_to_unit_power(foregone_value, 2*unit_to_power[btc_unit])
                + "</td></tr>")
            if makercount == len(weights):
                break
        mainbody += "</table>"

        return heading2, mainbody

    def create_orderbook_table(self, btc_unit, rel_unit):
        result = ''
        try:
            self.taker.dblock.acquire(True)
            rows = self.taker.db.execute('SELECT * FROM orderbook;').fetchall()
        finally:
            self.taker.dblock.release()
        if not rows:
            return 0, result
        rows = [o for o in rows if o["ordertype"] in filtered_offername_list]

        if jm_single().bc_interface == None:
            for row in rows:
                row["bondvalue"] = "No data"
        else:
            blocks = jm_single().bc_interface.get_current_block_height()
            mediantime = jm_single().bc_interface.get_best_block_median_time()
            interest_rate = get_interest_rate()
            for row in rows:
                with self.taker.dblock:
                    fbond_data = self.taker.db.execute(
                        "SELECT * FROM fidelitybonds WHERE counterparty=?;", (row["counterparty"],)
                    ).fetchall()
                if len(fbond_data) == 0:
                    row["bondvalue"] = "0"
                    continue
                else:
                    try:
                        parsed_bond = FidelityBondProof.parse_and_verify_proof_msg(
                            fbond_data[0]["counterparty"],
                            fbond_data[0]["takernick"],
                            fbond_data[0]["proof"]
                        )
                    except ValueError:
                        row["bondvalue"] = "0"
                        continue
                    utxo_data = FidelityBondMixin.get_validated_timelocked_fidelity_bond_utxo(
                        parsed_bond.utxo, parsed_bond.utxo_pub, parsed_bond.locktime,
                        parsed_bond.cert_expiry, blocks)
                    if utxo_data == None:
                        row["bondvalue"] = "0"
                        continue
                    bond_value = FidelityBondMixin.calculate_timelocked_fidelity_bond_value(
                        utxo_data["value"],
                        jm_single().bc_interface.get_block_time(
                            jm_single().bc_interface.get_block_hash(
                                blocks - utxo_data["confirms"] + 1
                            )
                        ),
                        parsed_bond.locktime,
                        mediantime,
                        interest_rate)
                    row["bondvalue"] = satoshi_to_unit_power(bond_value, 2*unit_to_power[btc_unit])

        order_keys_display = (('ordertype', ordertype_display),
                              ('counterparty', do_nothing),
                              ('oid', order_str),
                              ('cjfee', cjfee_display),
                              ('txfee', satoshi_to_unit),
                              ('minsize', satoshi_to_unit),
                              ('maxsize', satoshi_to_unit),
                              ('bondvalue', do_nothing))

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
        # print('httpd received ' + self.path + ' request')
        self.path, query = self.path.split('?', 1) if '?' in self.path else (
            self.path, '')
        args = parse_qs(query)
        pages = ['/', '/fidelitybonds', '/ordersize', '/depth', '/sybilresistance',
            '/orderbook.json']
        static_files = {'/vendor/sorttable.js', '/vendor/bootstrap.min.css', '/vendor/jquery-3.5.1.slim.min.js'}
        if self.path in static_files or self.path not in pages:
            return super().do_GET()
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
            table_heading = create_offerbook_table_heading(btc_unit, rel_unit)
            replacements = {
                'PAGETITLE': 'JoinMarket Browser Interface',
                'MAINHEADING': 'JoinMarket Orderbook',
                'SECONDHEADING':
                    (str(ordercount) + ' orders found by ' +
                     self.get_counterparty_count() + ' counterparties' + alert_msg),
                'MAINBODY': (
                    rotateObform + refresh_orderbook_form + choose_units_form +
                    table_heading + ordertable + '</table>\n')
            }
        elif self.path == '/fidelitybonds':
            btc_unit = args['btcunit'][0] if 'btcunit' in args else sorted_units[0]
            if btc_unit not in sorted_units:
                btc_unit = sorted_units[0]
            heading2, mainbody = self.create_fidelity_bond_table(btc_unit)

            replacements = {
                'PAGETITLE': 'JoinMarket Browser Interface',
                'MAINHEADING': 'Fidelity Bonds',
                'SECONDHEADING': heading2,
                'MAINBODY': mainbody
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
        elif self.path == '/sybilresistance':
            btc_unit = args['btcunit'][0] if 'btcunit' in args else sorted_units[0]
            if btc_unit not in sorted_units:
                btc_unit = sorted_units[0]
            heading2, mainbody = self.create_sybil_resistance_page(btc_unit)
            replacements = {
                'PAGETITLE': 'JoinMarket Browser Interface',
                'MAINHEADING': 'Resistance to Sybil Attacks from Fidelity Bonds',
                'SECONDHEADING': heading2,
                'MAINBODY': mainbody
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
        pages = ['/refreshorderbook', '/rotateOb']
        if self.path not in pages:
            return
        if self.path == '/refreshorderbook':
            self.taker.msgchan.request_orderbook()
            time.sleep(5)
            self.path = '/'
            self.do_GET()
        elif self.path == '/rotateOb':
            if filtered_offername_list == sw0offers:
                log.debug('Showing nested segwit orderbook')
                filtered_offername_list = swoffers
            elif filtered_offername_list == swoffers:
                log.debug('Showing native segwit orderbook')
                filtered_offername_list = sw0offers
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
        # in client-server, this is passed by client
        # in INIT message. Here, we have no Joinmarket client,
        # but we have access to the client config in this script:
        self.dust_threshold = jm_single().DUST_THRESHOLD

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
                self.check_for_fidelity_bond(nick, _chunks)
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
    mcs = [ObIRCMessageChannel(c) for c in get_mchannels()]
    mcc = MessageChannelCollection(mcs)
    mcc.set_nick(get_dummy_nick())
    taker = ObBasic(mcc, hostport)
    log.info("Starting ob-watcher")
    mcc.run()



if __name__ == "__main__":
    main()
    reactor.run()
    print('done')
