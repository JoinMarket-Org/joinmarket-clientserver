#! /usr/bin/env python

import sqlite3
import sys
import threading
from decimal import InvalidOperation, Decimal
from numbers import Integral

from jmdaemon.protocol import JM_VERSION
from jmdaemon import fidelity_bond_sanity_check
from jmbase.support import dict_factory, get_log, joinmarket_alert
log = get_log()


class JMTakerError(Exception):
    pass

class OrderbookWatch(object):

    def set_msgchan(self, msgchan):
        self.msgchan = msgchan
        self.msgchan.register_orderbookwatch_callbacks(self.on_order_seen,
                               self.on_order_cancel, self.on_fidelity_bond_seen)
        self.msgchan.register_channel_callbacks(
            self.on_welcome, self.on_set_topic, None, self.on_disconnect,
            self.on_nick_leave, None)

        self.dblock = threading.Lock()
        con = sqlite3.connect(":memory:", check_same_thread=False)
        con.row_factory = dict_factory
        self.db = con.cursor()
        try:
            self.dblock.acquire(True)
            self.db.execute("CREATE TABLE orderbook(counterparty TEXT, "
                            "oid INTEGER, ordertype TEXT, minsize INTEGER, "
                            "maxsize INTEGER, txfee INTEGER, cjfee TEXT, "
                            "minimum_tx_fee_rate INTEGER);")
            self.db.execute("CREATE TABLE fidelitybonds(counterparty TEXT, "
                "takernick TEXT, proof TEXT);");
        finally:
            self.dblock.release()

    @staticmethod
    def on_set_topic(newtopic):
        chunks = newtopic.split('|')
        for msg in chunks[1:]:
            try:
                msg = msg.strip()
                params = msg.split(' ')
                min_version = int(params[0])
                max_version = int(params[1])
                alert = msg[msg.index(params[1]) + len(params[1]):].strip()
            except (ValueError, IndexError):
                continue
            if min_version < JM_VERSION < max_version:
                print('=' * 60)
                print('JOINMARKET ALERT')
                print(alert)
                print('=' * 60)
                joinmarket_alert[0] = alert

    def on_order_seen(self, counterparty: str, oid: int, ordertype: str,
                      minsize: int, maxsize: int,
                      txfee: int, cjfee: Integral,
                      minimum_tx_fee_rate: int) -> None:
        try:
            self.dblock.acquire(True)
            if int(oid) < 0 or int(oid) > sys.maxsize:
                log.debug("Got invalid order ID: " + oid + " from " +
                          counterparty)
                return
            # delete orders eagerly, so in case a buggy maker sends an
            # invalid offer, we won't accidentally !fill based on the ghost
            # of its previous message.
            self.db.execute(
                ("DELETE FROM orderbook WHERE counterparty=? "
                 "AND oid=?;"), (counterparty, oid))
            # now validate the remaining fields
            if int(minsize) < 0 or int(minsize) > 21 * 10**14:
                log.debug("Got invalid minsize: {} from {}".format(
                    minsize, counterparty))
                return
            if int(minsize) < self.dust_threshold:
                minsize = self.dust_threshold
                log.debug("{} has dusty minsize, capping at {}".format(
                    counterparty, minsize))
                # do not pass return, go not drop this otherwise fine offer
            if int(maxsize) < 0 or int(maxsize) > 21 * 10**14:
                log.debug("Got invalid maxsize: " + maxsize + " from " +
                          counterparty)
                return
            if int(txfee) < 0:
                log.debug("Got invalid txfee: {} from {}".format(txfee,
                                                                 counterparty))
                return
            if int(minsize) > int(maxsize):

                fmt = ("Got minsize bigger than maxsize: {} - {} "
                       "from {}").format
                log.debug(fmt(minsize, maxsize, counterparty))
                return
            if ordertype in ['sw0absoffer', 'swabsoffer', 'absoffer']\
                    and not isinstance(cjfee, Integral):
                try:
                    cjfee = int(cjfee)
                except ValueError:
                    log.debug("Got non integer coinjoin fee: " + str(cjfee) +
                              " for an absoffer from " + counterparty)
                    return
            self.db.execute(
                'INSERT INTO orderbook VALUES(?, ?, ?, ?, ?, ?, ?, ?);',
                (counterparty, oid, ordertype, minsize, maxsize, txfee,
                 str(Decimal(cjfee)),   # any parseable Decimal is a valid cjfee
                 minimum_tx_fee_rate))
        except InvalidOperation:
            log.debug("Got invalid cjfee: " + str(cjfee) + " from " + counterparty)
        except Exception as e:
            log.debug("Error parsing order " + str(oid) + " from " + counterparty)
            log.debug("Exception was: " + repr(e))
        finally:
            self.dblock.release()

    def on_order_cancel(self, counterparty, oid):
        try:
            self.dblock.acquire(True)
            self.db.execute(
                ("DELETE FROM orderbook WHERE "
                 "counterparty=? AND oid=?;"), (counterparty, oid))
        finally:
            self.dblock.release()

    def on_fidelity_bond_seen(self, nick, bond_type, fidelity_bond_proof_msg):
        taker_nick = self.msgchan.nick
        maker_nick = nick
        if not fidelity_bond_sanity_check.fidelity_bond_sanity_check(fidelity_bond_proof_msg):
            log.debug("Failed to verify fidelity bond for {}, skipping."
                      .format(maker_nick))
            return
        try:
            self.dblock.acquire(True)
            self.db.execute("DELETE FROM fidelitybonds WHERE counterparty=?;",
                            (nick, ))
            self.db.execute("INSERT INTO fidelitybonds VALUES(?, ?, ?);",
                (nick, taker_nick, fidelity_bond_proof_msg))
        finally:
            self.dblock.release()

    def on_nick_leave(self, nick):
        try:
            self.dblock.acquire(True)
            self.db.execute('DELETE FROM orderbook WHERE counterparty=?;',
                            (nick,))
            self.db.execute('DELETE FROM fidelitybonds WHERE counterparty=?;',
                            (nick,))
        finally:
            self.dblock.release()

    def on_disconnect(self):
        try:
            self.dblock.acquire(True)
            self.db.execute('DELETE FROM orderbook;')
            self.db.execute('DELETE FROM fidelitybonds;')
        finally:
            self.dblock.release()
