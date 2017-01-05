#!/usr/bin/env python
from __future__ import print_function

'''
Joinmarket GUI using PyQt for doing coinjoins.
Some widgets copied and modified from https://github.com/spesmilo/electrum


    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import sys, base64, textwrap, re, datetime, os, math, json, logging
import Queue, platform, csv, threading, time

from decimal import Decimal
from functools import partial
from collections import namedtuple

from PyQt4 import QtCore
from PyQt4.QtGui import *

if platform.system() == 'Windows':
    MONOSPACE_FONT = 'Lucida Console'
elif platform.system() == 'Darwin':
    MONOSPACE_FONT = 'Monaco'
else:
    MONOSPACE_FONT = 'monospace'

GREEN_BG = "QWidget {background-color:#80ff80;}"
RED_BG = "QWidget {background-color:#ffcccc;}"
RED_FG = "QWidget {color:red;}"
BLUE_FG = "QWidget {color:blue;}"
BLACK_FG = "QWidget {color:black;}"

import jmbitcoin as btc

JM_CORE_VERSION = '0.2.2'
JM_GUI_VERSION = '5'

from jmclient import (load_program_config, get_network, Wallet,
                      get_p2pk_vbyte, jm_single, validate_address,
                      get_log, weighted_order_choose, Taker,
                      JMTakerClientProtocolFactory, WalletError,
                      start_reactor, get_schedule, get_tumble_schedule)
#from joinmarket import load_program_config, get_network, Wallet, encryptData, \
#    get_p2pk_vbyte, jm_single, mn_decode, mn_encode, create_wallet_file, \
#    validate_address, random_nick, get_log, IRCMessageChannel, \
#    weighted_order_choose, get_blockchain_interface_instance, joinmarket_alert, \
#    core_alert

def satoshis_to_amt_str(x):
    return str(Decimal(x)/Decimal('1e8')) + " BTC"

log = get_log()
donation_address = '1LT6rwv26bV7mgvRosoSCyGM7ttVRsYidP'
donation_address_testnet = 'mz6FQosuiNe8135XaQqWYmXsa3aD8YsqGL'

warnings = {"blockr_privacy": """You are using blockr as your method of
connecting to the blockchain; this means
that blockr.com can see the addresses you
query. This is bad for privacy - consider
using a Bitcoin Core node instead."""}
#configuration types
config_types = {'rpc_port': int,
                'port': int,
                'usessl': bool,
                'socks5': bool,
                'network': bool,
                'checktx': bool,
                'socks5_port': int,
                'maker_timeout_sec': int,
                'tx_fees': int,
                'gaplimit': int,
                'check_high_fee': int,
                'max_mix_depth': int,
                'txfee_default': int,
                'order_wait_time': int,
                'privacy_warning': None}
config_tips = {
    'blockchain_source': 'options: blockr, bitcoin-rpc',
    'network': 'one of "testnet" or "mainnet"',
    'checktx': 'whether to check fees before completing transaction',
    'rpc_host':
    'the host for bitcoind; only used if blockchain_source is bitcoin-rpc',
    'rpc_port': 'port for connecting to bitcoind over rpc',
    'rpc_user': 'user for connecting to bitcoind over rpc',
    'rpc_password': 'password for connecting to bitcoind over rpc',
    'host': 'hostname for IRC server',
    'channel': 'channel name on IRC server',
    'port': 'port for connecting to IRC server',
    'usessl': 'check to use SSL for connection to IRC',
    'socks5': 'check to use SOCKS5 proxy for IRC connection',
    'socks5_host': 'host for SOCKS5 proxy',
    'socks5_port': 'port for SOCKS5 proxy',
    'maker_timeout_sec': 'timeout for waiting for replies from makers',
    'merge_algorithm': 'for dust sweeping, try merge_algorithm = gradual, \n' +
    'for more rapid dust sweeping, try merge_algorithm = greedy \n' +
    'for most rapid dust sweeping, try merge_algorithm = greediest \n' +
    ' but dont forget to bump your miner fees!',
    'tx_fees':
    'the fee estimate is based on a projection of how many satoshis \n' +
    'per kB are needed to get in one of the next N blocks, N set here \n' +
    'as the value of "tx_fees". This estimate is high if you set N=1, \n' +
    'so we choose N=3 for a more reasonable figure, \n' +
    'as our default. Note that for clients not using a local blockchain \n' +
    'instance, we retrieve an estimate from the API at blockcypher.com, currently. \n',
    'gaplimit': 'How far forward to search for used addresses in the HD wallet',
    'check_high_fee': 'Percent fee considered dangerously high, default 2%',
    'max_mix_depth': 'Total number of mixdepths in the wallet, default 5',
    'txfee_default': 'Number of satoshis per counterparty for an initial\n' +
    'tx fee estimate; this value is not usually used and is best left at\n' +
    'the default of 5000',
    'order_wait_time': 'How long to wait for orders to arrive on entering\n' +
    'the message channel, default is 30s'
}


def JMQtMessageBox(obj, msg, mbtype='info', title=''):
    mbtypes = {'info': QMessageBox.information,
               'crit': QMessageBox.critical,
               'warn': QMessageBox.warning,
               'question': QMessageBox.question}
    title = "JoinmarketQt - " + title
    if mbtype == 'question':
        return QMessageBox.question(obj, title, msg, QMessageBox.Yes,
                                    QMessageBox.No)
    else:
        mbtypes[mbtype](obj, title, msg)


def update_config_for_gui():
    '''The default joinmarket config does not contain these GUI settings
    (they are generally set by command line flags or not needed).
    If they are set in the file, use them, else set the defaults.
    These *will* be persisted to joinmarket.cfg, but that will not affect
    operation of the command line version.
    '''
    gui_config_names = ['gaplimit', 'history_file', 'check_high_fee',
                        'max_mix_depth', 'txfee_default', 'order_wait_time',
                        'daemon_port', 'checktx']
    gui_config_default_vals = ['6', 'jm-tx-history.txt', '2', '5', '5000', '30',
                               '27183', 'true']
    if "GUI" not in jm_single().config.sections():
        jm_single().config.add_section("GUI")
    gui_items = jm_single().config.items("GUI")
    for gcn, gcv in zip(gui_config_names, gui_config_default_vals):
        if gcn not in [_[0] for _ in gui_items]:
            jm_single().config.set("GUI", gcn, gcv)
    #Extra setting not exposed to the GUI, but only for the GUI app
    if 'privacy_warning' not in [_[0] for _ in gui_items]:
        print('overwriting privacy_warning')
        jm_single().config.set("GUI", 'privacy_warning', '1')


def persist_config():
    '''This loses all comments in the config file.
    TODO: possibly correct that.'''
    with open('joinmarket.cfg', 'w') as f:
        jm_single().config.write(f)

def checkAddress(parent, addr):
    valid, errmsg = validate_address(str(addr))
    if not valid:
        JMQtMessageBox(parent,
                       "Bitcoin address not valid.\n" + errmsg,
                       mbtype='warn',
                       title="Error")

def getSettingsWidgets():
    results = []
    sN = ['Recipient address', 'Number of counterparties', 'Mixdepth',
          'Amount in bitcoins (BTC)']
    sH = ['The address you want to send the payment to',
          'How many other parties to send to; if you enter 4\n' +
          ', there will be 5 participants, including you',
          'The mixdepth of the wallet to send the payment from',
          'The amount IN BITCOINS to send.\n' +
          'If you enter 0, a SWEEP transaction\nwill be performed,' +
          ' spending all the coins \nin the given mixdepth.']
    sT = [str, int, int, float]
    #todo maxmixdepth
    sMM = ['', (2, 20),
           (0, jm_single().config.getint("GUI", "max_mix_depth") - 1),
           (0.00000001, 100.0, 8)]
    sD = ['', '3', '0', '']
    for x in zip(sN, sH, sT, sD, sMM):
        ql = QLabel(x[0])
        ql.setToolTip(x[1])
        qle = QLineEdit(x[3])
        if x[2] == int:
            qle.setValidator(QIntValidator(*x[4]))
        if x[2] == float:
            qle.setValidator(QDoubleValidator(*x[4]))
        results.append((ql, qle))
    return results

class TaskThread(QtCore.QThread):
    '''Thread that runs background tasks.  Callbacks are guaranteed
    to happen in the context of its parent.'''

    Task = namedtuple("Task", "task cb_success cb_done cb_error")
    doneSig = QtCore.pyqtSignal(object, object, object)

    def __init__(self, parent, on_error=None):
        super(TaskThread, self).__init__(parent)
        self.on_error = on_error
        self.tasks = Queue.Queue()
        self.doneSig.connect(self.on_done)
        self.start()

    def add(self, task, on_success=None, on_done=None, on_error=None):
        on_error = on_error or self.on_error
        self.tasks.put(TaskThread.Task(task, on_success, on_done, on_error))

    def run(self):
        while True:
            task = self.tasks.get()
            if not task:
                break
            try:
                result = task.task()
                self.doneSig.emit(result, task.cb_done, task.cb_success)
            except BaseException:
                self.doneSig.emit(sys.exc_info(), task.cb_done, task.cb_error)

    def on_done(self, result, cb_done, cb):
        # This runs in the parent's thread.
        if cb_done:
            cb_done()
        if cb:
            cb(result)

    def stop(self):
        self.tasks.put(None)

class QtHandler(logging.Handler):

    def __init__(self):
        logging.Handler.__init__(self)

    def emit(self, record):
        record = self.format(record)
        if record: XStream.stdout().write('%s\n' % record)


handler = QtHandler()
handler.setFormatter(logging.Formatter("%(levelname)s:%(message)s"))
log.addHandler(handler)


class XStream(QtCore.QObject):
    _stdout = None
    _stderr = None
    messageWritten = QtCore.pyqtSignal(str)

    def flush(self):
        pass

    def fileno(self):
        return -1

    def write(self, msg):
        if (not self.signalsBlocked()):
            self.messageWritten.emit(unicode(msg))

    @staticmethod
    def stdout():
        if (not XStream._stdout):
            XStream._stdout = XStream()
            sys.stdout = XStream._stdout
        return XStream._stdout

    @staticmethod
    def stderr():
        if (not XStream._stderr):
            XStream._stderr = XStream()
            sys.stderr = XStream._stderr
        return XStream._stderr


class Buttons(QHBoxLayout):

    def __init__(self, *buttons):
        QHBoxLayout.__init__(self)
        self.addStretch(1)
        for b in buttons:
            self.addWidget(b)


class CloseButton(QPushButton):

    def __init__(self, dialog):
        QPushButton.__init__(self, "Close")
        self.clicked.connect(dialog.close)
        self.setDefault(True)


class CopyButton(QPushButton):

    def __init__(self, text_getter, app):
        QPushButton.__init__(self, "Copy")
        self.clicked.connect(lambda: app.clipboard().setText(text_getter()))


class CopyCloseButton(QPushButton):

    def __init__(self, text_getter, app, dialog):
        QPushButton.__init__(self, "Copy and Close")
        self.clicked.connect(lambda: app.clipboard().setText(text_getter()))
        self.clicked.connect(dialog.close)
        self.setDefault(True)


class OkButton(QPushButton):

    def __init__(self, dialog, label=None):
        QPushButton.__init__(self, label or "OK")
        self.clicked.connect(dialog.accept)
        self.setDefault(True)


class CancelButton(QPushButton):

    def __init__(self, dialog, label=None):
        QPushButton.__init__(self, label or "Cancel")
        self.clicked.connect(dialog.reject)


class HelpLabel(QLabel):

    def __init__(self, text, help_text, wtitle):
        QLabel.__init__(self, text)
        self.help_text = help_text
        self.wtitle = wtitle
        self.font = QFont()
        self.setStyleSheet(BLUE_FG)

    def mouseReleaseEvent(self, x):
        QMessageBox.information(w, self.wtitle, self.help_text, 'OK')

    def enterEvent(self, event):
        self.font.setUnderline(True)
        self.setFont(self.font)
        app.setOverrideCursor(QCursor(QtCore.Qt.PointingHandCursor))
        return QLabel.enterEvent(self, event)

    def leaveEvent(self, event):
        self.font.setUnderline(False)
        self.setFont(self.font)
        app.setOverrideCursor(QCursor(QtCore.Qt.ArrowCursor))
        return QLabel.leaveEvent(self, event)


def check_password_strength(password):
    '''
    Check the strength of the password entered by the user and return back the same
    :param password: password entered by user in New Password
    :return: password strength Weak or Medium or Strong
    '''
    password = unicode(password)
    n = math.log(len(set(password)))
    num = re.search("[0-9]", password) is not None and re.match(
        "^[0-9]*$", password) is None
    caps = password != password.upper() and password != password.lower()
    extra = re.match("^[a-zA-Z0-9]*$", password) is None
    score = len(password) * (n + caps + num + extra) / 20
    password_strength = {0: "Weak", 1: "Medium", 2: "Strong", 3: "Very Strong"}
    return password_strength[min(3, int(score))]


def update_password_strength(pw_strength_label, password):
    '''
    call the function check_password_strength and update the label pw_strength 
    interactively as the user is typing the password
    :param pw_strength_label: the label pw_strength
    :param password: password entered in New Password text box
    :return: None
    '''
    if password:
        colors = {"Weak": "Red",
                  "Medium": "Blue",
                  "Strong": "Green",
                  "Very Strong": "Green"}
        strength = check_password_strength(password)
        label = "Password Strength"+ ": "+"<font color=" + \
        colors[strength] + ">" + strength + "</font>"
    else:
        label = ""
    pw_strength_label.setText(label)


def make_password_dialog(self, msg, new_pass=True):

    self.new_pw = QLineEdit()
    self.new_pw.setEchoMode(2)
    self.conf_pw = QLineEdit()
    self.conf_pw.setEchoMode(2)

    vbox = QVBoxLayout()
    label = QLabel(msg)
    label.setWordWrap(True)

    grid = QGridLayout()
    grid.setSpacing(8)
    grid.setColumnMinimumWidth(0, 70)
    grid.setColumnStretch(1, 1)
    #TODO perhaps add an icon here
    logo = QLabel()
    lockfile = ":icons/lock.png"
    logo.setPixmap(QPixmap(lockfile).scaledToWidth(36))
    logo.setAlignment(QtCore.Qt.AlignCenter)

    grid.addWidget(logo, 0, 0)
    grid.addWidget(label, 0, 1, 1, 2)
    vbox.addLayout(grid)

    grid = QGridLayout()
    grid.setSpacing(8)
    grid.setColumnMinimumWidth(0, 250)
    grid.setColumnStretch(1, 1)

    grid.addWidget(QLabel('New Password' if new_pass else 'Password'), 1, 0)
    grid.addWidget(self.new_pw, 1, 1)

    grid.addWidget(QLabel('Confirm Password'), 2, 0)
    grid.addWidget(self.conf_pw, 2, 1)
    vbox.addLayout(grid)

    #Password Strength Label
    self.pw_strength = QLabel()
    grid.addWidget(self.pw_strength, 3, 0, 1, 2)
    self.new_pw.textChanged.connect(
        lambda: update_password_strength(self.pw_strength, self.new_pw.text()))

    vbox.addStretch(1)
    vbox.addLayout(Buttons(CancelButton(self), OkButton(self)))
    return vbox


class PasswordDialog(QDialog):

    def __init__(self):
        super(PasswordDialog, self).__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Create a new password')
        msg = "Enter a new password"
        self.setLayout(make_password_dialog(self, msg))
        self.show()


class MyTreeWidget(QTreeWidget):

    def __init__(self,
                 parent,
                 create_menu,
                 headers,
                 stretch_column=None,
                 editable_columns=None):
        QTreeWidget.__init__(self, parent)
        self.parent = parent
        self.stretch_column = stretch_column
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(create_menu)
        self.setUniformRowHeights(True)
        # extend the syntax for consistency
        self.addChild = self.addTopLevelItem
        self.insertChild = self.insertTopLevelItem
        self.editor = None
        self.pending_update = False
        if editable_columns is None:
            editable_columns = [stretch_column]
        self.editable_columns = editable_columns
        self.itemActivated.connect(self.on_activated)
        self.update_headers(headers)

    def update_headers(self, headers):
        self.setColumnCount(len(headers))
        self.setHeaderLabels(headers)
        self.header().setStretchLastSection(False)
        for col in range(len(headers)):
            sm = QHeaderView.Stretch if col == self.stretch_column else QHeaderView.ResizeToContents
            self.header().setResizeMode(col, sm)

    def editItem(self, item, column):
        if column in self.editable_columns:
            self.editing_itemcol = (item, column, unicode(item.text(column)))
            # Calling setFlags causes on_changed events for some reason
            item.setFlags(item.flags() | Qt.ItemIsEditable)
            QTreeWidget.editItem(self, item, column)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)

    def keyPressEvent(self, event):
        if event.key() == QtCore.Qt.Key_F2:
            self.on_activated(self.currentItem(), self.currentColumn())
        else:
            QTreeWidget.keyPressEvent(self, event)

    def permit_edit(self, item, column):
        return (column in self.editable_columns and
                self.on_permit_edit(item, column))

    def on_permit_edit(self, item, column):
        return True

    def on_activated(self, item, column):
        if self.permit_edit(item, column):
            self.editItem(item, column)
        else:
            pt = self.visualItemRect(item).bottomLeft()
            pt.setX(50)
            self.emit(
                QtCore.SIGNAL('customContextMenuRequested(const QPoint&)'), pt)

    def createEditor(self, parent, option, index):
        self.editor = QStyledItemDelegate.createEditor(self.itemDelegate(),
                                                       parent, option, index)
        self.editor.connect(self.editor, QtCore.SIGNAL("editingFinished()"),
                            self.editing_finished)
        return self.editor

    def editing_finished(self):
        # Long-time QT bug - pressing Enter to finish editing signals
        # editingFinished twice.  If the item changed the sequence is
        # Enter key:  editingFinished, on_change, editingFinished
        # Mouse: on_change, editingFinished
        # This mess is the cleanest way to ensure we make the
        # on_edited callback with the updated item
        if self.editor:
            (item, column, prior_text) = self.editing_itemcol
            if self.editor.text() == prior_text:
                self.editor = None  # Unchanged - ignore any 2nd call
            elif item.text(column) == prior_text:
                pass  # Buggy first call on Enter key, item not yet updated
            else:
                # What we want - the updated item
                self.on_edited(*self.editing_itemcol)
                self.editor = None

            # Now do any pending updates
            if self.editor is None and self.pending_update:
                self.pending_update = False
                self.on_update()

    def on_edited(self, item, column, prior):
        '''Called only when the text actually changes'''
        key = str(item.data(0, Qt.UserRole).toString())
        text = unicode(item.text(column))
        self.parent.wallet.set_label(key, text)
        if text:
            item.setForeground(column, QBrush(QColor('black')))
        else:
            text = self.parent.wallet.get_default_label(key)
            item.setText(column, text)
            item.setForeground(column, QBrush(QColor('gray')))
        self.parent.history_list.update()
        self.parent.update_completions()

    def update(self):
        # Defer updates if editing
        if self.editor:
            self.pending_update = True
        else:
            self.on_update()

    def on_update(self):
        pass

    def get_leaves(self, root):
        child_count = root.childCount()
        if child_count == 0:
            yield root
        for i in range(child_count):
            item = root.child(i)
            for x in self.get_leaves(item):
                yield x

    def filter(self, p, columns):
        p = unicode(p).lower()
        for item in self.get_leaves(self.invisibleRootItem()):
            item.setHidden(all([unicode(item.text(column)).lower().find(p) == -1
                                for column in columns]))


class SettingsTab(QDialog):

    def __init__(self):
        super(SettingsTab, self).__init__()
        self.initUI()

    def initUI(self):
        outerGrid = QGridLayout()
        sA = QScrollArea()
        sA.setWidgetResizable(True)
        frame = QFrame()
        grid = QGridLayout()
        self.settingsFields = []
        j = 0
        for i, section in enumerate(jm_single().config.sections()):
            pairs = jm_single().config.items(section)
            #an awkward design element from the core code: maker_timeout_sec
            #is set outside the config, if it doesn't exist in the config.
            #Add it here and it will be in the newly updated config file.
            if section == 'MESSAGING' and 'maker_timeout_sec' not in [
                    _[0] for _ in pairs
            ]:
                jm_single().config.set(section, 'maker_timeout_sec', '60')
                pairs = jm_single().config.items(section)
            newSettingsFields = self.getSettingsFields(section,
                                                       [_[0] for _ in pairs])
            self.settingsFields.extend(newSettingsFields)
            sL = QLabel(section)
            sL.setStyleSheet("QLabel {color: blue;}")
            grid.addWidget(sL)
            j += 1
            for k, ns in enumerate(newSettingsFields):
                grid.addWidget(ns[0], j, 0)
                #try to find the tooltip for this label from config tips;
                #it might not be there
                if str(ns[0].text()) in config_tips:
                    ttS = config_tips[str(ns[0].text())]
                    ns[0].setToolTip(ttS)
                grid.addWidget(ns[1], j, 1)
                sfindex = len(self.settingsFields) - len(newSettingsFields) + k
                if isinstance(ns[1], QCheckBox):
                    ns[1].toggled.connect(lambda checked, s=section,
                                          q=sfindex: self.handleEdit(
                                    s, self.settingsFields[q], checked))
                else:
                    ns[1].editingFinished.connect(
                    lambda q=sfindex, s=section: self.handleEdit(s,
                                                      self.settingsFields[q]))
                j += 1
        outerGrid.addWidget(sA)
        sA.setWidget(frame)
        frame.setLayout(grid)
        frame.adjustSize()
        self.setLayout(outerGrid)
        self.show()

    def handleEdit(self, section, t, checked=None):
        if isinstance(t[1], QCheckBox):
            if str(t[0].text()) == 'Testnet':
                oname = 'network'
                oval = 'testnet' if checked else 'mainnet'
                add = '' if not checked else ' - Testnet'
                w.setWindowTitle(appWindowTitle + add)
            else:
                oname = str(t[0].text())
                oval = 'true' if checked else 'false'
            log.debug('setting section: ' + section + ' and name: ' + oname +
                      ' to: ' + oval)
            jm_single().config.set(section, oname, oval)

        else:  #currently there is only QLineEdit
            log.debug('setting section: ' + section + ' and name: ' + str(t[
                0].text()) + ' to: ' + str(t[1].text()))
            jm_single().config.set(section, str(t[0].text()), str(t[1].text()))
            if str(t[0].text()) == 'blockchain_source':
                jm_single().bc_interface = get_blockchain_interface_instance(
                    jm_single().config)

    def getSettingsFields(self, section, names):
        results = []
        for name in names:
            val = jm_single().config.get(section, name)
            if name in config_types:
                t = config_types[name]
                if t == bool:
                    qt = QCheckBox()
                    if val == 'testnet' or val.lower() == 'true':
                        qt.setChecked(True)
                elif not t:
                    continue
                else:
                    qt = QLineEdit(val)
                    if t == int:
                        qt.setValidator(QIntValidator(0, 65535))
            else:
                qt = QLineEdit(val)
            label = 'Testnet' if name == 'network' else name
            results.append((QLabel(label), qt))
        return results

""" TODO implement this option
class SchStaticPage(QWizardPage):
    def __init__(self, parent):
        super(SchStaticPage, self).__init__(parent)
        self.setTitle("Manually create a schedule entry")
        layout = QGridLayout()
        wdgts = getSettingsWidgets()
        for i, x in enumerate(wdgts):
            layout.addWidget(x[0], i + 1, 0)
            layout.addWidget(x[1], i + 1, 1, 1, 2)
        wdgts[0][1].editingFinished.connect(
                    lambda: checkAddress(self, wdgts[0][1].text()))
        self.setLayout(layout)
"""

class SchDynamicPage1(QWizardPage):
    def __init__(self, parent):
        super(SchDynamicPage1, self).__init__(parent)
        self.setTitle("Tumble schedule generation")
        self.setSubTitle("Set parameters for the sequence of transactions in the tumble.")
        results = []
        sN = ['Starting mixdepth', 'Average number of counterparties',
              'How many mixdepths to tumble through',
              'Average wait time between transactions, in seconds',
              'Average number of transactions per mixdepth']
        #Tooltips
        sH = ["The starting mixdepth can be decided from the Wallet tab; it must "
        "have coins in it, but it's OK if some coins are in other mixdepths.",
        "How many other participants are in each coinjoin, on average; but "
        "each individual coinjoin will have a number that's slightly varied "
        "from this, randomly",
        "For example, if you start at mixdepth 1 and enter 4 here, the tumble "
        "will move coins from mixdepth 1 to mixdepth 5",
        "This is the time waited *after* 1 confirmation has occurred, and is "
        "varied randomly.",
        "Will be varied randomly, with a minimum of 1 per mixdepth"]
        #types
        sT = [int, int, int, float, int]
        #constraints
        sMM = [(0, jm_single().config.getint("GUI", "max_mix_depth") - 1), (3, 20),
               (1, 5), (0.00000001, 100.0, 8), (2, 10)]
        sD = ['', '', '', '', '']
        for x in zip(sN, sH, sT, sD, sMM):
            ql = QLabel(x[0])
            ql.setToolTip(x[1])
            qle = QLineEdit(x[3])
            if x[2] == int:
                qle.setValidator(QIntValidator(*x[4]))
            if x[2] == float:
                qle.setValidator(QDoubleValidator(*x[4]))
            results.append((ql, qle))
        layout = QGridLayout()
        layout.setSpacing(4)
        for i, x in enumerate(results):
            layout.addWidget(x[0], i + 1, 0)
            layout.addWidget(x[1], i + 1, 1, 1, 2)
        self.setLayout(layout)
        self.registerField("mixdepthsrc*", results[0][1])
        self.registerField("makercount*", results[1][1])
        self.registerField("mixdepthcount*", results[2][1])
        self.registerField("timelambda*", results[3][1])
        self.registerField("txcountparams*", results[4][1])

class SchDynamicPage2(QWizardPage):

    def __init__(self, parent):
        super(SchDynamicPage2, self).__init__(parent)
        self.setTitle("Tumble schedule generation 2")
        self.setSubTitle("Set destination addresses for tumble.")
        layout = QGridLayout()
        layout.setSpacing(4)
        #by default create three address fields
        addrLEs = []
        #for testing
        testaddrs = ["mteaYsGsLCL9a4cftZFTpGEWXNwZyDt5KS",
                     "msFGHeut3rfJk5sKuoZNfpUq9MeVMqmido",
                     "mkZfBXCRPs8fCmwWLrspjCvYozDhK6Eepz"]
        for i in range(3):
            layout.addWidget(QLabel("Destination address: " + str(i)), i, 0)
            addrLEs.append(QLineEdit(testaddrs[i]))
            layout.addWidget(addrLEs[-1], i, 1, 1, 2)
            #addrLEs[-1].editingFinished.connect(
            #    lambda: checkAddress(self, addrLEs[-1].text()))
            self.registerField("destaddr"+str(i), addrLEs[-1])
        self.setLayout(layout)

class SchFinishPage(QWizardPage):
    def __init__(self, parent):
        super(SchFinishPage, self).__init__(parent)
        self.setTitle("Save your schedule")
        self.setSubTitle("The schedule will be saved to this file when you click Finish")
        layout = QGridLayout()
        layout.setSpacing(4)
        layout.addWidget(QLabel("Enter schedule name: "), 0, 0)
        self.schedName = QLineEdit()
        layout.addWidget(self.schedName, 0, 1, 1, 2)
        self.registerField("schedfilename*", self.schedName)
        self.setLayout(layout)

class SchIntroPage(QWizardPage):
    def __init__(self, parent):
        super(SchIntroPage, self).__init__(parent)
        self.setTitle("Generate a join transaction schedule")
        self.rbgroup = QButtonGroup(self)
        self.r0 = QRadioButton("Define schedule manually (not yet implemented)")
        self.r0.setEnabled(False)
        self.r1 = QRadioButton("Generate a tumble schedule automatically")
        self.rbgroup.addButton(self.r0)
        self.rbgroup.addButton(self.r1)
        layout = QVBoxLayout()
        layout.addWidget(self.r0)
        layout.addWidget(self.r1)
        self.setLayout(layout)

"""
    def nextId(self):
        if self.rbgroup.checkedButton() == self.r0:
            self.parent().staticSchedule = True
            return 3
        elif self.rbgroup.checkedButton() == self.r1:
            self.parent().staticSchedule = False
            return 1
        else:
            return 0
"""

class ScheduleWizard(QWizard):
    def __init__(self):
        super(ScheduleWizard, self).__init__()
        self.setWindowTitle("Joinmarket schedule generator")
        self.setPage(0, SchIntroPage(self))
        self.setPage(1, SchDynamicPage1(self))
        self.setPage(2, SchDynamicPage2(self))
        #self.setPage(3, SchStaticPage(self))
        self.setPage(3, SchFinishPage(self))

    def get_schedule(self):
        destaddrs = [str(x) for x in [self.field("destaddr0").toString(),
                     self.field("destaddr1").toString(),
                     self.field("destaddr2").toString()]]
        opts = {}
        opts['mixdepthsrc'] = int(self.field("mixdepthsrc").toString())
        opts['mixdepthcount'] = int(self.field("mixdepthcount").toString())
        opts['txfee'] = -1
        opts['addrcount'] = 3
        opts['makercountrange'] = (int(self.field("makercount").toString()), 1)
        opts['minmakercount'] = 2
        opts['txcountparams'] = (int(self.field("txcountparams").toString()), 1)
        opts['mintxcount'] = 1
        opts['amountpower'] = 100.0
        opts['timelambda'] = float(self.field("timelambda").toString())
        opts['waittime'] = 20
        opts['mincjamount'] = 1000000
        #needed for Taker to check:
        jm_single().mincjamount = opts['mincjamount']
        return get_tumble_schedule(opts, destaddrs)

class SpendTab(QWidget):

    def __init__(self):
        super(SpendTab, self).__init__()
        self.initUI()
        self.taker = None
        self.filter_offers_response = None
        self.taker_info_response = None
        self.clientfactory = None
        #signals from client backend to GUI
        self.jmclient_obj = QtCore.QObject()
        #This signal/callback requires user acceptance decision.
        self.jmclient_obj.connect(self.jmclient_obj, QtCore.SIGNAL('JMCLIENT:offers'),
                                                            self.checkOffers)
        #This signal/callback is for information only (including abort/error
        #conditions which require no feedback from user.
        self.jmclient_obj.connect(self.jmclient_obj, QtCore.SIGNAL('JMCLIENT:info'),
                                  self.takerInfo)
        #Signal indicating Taker has finished its work
        self.jmclient_obj.connect(self.jmclient_obj, QtCore.SIGNAL('JMCLIENT:finished'),
                                  self.takerFinished)
        #will be set in 'multiple join' tab if the user chooses to run a schedule
        self.loaded_schedule = None

    def generateTumbleSchedule(self):
        #needs a set of tumbler options and destination addresses, so needs
        #a wizard
        wizard = ScheduleWizard()
        wizard.exec_()
        self.loaded_schedule = wizard.get_schedule()
        print(str(self.loaded_schedule))
        self.toggleButtons(False, False, True, False)


    def selectSchedule(self):
        current_path = os.path.dirname(os.path.realpath(__file__))
        firstarg = QFileDialog.getOpenFileName(self,
                                               'Choose Schedule File',
                                               directory=current_path)
        #TODO validate the schedule
        log.debug('Looking for schedule in: ' + firstarg)
        if not firstarg:
            return
        res, schedule = get_schedule(firstarg)
        if not res:
            JMQtMessageBox(self, "Not a valid JM schedule file", mbtype='crit',
                           title='Error')
        else:
            w.statusBar().showMessage("Schedule loaded OK.")
            self.sch_label2.setText(os.path.basename(str(firstarg)))
            self.schedule_set_button.setEnabled(True)
            self.toggleButtons(False, False, True, False)
            self.loaded_schedule = schedule

    def initUI(self):
        vbox = QVBoxLayout(self)
        top = QFrame()
        top.setFrameShape(QFrame.StyledPanel)
        topLayout = QGridLayout()
        top.setLayout(topLayout)
        sA = QScrollArea()
        sA.setWidgetResizable(True)
        topLayout.addWidget(sA)
        self.qtw = QTabWidget()
        sA.setWidget(self.qtw)
        self.single_join_tab = QWidget()
        self.schedule_tab = QWidget()
        self.qtw.addTab(self.single_join_tab, "Single Join")
        self.qtw.addTab(self.schedule_tab, "Multiple Join")

        #construct layout for scheduler
        sch_layout = QGridLayout()
        sch_layout.setSpacing(4)
        self.schedule_tab.setLayout(sch_layout)
        current_schedule_layout = QHBoxLayout()
        sch_label1=QLabel("Current schedule: ")
        sch_label1.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.sch_label2 = QLabel("None")
        current_schedule_layout.addWidget(sch_label1)
        current_schedule_layout.addWidget(self.sch_label2)
        sch_layout.addLayout(current_schedule_layout, 0, 0, 1, 2)
        self.schedule_set_button = QPushButton('Choose schedule file')
        self.schedule_set_button.clicked.connect(self.selectSchedule)
        self.schedule_generate_button = QPushButton('Generate tumble schedule')
        self.schedule_generate_button.clicked.connect(self.generateTumbleSchedule)
        #TODO Is it possible to re-use buttons? (start, abort)
        self.sch_startButton = QPushButton('Run schedule')
        self.sch_startButton.setEnabled(False) #not runnable until schedule chosen
        self.sch_startButton.clicked.connect(self.startMultiple)
        self.sch_abortButton = QPushButton('Abort')
        self.sch_abortButton.setEnabled(False)
        self.sch_abortButton.clicked.connect(self.giveUp)
        sch_buttons = QHBoxLayout()
        sch_buttons.addStretch(1)
        sch_buttons.addWidget(self.schedule_set_button)
        sch_buttons.addWidget(self.schedule_generate_button)
        sch_buttons.addWidget(self.sch_startButton)
        sch_buttons.addWidget(self.sch_abortButton)
        sch_layout.addLayout(sch_buttons, 1, 0, 1, 2)



        innerTopLayout = QGridLayout()
        innerTopLayout.setSpacing(4)
        self.single_join_tab.setLayout(innerTopLayout)

        donateLayout = QHBoxLayout()
        self.donateCheckBox = QCheckBox()
        self.donateCheckBox.setChecked(False)
        self.donateCheckBox.setMaximumWidth(30)
        self.donateLimitBox = QDoubleSpinBox()
        self.donateLimitBox.setMinimum(0.001)
        self.donateLimitBox.setMaximum(0.100)
        self.donateLimitBox.setSingleStep(0.001)
        self.donateLimitBox.setDecimals(3)
        self.donateLimitBox.setValue(0.010)
        self.donateLimitBox.setMaximumWidth(100)
        self.donateLimitBox.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        donateLayout.addWidget(self.donateCheckBox)
        label1 = QLabel("Check to send change lower than: ")
        label1.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        donateLayout.addWidget(label1)
        donateLayout.setAlignment(label1, QtCore.Qt.AlignLeft)
        donateLayout.addWidget(self.donateLimitBox)
        donateLayout.setAlignment(self.donateLimitBox, QtCore.Qt.AlignLeft)
        label2 = QLabel(" BTC as a donation.")
        donateLayout.addWidget(label2)
        label2.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        donateLayout.setAlignment(label2, QtCore.Qt.AlignLeft)
        label3 = HelpLabel('More', '\n'.join(
            ['If the calculated change for your transaction',
             'is smaller than the value you choose (default 0.01 btc)',
             'then that change is sent as a donation. If your change',
             'is larger than that, there will be no donation.', '',
             'As well as helping the developers, this feature can,',
             'in certain circumstances, improve privacy, because there',
             'is no change output that can be linked with your inputs later.']),
                           'About the donation feature')
        label3.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        donateLayout.setAlignment(label3, QtCore.Qt.AlignLeft)
        donateLayout.addWidget(label3)
        donateLayout.addStretch(1)
        innerTopLayout.addLayout(donateLayout, 0, 0, 1, 2)
        self.widgets = getSettingsWidgets()
        for i, x in enumerate(self.widgets):
            innerTopLayout.addWidget(x[0], i + 1, 0)
            innerTopLayout.addWidget(x[1], i + 1, 1, 1, 2)
        self.widgets[0][1].editingFinished.connect(
            lambda: checkAddress(self, self.widgets[0][1].text()))
        self.startButton = QPushButton('Start')
        self.startButton.setToolTip(
            'You will be prompted to decide whether to accept\n' +
            'the transaction after connecting, and shown the\n' +
            'fees to pay; you can cancel at that point if you wish.')
        self.startButton.clicked.connect(self.startSendPayment)
        self.abortButton = QPushButton('Abort')
        self.abortButton.setEnabled(False)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.startButton)
        buttons.addWidget(self.abortButton)
        self.abortButton.clicked.connect(self.giveUp)
        innerTopLayout.addLayout(buttons, len(self.widgets) + 1, 0, 1, 2)
        splitter1 = QSplitter(QtCore.Qt.Vertical)
        self.textedit = QTextEdit()
        self.textedit.verticalScrollBar().rangeChanged.connect(
            self.resizeScroll)
        XStream.stdout().messageWritten.connect(self.updateConsoleText)
        XStream.stderr().messageWritten.connect(self.updateConsoleText)
        splitter1.addWidget(top)
        splitter1.addWidget(self.textedit)
        splitter1.setSizes([400, 200])
        self.setLayout(vbox)
        vbox.addWidget(splitter1)
        self.show()

    def updateConsoleText(self, txt):
        #these alerts are a bit suboptimal;
        #colored is better, and in the ultra-rare
        #case of getting both, one will be swallowed.
        #However, the transaction confirmation dialog
        #will at least show both in RED and BOLD, and they will be more prominent.
        #TODO in new daemon this is not accessible? Or?
        """
        if joinmarket_alert[0]:
            w.statusBar().showMessage("JOINMARKET ALERT: " + joinmarket_alert[
                0])
        if core_alert[0]:
            w.statusBar().showMessage("BITCOIN CORE ALERT: " + core_alert[0])
        """
        self.textedit.insertPlainText(txt)

    def resizeScroll(self, mini, maxi):
        self.textedit.verticalScrollBar().setValue(maxi)

    def startMultiple(self):
        self.qtw.setTabEnabled(0, False)
        self.startSendPayment(multiple=True)

    def startSendPayment(self, ignored_makers=None, multiple=False):
        self.aborted = False
        if not multiple and not self.validateSettings():
            return
        if jm_single().config.get("BLOCKCHAIN",
                                  "blockchain_source") == 'blockr':
            res = self.showBlockrWarning()
            if res == True:
                return

        #all settings are valid; start
        JMQtMessageBox(
            self,
            "Connecting to IRC.\nView real-time log in the lower pane.",
            title="Sendpayment")

        if multiple:
            self.toggleButtons(False, False, False, True)
        else:
            self.toggleButtons(False, True, False, False)

        log.debug('starting coinjoin(s)..')

        w.statusBar().showMessage("Syncing wallet ...")
        jm_single().bc_interface.sync_wallet(w.wallet, fast=True)
        if not multiple:
            destaddr = str(self.widgets[0][1].text())
            #convert from bitcoins (enforced by QDoubleValidator) to satoshis
            btc_amount_str = str(self.widgets[3][1].text())
            amount = int(Decimal(btc_amount_str) * Decimal('1e8'))
            makercount = int(self.widgets[1][1].text())
            mixdepth = int(self.widgets[2][1].text())
            #note 'amount' is integer, so not interpreted as fraction
            self.taker_schedule = [(mixdepth, amount, makercount, destaddr, 0)]
        else:
            assert self.loaded_schedule
            self.taker_schedule = self.loaded_schedule

        #Decide whether to interrupt processing to sanity check the fees
        if jm_single().config.get("GUI", "checktx") == "true":
            check_offers_callback = self.callback_checkOffers
        else:
            check_offers_callback = None

        self.taker = Taker(w.wallet,
                           self.taker_schedule,
                           order_chooser=weighted_order_choose,
                           callbacks=[check_offers_callback,
                                      self.callback_takerInfo,
                                      self.callback_takerFinished])
        if ignored_makers:
            self.taker.ignored_makers.extend(ignored_makers)
        if not self.clientfactory:
            #First run means we need to start: create clientfactory
            #and start reactor Thread
            self.clientfactory = JMTakerClientProtocolFactory(self.taker)
            thread = TaskThread(self)
            thread.add(partial(start_reactor,
                   "localhost",
                   jm_single().config.getint("GUI", "daemon_port"),
                   self.clientfactory,
                   ish=False,
                   daemon=True))
        else:
            #This will re-use IRC connections in background (daemon), no restart
            self.clientfactory.getClient().taker = self.taker
            self.clientfactory.getClient().clientStart()
        w.statusBar().showMessage("Connecting to IRC ...")

    def callback_checkOffers(self, offers_fee, cjamount):
        """Receives the signal from the JMClient thread
        """
        if self.aborted:
            log.debug("Not processing orders, user has aborted.")
            return False
        self.offers_fee = offers_fee
        self.jmclient_obj.emit(QtCore.SIGNAL('JMCLIENT:offers'))
        #The JMClient thread must wait for user input
        while not self.filter_offers_response:
            time.sleep(0.1)
        if self.filter_offers_response == "ACCEPT":
            self.filter_offers_response = None
            #The user is now committed to the transaction
            self.abortButton.setEnabled(False)
            return True
        self.filter_offers_response = None
        return False

    def callback_takerInfo(self, infotype, infomsg):
        if infotype == "ABORT":
            #Abort signal explicitly means this transaction will not continue.
            self.giveUp()
            self.taker_info_type = 'warn'
        elif infotype == "INFO":
            self.taker_info_type = 'info'
        else:
            raise NotImplementedError
        self.taker_infomsg = infomsg
        self.jmclient_obj.emit(QtCore.SIGNAL('JMCLIENT:info'))
        while not self.taker_info_response:
            time.sleep(0.1)
        #No need to check response type, only OK for msgbox
        self.taker_info_response = None
        return

    def callback_takerFinished(self, res, fromtx=False, waittime=0):
        self.taker_finished_res = res
        self.taker_finished_fromtx = fromtx
        #TODO; equivalent of reactor.callLater to deliberately delay (for tumbler)
        self.taker_finished_waittime = waittime
        self.jmclient_obj.emit(QtCore.SIGNAL('JMCLIENT:finished'))
        return

    def takerInfo(self):
        if self.taker_info_type == "info":
            w.statusBar().showMessage(self.taker_infomsg)
        else:
            JMQtMessageBox(self, self.taker_infomsg, mbtype=self.taker_info_type)
        self.taker_info_response = True

    def checkOffers(self):
        """Parse offers and total fee from client protocol,
        allow the user to agree or decide.
        """
        if not self.offers_fee:
            JMQtMessageBox(self,
                           "Not enough matching offers found.",
                           mbtype='warn',
                           title="Error")
            self.giveUp()
            return
        offers, total_cj_fee = self.offers_fee
        total_fee_pc = 1.0 * total_cj_fee / self.taker.cjamount
        #Note this will be a new value if sweep, else same as previously entered
        btc_amount_str = satoshis_to_amt_str(self.taker.cjamount)

        #TODO separate this out into a function
        mbinfo = []
        #See note above re: alerts
        """
        if joinmarket_alert[0]:
            mbinfo.append("<b><font color=red>JOINMARKET ALERT: " +
                          joinmarket_alert[0] + "</font></b>")
            mbinfo.append(" ")
        if core_alert[0]:
            mbinfo.append("<b><font color=red>BITCOIN CORE ALERT: " +
                          core_alert[0] + "</font></b>")
            mbinfo.append(" ")
        """
        mbinfo.append("Sending amount: " + btc_amount_str)
        mbinfo.append("to address: " + self.destaddr)
        mbinfo.append(" ")
        mbinfo.append("Counterparties chosen:")
        mbinfo.append('Name,     Order id, Coinjoin fee (sat.)')
        for k, o in offers.iteritems():
            if o['ordertype'] == 'reloffer':
                display_fee = int(self.taker.cjamount *
                                  float(o['cjfee'])) - int(o['txfee'])
            elif o['ordertype'] == 'absoffer':
                display_fee = int(o['cjfee']) - int(o['txfee'])
            else:
                log.debug("Unsupported order type: " + str(o['ordertype']) +
                          ", aborting.")
                self.giveUp()
                return False
            mbinfo.append(k + ', ' + str(o['oid']) + ',         ' + str(
                display_fee))
        mbinfo.append('Total coinjoin fee = ' + str(total_cj_fee) +
                      ' satoshis, or ' + str(float('%.3g' % (
                          100.0 * total_fee_pc))) + '%')
        title = 'Check Transaction'
        if total_fee_pc * 100 > jm_single().config.getint("GUI",
                                                          "check_high_fee"):
            title += ': WARNING: Fee is HIGH!!'
        reply = JMQtMessageBox(self,
                               '\n'.join([m + '<p>' for m in mbinfo]),
                               mbtype='question',
                               title=title)
        if reply == QMessageBox.Yes:
            #amount is now accepted; pass control back to reactor
            self.filter_offers_response = "ACCEPT"
        else:
            self.filter_offers_response = "REJECT"
            self.giveUp()

    def takerFinished(self):
        if self.taker_finished_fromtx:
            #not the final finished transaction
            if self.taker_finished_res:
                w.statusBar().showMessage("Transaction completed successfully.")
                self.persistTxToHistory(self.taker.my_cj_addr,
                                        self.taker.cjamount,
                                        self.taker.txid)
                jm_single().bc_interface.sync_wallet(w.wallet)
                self.clientfactory.getClient().clientStart()
            else:
                #a transaction failed; just stop
                self.giveUp()
        else:
            #the final, or a permanent failure
            if not self.taker_finished_res:
                log.info("Did not complete successfully, shutting down")
            else:
                log.info("All transactions completed correctly")
                w.statusBar().showMessage("All transaction(s) completed successfully.")
                self.persistTxToHistory(self.taker.my_cj_addr,
                                        self.taker.cjamount,
                                        self.taker.txid)
                if len(self.taker.schedule) == 1:
                    msg = "Transaction has been broadcast.\n" + "Txid: " + \
                           str(self.taker.txid)
                else:
                    msg = "All transactions have been broadcast."
                JMQtMessageBox(self, msg, title="Success")
            self.cleanUp()

    def persistTxToHistory(self, addr, amt, txid):
        #persist the transaction to history
        with open(jm_single().config.get("GUI", "history_file"), 'ab') as f:
            f.write(','.join([addr, satoshis_to_amt_str(amt), txid,
                              datetime.datetime.now(
                                  ).strftime("%Y/%m/%d %H:%M:%S")]))
            f.write('\n')  #TODO: Windows
        #update the TxHistory tab
        txhist = w.centralWidget().widget(3)
        txhist.updateTxInfo()

    def toggleButtons(self, send, abort, schsend, schabort):
        self.startButton.setEnabled(send)
        self.abortButton.setEnabled(abort)
        self.sch_startButton.setEnabled(schsend)
        self.sch_abortButton.setEnabled(schabort)

    def giveUp(self):
        self.aborted = True
        log.debug("Transaction aborted.")
        self.qtw.setTabEnabled(0, True)
        self.qtw.setTabEnabled(1, True)
        self.toggleButtons(True, False, False, False)
        w.statusBar().showMessage("Transaction aborted.")

    def cleanUp(self):
        if not self.taker.txid:
            if not self.aborted:
                if not self.taker.ignored_makers:
                    w.statusBar().showMessage("Transaction failed.")
                    JMQtMessageBox(self,
                                   "Transaction was not completed.",
                                   mbtype='warn',
                                   title="Failed")
                else:
                    reply = JMQtMessageBox(
                        self,
                        '\n'.join([
                            "The following counterparties did not respond: ",
                            ','.join(self.taker.ignored_makers),
                            "This sometimes happens due to bad network connections.",
                            "",
                            "If you would like to try again, ignoring those",
                            "counterparties, click Yes."
                        ]),
                        mbtype='question',
                        title="Transaction not completed.")
                    if reply == QMessageBox.Yes:
                        self.startSendPayment(
                            ignored_makers=self.taker.ignored_makers)
                    else:
                        self.giveUp()
                        return
        self.qtw.setTabEnabled(0, True)
        self.qtw.setTabEnabled(1, True)
        self.toggleButtons(True, False, False, False)

    def validateSettings(self):
        valid, errmsg = validate_address(self.widgets[0][1].text())
        if not valid:
            JMQtMessageBox(self, errmsg, mbtype='warn', title="Error")
            return False
        errs = ["Non-zero number of counterparties must be provided.",
                "Mixdepth must be chosen.",
                "Amount, in bitcoins, must be provided."]
        for i in range(1, 4):
            if self.widgets[i][1].text().size() == 0:
                JMQtMessageBox(self, errs[i - 1], mbtype='warn', title="Error")
                return False
        #QIntValidator does not prevent entry of 0 for counterparties.
        #Note, use of '1' is not recommended, but not prevented here.
        if self.widgets[1][1].text() == '0':
            JMQtMessageBox(self, errs[0], mbtype='warn', title="Error")
            return False
        if not w.wallet:
            JMQtMessageBox(self,
                           "There is no wallet loaded.",
                           mbtype='warn',
                           title="Error")
            return False
        return True

    def showBlockrWarning(self):
        if jm_single().config.getint("GUI", "privacy_warning") == 0:
            return False
        qmb = QMessageBox()
        qmb.setIcon(QMessageBox.Warning)
        qmb.setWindowTitle("Privacy Warning")
        qcb = QCheckBox("Don't show this warning again.")
        lyt = qmb.layout()
        lyt.addWidget(QLabel(warnings['blockr_privacy']), 0, 1)
        lyt.addWidget(qcb, 1, 1)
        qmb.addButton(QPushButton("Continue"), QMessageBox.YesRole)
        qmb.addButton(QPushButton("Cancel"), QMessageBox.NoRole)

        qmb.exec_()

        switch_off_warning = '0' if qcb.isChecked() else '1'
        jm_single().config.set("GUI", "privacy_warning", switch_off_warning)

        res = qmb.buttonRole(qmb.clickedButton())
        if res == QMessageBox.YesRole:
            return False
        elif res == QMessageBox.NoRole:
            return True
        else:
            log.debug("GUI error: unrecognized button, canceling.")
            return True


class TxHistoryTab(QWidget):

    def __init__(self):
        super(TxHistoryTab, self).__init__()
        self.initUI()

    def initUI(self):
        self.tHTW = MyTreeWidget(self, self.create_menu, self.getHeaders())
        self.tHTW.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.tHTW.header().setResizeMode(QHeaderView.Interactive)
        self.tHTW.header().setStretchLastSection(False)
        self.tHTW.on_update = self.updateTxInfo
        vbox = QVBoxLayout()
        self.setLayout(vbox)
        vbox.setMargin(0)
        vbox.setSpacing(0)
        vbox.addWidget(self.tHTW)
        self.updateTxInfo()
        self.show()

    def getHeaders(self):
        '''Function included in case dynamic in future'''
        return ['Receiving address', 'Amount in BTC', 'Transaction id', 'Date']

    def updateTxInfo(self, txinfo=None):
        self.tHTW.clear()
        if not txinfo:
            txinfo = self.getTxInfoFromFile()
        for t in txinfo:
            t_item = QTreeWidgetItem(t)
            self.tHTW.addChild(t_item)
        for i in range(4):
            self.tHTW.resizeColumnToContents(i)

    def getTxInfoFromFile(self):
        hf = jm_single().config.get("GUI", "history_file")
        if not os.path.isfile(hf):
            if w:
                w.statusBar().showMessage("No transaction history found.")
            return []
        txhist = []
        with open(hf, 'rb') as f:
            txlines = f.readlines()
            for tl in txlines:
                txhist.append(tl.strip().split(','))
                if not len(txhist[-1]) == 4:
                    JMQtMessageBox(self,
                                   "Incorrectedly formatted file " + hf,
                                   mbtype='warn',
                                   title="Error")
                    w.statusBar().showMessage("No transaction history found.")
                    return []
        return txhist[::-1
                     ]  #appended to file in date order, window shows reverse

    def create_menu(self, position):
        item = self.tHTW.currentItem()
        if not item:
            return
        address_valid = False
        if item:
            address = str(item.text(0))
            try:
                btc.b58check_to_hex(address)
                address_valid = True
            except AssertionError:
                log.debug('no btc address found, not creating menu item')

        menu = QMenu()
        if address_valid:
            menu.addAction("Copy address to clipboard",
                           lambda: app.clipboard().setText(address))
        menu.addAction("Copy transaction id to clipboard",
                       lambda: app.clipboard().setText(str(item.text(2))))
        menu.addAction("Copy full tx info to clipboard",
                       lambda: app.clipboard().setText(
                           ','.join([str(item.text(_)) for _ in range(4)])))
        menu.exec_(self.tHTW.viewport().mapToGlobal(position))


class JMWalletTab(QWidget):

    def __init__(self):
        super(JMWalletTab, self).__init__()
        self.wallet_name = 'NONE'
        self.initUI()

    def initUI(self):
        self.label1 = QLabel(
            "CURRENT WALLET: " + self.wallet_name + ', total balance: 0.0',
            self)
        v = MyTreeWidget(self, self.create_menu, self.getHeaders())
        v.setSelectionMode(QAbstractItemView.ExtendedSelection)
        v.on_update = self.updateWalletInfo
        self.history = v
        vbox = QVBoxLayout()
        self.setLayout(vbox)
        vbox.setMargin(0)
        vbox.setSpacing(0)
        vbox.addWidget(self.label1)
        vbox.addWidget(v)
        buttons = QWidget()
        vbox.addWidget(buttons)
        self.updateWalletInfo()
        #vBoxLayout.addWidget(self.label2)
        #vBoxLayout.addWidget(self.table)
        self.show()

    def getHeaders(self):
        '''Function included in case dynamic in future'''
        return ['Address', 'Index', 'Balance', 'Used/New']

    def create_menu(self, position):
        item = self.history.currentItem()
        address_valid = False
        if item:
            address = str(item.text(0))
            try:
                btc.b58check_to_hex(address)
                address_valid = True
            except AssertionError:
                log.debug('no btc address found, not creating menu item')

        menu = QMenu()
        if address_valid:
            menu.addAction("Copy address to clipboard",
                           lambda: app.clipboard().setText(address))
        menu.addAction("Resync wallet from blockchain",
                       lambda: w.resyncWallet())
        #TODO add more items to context menu
        menu.exec_(self.history.viewport().mapToGlobal(position))

    def updateWalletInfo(self, walletinfo=None):
        l = self.history
        l.clear()
        if walletinfo:
            self.mainwindow = self.parent().parent().parent()
            rows, mbalances, total_bal = walletinfo
            if get_network() == 'testnet':
                self.wallet_name = self.mainwindow.wallet.seed
            else:
                self.wallet_name = os.path.basename(self.mainwindow.wallet.path)
            self.label1.setText("CURRENT WALLET: " + self.wallet_name +
                                ', total balance: ' + total_bal)

        for i in range(jm_single().config.getint("GUI", "max_mix_depth")):
            if walletinfo:
                mdbalance = mbalances[i]
            else:
                mdbalance = "{0:.8f}".format(0)
            m_item = QTreeWidgetItem(["Mixdepth " + str(i) + " , balance: " +
                                      mdbalance, '', '', '', ''])
            l.addChild(m_item)
            for forchange in [0, 1]:
                heading = 'EXTERNAL' if forchange == 0 else 'INTERNAL'
                heading_end = ' addresses m/0/%d/%d/' % (i, forchange)
                heading += heading_end
                seq_item = QTreeWidgetItem([heading, '', '', '', ''])
                m_item.addChild(seq_item)
                if not forchange:
                    seq_item.setExpanded(True)
                if not walletinfo:
                    item = QTreeWidgetItem(['None', '', '', ''])
                    seq_item.addChild(item)
                else:
                    for j in range(len(rows[i][forchange])):
                        item = QTreeWidgetItem(rows[i][forchange][j])
                        item.setFont(0, QFont(MONOSPACE_FONT))
                        if rows[i][forchange][j][3] == 'used':
                            item.setForeground(3, QBrush(QColor('red')))
                        seq_item.addChild(item)


class JMMainWindow(QMainWindow):

    def __init__(self):
        super(JMMainWindow, self).__init__()
        self.wallet = None
        self.initUI()

    def closeEvent(self, event):
        quit_msg = "Are you sure you want to quit?"
        reply = JMQtMessageBox(self, quit_msg, mbtype='question')
        if reply == QMessageBox.Yes:
            persist_config()
            event.accept()
        else:
            event.ignore()

    def initUI(self):
        self.statusBar().showMessage("Ready")
        self.setGeometry(300, 300, 250, 150)
        exitAction = QAction(QIcon('exit.png'), '&Exit', self)
        exitAction.setShortcut('Ctrl+Q')
        exitAction.setStatusTip('Exit application')
        exitAction.triggered.connect(qApp.quit)
        generateAction = QAction('&Generate', self)
        generateAction.setStatusTip('Generate new wallet')
        generateAction.triggered.connect(self.generateWallet)
        loadAction = QAction('&Load', self)
        loadAction.setStatusTip('Load wallet from file')
        loadAction.triggered.connect(self.selectWallet)
        recoverAction = QAction('&Recover', self)
        recoverAction.setStatusTip('Recover wallet from seedphrase')
        recoverAction.triggered.connect(self.recoverWallet)
        aboutAction = QAction('About Joinmarket', self)
        aboutAction.triggered.connect(self.showAboutDialog)
        exportPrivAction = QAction('&Export keys', self)
        exportPrivAction.setStatusTip('Export all private keys to a csv file')
        exportPrivAction.triggered.connect(self.exportPrivkeysCsv)
        menubar = QMenuBar()

        walletMenu = menubar.addMenu('&Wallet')
        walletMenu.addAction(loadAction)
        walletMenu.addAction(generateAction)
        walletMenu.addAction(recoverAction)
        walletMenu.addAction(exportPrivAction)
        walletMenu.addAction(exitAction)
        aboutMenu = menubar.addMenu('&About')
        aboutMenu.addAction(aboutAction)

        self.setMenuBar(menubar)
        self.show()

    def showAboutDialog(self):
        msgbox = QDialog(self)
        lyt = QVBoxLayout(msgbox)
        msgbox.setWindowTitle(appWindowTitle)
        label1 = QLabel()
        label1.setText(
            "<a href=" + "'https://github.com/joinmarket-org/joinmarket/wiki'>"
            + "Read more about Joinmarket</a><p>" + "<p>".join(
                ["Joinmarket core software version: " + JM_CORE_VERSION,
                 "JoinmarketQt version: " + JM_GUI_VERSION,
                 "Messaging protocol version:" + " %s" % (
                     str(jm_single().JM_VERSION)
                 ), "Help us support Bitcoin fungibility -", "donate here: "]))
        label2 = QLabel(donation_address)
        for l in [label1, label2]:
            l.setTextFormat(QtCore.Qt.RichText)
            l.setTextInteractionFlags(QtCore.Qt.TextBrowserInteraction)
            l.setOpenExternalLinks(True)
        label2.setText("<a href='bitcoin:" + donation_address + "'>" +
                       donation_address + "</a>")
        lyt.addWidget(label1)
        lyt.addWidget(label2)
        btnbox = QDialogButtonBox(msgbox)
        btnbox.setStandardButtons(QDialogButtonBox.Ok)
        btnbox.accepted.connect(msgbox.accept)
        lyt.addWidget(btnbox)
        msgbox.exec_()

    def exportPrivkeysCsv(self):
        if not self.wallet:
            JMQtMessageBox(self,
                           "No wallet loaded.",
                           mbtype='crit',
                           title="Error")
            return
        #TODO add password protection; too critical
        d = QDialog(self)
        d.setWindowTitle('Private keys')
        d.setMinimumSize(850, 300)
        vbox = QVBoxLayout(d)

        msg = "%s\n%s\n%s" % (
            "WARNING: ALL your private keys are secret.",
            "Exposing a single private key can compromise your entire wallet!",
            "In particular, DO NOT use 'redeem private key' services proposed by third parties."
        )
        vbox.addWidget(QLabel(msg))
        e = QTextEdit()
        e.setReadOnly(True)
        vbox.addWidget(e)
        b = OkButton(d, 'Export')
        b.setEnabled(False)
        vbox.addLayout(Buttons(CancelButton(d), b))
        private_keys = {}
        #prepare list of addresses with non-zero balance
        #TODO: consider adding a 'export insanely huge amount'
        #option for anyone with gaplimit troubles, although
        #that is a complete mess for a user, mostly changing
        #the gaplimit in the Settings tab should address it.
        rows = get_wallet_printout(self.wallet)
        addresses = []
        for forchange in rows[0]:
            for mixdepth in forchange:
                for addr_info in mixdepth:
                    if float(addr_info[2]) > 0:
                        addresses.append(addr_info[0])
        done = False

        def privkeys_thread():
            for addr in addresses:
                time.sleep(0.1)
                if done:
                    break
                priv = self.wallet.get_key_from_addr(addr)
                private_keys[addr] = btc.wif_compressed_privkey(
                    priv,
                    vbyte=get_p2pk_vbyte())
                d.emit(QtCore.SIGNAL('computing_privkeys'))
            d.emit(QtCore.SIGNAL('show_privkeys'))

        def show_privkeys():
            s = "\n".join(map(lambda x: x[0] + "\t" + x[1], private_keys.items(
            )))
            e.setText(s)
            b.setEnabled(True)

        d.connect(
            d, QtCore.SIGNAL('computing_privkeys'),
            lambda: e.setText("Please wait... %d/%d" % (len(private_keys), len(addresses))))
        d.connect(d, QtCore.SIGNAL('show_privkeys'), show_privkeys)

        threading.Thread(target=privkeys_thread).start()
        if not d.exec_():
            done = True
            return
        privkeys_fn_base = 'joinmarket-private-keys'
        i = 0
        privkeys_fn = privkeys_fn_base
        while os.path.isfile(privkeys_fn + '.csv'):
            i += 1
            privkeys_fn = privkeys_fn_base + str(i)
        try:
            with open(privkeys_fn + '.csv', "w") as f:
                transaction = csv.writer(f)
                transaction.writerow(["address", "private_key"])
                for addr, pk in private_keys.items():
                    #sanity check
                    if not btc.privtoaddr(
                            btc.from_wif_privkey(pk,
                                                 vbyte=get_p2pk_vbyte()),
                            magicbyte=get_p2pk_vbyte()) == addr:
                        JMQtMessageBox(None, "Failed to create privkey export -" +\
                                       " critical error in key parsing.",
                                       mbtype='crit')
                        return
                    transaction.writerow(["%34s" % addr, pk])
        except (IOError, os.error), reason:
            export_error_label = "JoinmarketQt was unable to produce a private key-export."
            JMQtMessageBox(None,
                           export_error_label + "\n" + str(reason),
                           mbtype='crit',
                           title="Unable to create csv")

        except Exception as e:
            JMQtMessageBox(self, str(e), mbtype='crit', title="Error")
            return

        JMQtMessageBox(self,
                       "Private keys exported to: " + privkeys_fn + '.csv',
                       title="Success")

    def recoverWallet(self):
        if get_network() == 'testnet':
            JMQtMessageBox(self,
                           'recover from seedphrase not supported for testnet',
                           mbtype='crit',
                           title="Error")
            return
        d = QDialog(self)
        d.setModal(1)
        d.setWindowTitle('Recover from seed')
        layout = QGridLayout(d)
        message_e = QTextEdit()
        layout.addWidget(QLabel('Enter 12 words'), 0, 0)
        layout.addWidget(message_e, 1, 0)
        hbox = QHBoxLayout()
        buttonBox = QDialogButtonBox(self)
        buttonBox.setStandardButtons(QDialogButtonBox.Ok |
                                     QDialogButtonBox.Cancel)
        buttonBox.button(QDialogButtonBox.Ok).clicked.connect(d.accept)
        buttonBox.button(QDialogButtonBox.Cancel).clicked.connect(d.reject)
        hbox.addWidget(buttonBox)
        layout.addLayout(hbox, 3, 0)
        result = d.exec_()
        if result != QDialog.Accepted:
            return
        msg = str(message_e.toPlainText())
        words = msg.split()  #splits on any number of ws chars
        if not len(words) == 12:
            JMQtMessageBox(self,
                           "You did not provide 12 words, aborting.",
                           mbtype='warn',
                           title="Error")
        else:
            try:
                seed = mn_decode(words)
                self.initWallet(seed=seed)
            except ValueError as e:
                JMQtMessageBox(self,
                               "Could not decode seedphrase: " + repr(e),
                               mbtype='warn',
                               title="Error")

    def selectWallet(self, testnet_seed=None):
        if get_network() != 'testnet':
            current_path = os.path.dirname(os.path.realpath(__file__))
            if os.path.isdir(os.path.join(current_path, 'wallets')):
                current_path = os.path.join(current_path, 'wallets')
            firstarg = QFileDialog.getOpenFileName(self,
                                                   'Choose Wallet File',
                                                   directory=current_path)
            #TODO validate the file looks vaguely like a wallet file
            log.debug('Looking for wallet in: ' + firstarg)
            if not firstarg:
                return
            decrypted = False
            while not decrypted:
                text, ok = QInputDialog.getText(self,
                                                'Decrypt wallet',
                                                'Enter your password:',
                                                mode=QLineEdit.Password)
                if not ok:
                    return
                pwd = str(text).strip()
                decrypted = self.loadWalletFromBlockchain(firstarg, pwd)
        else:
            if not testnet_seed:
                testnet_seed, ok = QInputDialog.getText(self,
                                                        'Load Testnet wallet',
                                                        'Enter a testnet seed:',
                                                        mode=QLineEdit.Normal)
                if not ok:
                    return
            firstarg = str(testnet_seed)
            pwd = None
            #ignore return value as there is no decryption failure possible
            self.loadWalletFromBlockchain(firstarg, pwd)

    def loadWalletFromBlockchain(self, firstarg=None, pwd=None):
        if (firstarg and pwd) or (firstarg and get_network() == 'testnet'):
            try:
                self.wallet = Wallet(
                    str(firstarg),
                    pwd,
                    max_mix_depth=jm_single().config.getint(
                    "GUI", "max_mix_depth"))
            except WalletError:
                JMQtMessageBox(self,
                               "Wrong password",
                               mbtype='warn',
                               title="Error")
                return False
        if 'listunspent_args' not in jm_single().config.options('POLICY'):
            jm_single().config.set('POLICY', 'listunspent_args', '[0]')
        assert self.wallet, "No wallet loaded"
        thread = TaskThread(self)
        task = partial(jm_single().bc_interface.sync_wallet, self.wallet)
        thread.add(task, on_done=self.updateWalletInfo)
        self.statusBar().showMessage("Reading wallet from blockchain ...")
        return True

    def updateWalletInfo(self):
        t = self.centralWidget().widget(0)
        if not self.wallet:  #failure to sync in constructor means object is not created
            newstmsg = "Unable to sync wallet - see error in console."
        else:
            t.updateWalletInfo(get_wallet_printout(self.wallet))
            newstmsg = "Wallet synced successfully."
        self.statusBar().showMessage(newstmsg)

    def resyncWallet(self):
        if not self.wallet:
            JMQtMessageBox(self,
                           "No wallet loaded",
                           mbtype='warn',
                           title="Error")
            return
        self.loadWalletFromBlockchain()

    def generateWallet(self):
        log.debug('generating wallet')
        if get_network() == 'testnet':
            seed = self.getTestnetSeed()
            self.selectWallet(testnet_seed=seed)
        else:
            self.initWallet()

    def getTestnetSeed(self):
        text, ok = QInputDialog.getText(
            self, 'Testnet seed', 'Enter a string as seed (can be anything):')
        if not ok or not text:
            JMQtMessageBox(self,
                           "No seed entered, aborting",
                           mbtype='warn',
                           title="Error")
            return
        return str(text).strip()

    def initWallet(self, seed=None):
        '''Creates a new mainnet
        wallet
        '''
        if not seed:
            seed = btc.sha256(os.urandom(64))[:32]
            words = mn_encode(seed)
            mb = QMessageBox()
            seed_recovery_warning = [
                "WRITE DOWN THIS WALLET RECOVERY SEED.",
                "If you fail to do this, your funds are",
                "at risk. Do NOT ignore this step!!!"
            ]
            mb.setText("\n".join(seed_recovery_warning))
            mb.setInformativeText(' '.join(words))
            mb.setStandardButtons(QMessageBox.Ok)
            ret = mb.exec_()

        pd = PasswordDialog()
        while True:
            pd.exec_()
            if pd.new_pw.text() != pd.conf_pw.text():
                JMQtMessageBox(self,
                               "Passwords don't match.",
                               mbtype='warn',
                               title="Error")
                continue
            break

        walletfile = create_wallet_file(str(pd.new_pw.text()), seed)
        walletname, ok = QInputDialog.getText(self, 'Choose wallet name',
                                              'Enter wallet file name:',
                                              QLineEdit.Normal, "wallet.json")
        if not ok:
            JMQtMessageBox(self, "Create wallet aborted", mbtype='warn')
            return
        #create wallets subdir if it doesn't exist
        if not os.path.exists('wallets'):
            os.makedirs('wallets')
        walletpath = os.path.join('wallets', str(walletname))
        # Does a wallet with the same name exist?
        if os.path.isfile(walletpath):
            JMQtMessageBox(self,
                           walletpath + ' already exists. Aborting.',
                           mbtype='warn',
                           title="Error")
            return
        else:
            fd = open(walletpath, 'w')
            fd.write(walletfile)
            fd.close()
            JMQtMessageBox(self,
                           'Wallet saved to ' + str(walletname),
                           title="Wallet created")
            self.loadWalletFromBlockchain(
                str(walletname), str(pd.new_pw.text()))


def get_wallet_printout(wallet):
    """Given a joinmarket wallet, retrieve the list of
    addresses and corresponding balances to be displayed;
    this could/should be a re-used function for both
    command line and GUI.
    The format of the retrieved data is:
    rows: is of format [[[addr,index,bal,used],[addr,...]]*5,
    [[addr, index,..], [addr, index..]]*5]
    mbalances: is a simple array of 5 mixdepth balances
    total_balance: whole wallet
    Bitcoin amounts returned are in btc, not satoshis
    """
    rows = []
    mbalances = []
    total_balance = 0
    for m in range(wallet.max_mix_depth):
        rows.append([])
        balance_depth = 0
        for forchange in [0, 1]:
            rows[m].append([])
            for k in range(wallet.index[m][forchange] + jm_single(
            ).config.getint("GUI", "gaplimit")):
                addr = wallet.get_addr(m, forchange, k)
                balance = 0.0
                for addrvalue in wallet.unspent.values():
                    if addr == addrvalue['address']:
                        balance += addrvalue['value']
                balance_depth += balance
                used = ('used' if k < wallet.index[m][forchange] else 'new')
                if balance > 0.0 or (k >= wallet.index[m][forchange] and
                                     forchange == 0):
                    rows[m][forchange].append([addr, str(k), "{0:.8f}".format(
                        balance / 1e8), used])
        mbalances.append(balance_depth)
        total_balance += balance_depth

    return (rows, ["{0:.8f}".format(x / 1e8) for x in mbalances],
            "{0:.8f}".format(total_balance / 1e8))

################################
config_load_error = False
app = QApplication(sys.argv)
try:
    load_program_config()
except Exception as e:
    config_load_error = "Failed to setup joinmarket: "+repr(e)
    if "RPC" in repr(e):
        config_load_error += '\n'*3 + ''.join(
            ["Errors about failed RPC connections usually mean an incorrectly ",
             "configured instance of Bitcoin Core (e.g. it hasn't been started ",
             "or the rpc ports are not correct in your joinmarket.cfg or your ",
             "bitcoin.conf file; see the joinmarket wiki for configuration details."
             ])
    JMQtMessageBox(None, config_load_error, mbtype='crit', title='failed to load')
    exit(1)
update_config_for_gui()

#for testing, TODO remove
jm_single().maker_timeout_sec = 5

#we're not downloading from github, so logs dir
#might not exist
if not os.path.exists('logs'):
    os.makedirs('logs')
appWindowTitle = 'JoinMarketQt'
w = JMMainWindow()
tabWidget = QTabWidget(w)
tabWidget.addTab(JMWalletTab(), "JM Wallet")
settingsTab = SettingsTab()
tabWidget.addTab(settingsTab, "Settings")
tabWidget.addTab(SpendTab(), "Send Payment")
tabWidget.addTab(TxHistoryTab(), "Tx History")
w.resize(600, 500)
suffix = ' - Testnet' if get_network() == 'testnet' else ''
w.setWindowTitle(appWindowTitle + suffix)
tabWidget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
w.setCentralWidget(tabWidget)
w.show()

sys.exit(app.exec_())
