#!/usr/bin/env python
from __future__ import print_function

'''
Qt files for the wizard for initiating a tumbler run.


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
import sys, math, re, logging, Queue
from collections import namedtuple
from decimal import Decimal

from PyQt4 import QtCore
from PyQt4.QtGui import *

from jmclient import (load_program_config, get_network, Wallet,
                      get_p2pk_vbyte, jm_single, validate_address,
                      get_log, weighted_order_choose, Taker,
                      JMTakerClientProtocolFactory, WalletError,
                      start_reactor, get_schedule, get_tumble_schedule)


GREEN_BG = "QWidget {background-color:#80ff80;}"
RED_BG = "QWidget {background-color:#ffcccc;}"
RED_FG = "QWidget {color:red;}"
BLUE_FG = "QWidget {color:blue;}"
BLACK_FG = "QWidget {color:black;}"

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
    'blockchain_source': 'options: blockr, bc.i, bitcoin-rpc',
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
              'Average wait time between transactions, in minutes',
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
        if jm_single().config.get("BLOCKCHAIN", "blockchain_source") == "regtest":
            testaddrs = ["mteaYsGsLCL9a4cftZFTpGEWXNwZyDt5KS",
                     "msFGHeut3rfJk5sKuoZNfpUq9MeVMqmido",
                     "mkZfBXCRPs8fCmwWLrspjCvYozDhK6Eepz"]
        else:
            testaddrs = ["","",""]
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
        self.setTitle("Advanced options")
        self.setSubTitle("(the default values are usually sufficient)")
        layout = QGridLayout()
        layout.setSpacing(4)

        results = []
        sN = ['Makercount sdev', 'Tx count sdev',
              'Amount power',
              'Minimum maker count',
              'Minimum transaction count',
              'Min coinjoin amount',
              'wait time']
        #Tooltips
        sH = ["Standard deviation of the number of makers to use in each "
              "transaction.",
        "Standard deviation of the number of transactions to use in each "
        "mixdepth",
        "A parameter to control the random coinjoin sizes.",
        "The lowest allowed number of maker counterparties.",
        "The lowest allowed number of transactions in one mixdepth.",
        "The lowest allowed size of any coinjoin, in satoshis.",
        "The time in seconds to wait for response from counterparties."]
        #types
        sT = [float, float, float, int, int, int, float]
        #constraints
        sMM = [(0.0, 10.0, 2), (0.0, 10.0, 2), (1.0, 10000.0, 1), (2,20),
               (1, 10), (100000, 100000000), (10.0, 500.0, 2)]
        sD = ['1.0', '1.0', '100.0', '2', '1', '1000000', '20']
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
        #fields not considered 'mandatory' as defaults are accepted
        self.registerField("makercountsdev", results[0][1])
        self.registerField("txcountsdev", results[1][1])
        self.registerField("amountpower", results[2][1])
        self.registerField("minmakercount", results[3][1])
        self.registerField("mintxcount", results[4][1])
        self.registerField("mincjamount", results[5][1])
        self.registerField("waittime", results[6][1])

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

    def get_name(self):
        #TODO de-hardcode generated name
        return "TUMBLE.schedule"
        #return self.field("schedfilename").toString()

    def get_destaddrs(self):
        return self.destaddrs

    def get_schedule(self):
        self.destaddrs = [str(x) for x in [self.field("destaddr0").toString(),
                     self.field("destaddr1").toString(),
                     self.field("destaddr2").toString()]]
        self.opts = {}
        self.opts['mixdepthsrc'] = int(self.field("mixdepthsrc").toString())
        self.opts['mixdepthcount'] = int(self.field("mixdepthcount").toString())
        self.opts['txfee'] = -1
        self.opts['addrcount'] = 3
        self.opts['makercountrange'] = (int(self.field("makercount").toString()),
                                    float(self.field("makercountsdev").toString()))
        self.opts['minmakercount'] = int(self.field("minmakercount").toString())
        self.opts['txcountparams'] = (int(self.field("txcountparams").toString()),
                                    float(self.field("txcountsdev").toString()))
        self.opts['mintxcount'] = int(self.field("mintxcount").toString())
        self.opts['amountpower'] = float(self.field("amountpower").toString())
        self.opts['timelambda'] = float(self.field("timelambda").toString())
        self.opts['waittime'] = float(self.field("waittime").toString())
        self.opts['mincjamount'] = int(self.field("mincjamount").toString())
        #needed for Taker to check:
        jm_single().mincjamount = self.opts['mincjamount']
        return get_tumble_schedule(self.opts, self.destaddrs)
