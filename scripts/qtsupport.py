#!/usr/bin/env python

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
import math, logging, qrcode, re, string
from io import BytesIO
from PySide2 import QtCore

from PySide2.QtGui import *
from PySide2.QtWidgets import *

from jmbitcoin.amount import amount_to_sat, btc_to_sat, sat_to_btc
from jmbitcoin.bip21 import decode_bip21_uri
from jmclient import (jm_single, validate_address, get_tumble_schedule)


GREEN_BG = "QWidget {background-color:#80ff80;}"
RED_BG = "QWidget {background-color:#ffcccc;}"
RED_FG = "QWidget {color:red;}"
BLUE_FG = "QWidget {color:blue;}"
BLACK_FG = "QWidget {color:black;}"

donation_address = 'Currently disabled'
donation_address_testnet = 'Currently disabled'

#TODO legacy, remove or change
warnings = {"blockr_privacy": """You are using blockr as your method of
connecting to the blockchain; this means
that blockr.com can see the addresses you
query. This is bad for privacy - consider
using a Bitcoin Core node instead."""}

#configuration types
config_types = {'rpc_port': int,
                'network': bool,
                'checktx': bool,
                'socks5_port': int,
                'maker_timeout_sec': int,
                'tx_fees': int,
                'gaplimit': int,
                'check_high_fee': int,
                'max_mix_depth': int,
                'order_wait_time': int,
                'no_daemon': int,
                'daemon_port': int,
                'absurd_fee_per_kb': 'amount'}
config_tips = {
    'blockchain_source': 'options: bitcoin-rpc, regtest (for testing)',
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
    'usessl': "'true'/'false' to use SSL for each connection to IRC\n",
    'socks5': "'true'/'false' to use a SOCKS5 proxy for each connection",
    'socks5_host': 'host for SOCKS5 proxy',
    'socks5_port': 'port for SOCKS5 proxy',
    'maker_timeout_sec': 'timeout for waiting for replies from makers',
    'merge_algorithm': 'for dust sweeping, try merge_algorithm = gradual, \n' +
    'for more rapid dust sweeping, try merge_algorithm = greedy, \n' +
    'for most rapid dust sweeping, try merge_algorithm = greediest \n',
    'tx_fees':
    'the fee estimate is based on a projection of how many satoshis \n' +
    'per kB are needed to get in one of the next N blocks, N set here \n' +
    'as the value of "tx_fees". This estimate is high if you set N=1, \n' +
    'so we choose N=3 for a more reasonable figure as our default.\n' +
    'Alternative: Any value higher than 1000 will be interpreted as \n' +
    'fee value in satoshi per KB. This overrides the dynamic estimation.',
    'gaplimit': 'How far forward to search for used addresses in the HD wallet',
    'check_high_fee': 'Percent fee considered dangerously high, default 2%',
    'max_mix_depth': 'Total number of mixdepths in the wallet, default 5',
    'order_wait_time': 'How long to wait for orders to arrive on entering\n' +
    'the message channel, default is 30s',
    'no_daemon': "1 means don't use a separate daemon; set to 0 only if you\n" +
    "are running an instance of joinmarketd separately",
    "daemon_port": "The port on which the joinmarket daemon is running",
    "daemon_host": "The host on which the joinmarket daemon is running; remote\n" +
    "hosts should be considered *highly* experimental for now, not recommended.",
    "use_ssl": "Set to 'true' to use TLS for client-daemon connection; see\n" +
    "documentation for details on how to set up certs if you use this.",
    "history_file": "Location of the file storing transaction history",
    "segwit": "Only used for migrating legacy wallets; see documentation.",
    "native": "NOT currently supported, except for PayJoin (command line only)",
    "console_log_level": "one of INFO, DEBUG, WARN, ERROR; INFO is least noisy;\n" +
    "consider switching to DEBUG in case of problems.",
    "absurd_fee_per_kb": "maximum amount per kilobyte you are willing to pay,\n" +
    "whatever the fee estimate currently says.",
    "tx_broadcast": "Options: self, random-peer, not-self (note: random-maker\n" +
    "is not currently supported).\n" +
    "self = broadcast transaction with your own ip\n" +
    "random-peer = everyone who took part in the coinjoin has\n" +
    "a chance of broadcasting.\n" +
    "not-self = never broadcast with your own ip.",
    "privacy_warning": "Not currently used, ignore.",
    "taker_utxo_retries": "Global consensus parameter, do NOT change.\n" +
    "See documentation of use of 'commitments'.",
    "taker_utxo_age": "Global consensus parameter, do NOT change.\n" +
    "See documentation of use of 'commitments'.",
    "taker_utxo_amtpercent": "Global consensus parameter, do not change.\n" +
    "See documentation of use of 'commitments'.",
    "accept_commitment_broadcasts": "Not used, ignore.",
    "commit_file_location": "Location of the file that stores the commitments\n" +
    "you've used, and any external commitments you've loaded.\n" +
    "See documentation of use of 'commitments'.",
    "listunspent_args": "Set to [1, 9999999] to show and use only coins that\n" +
    "are confirmed; set to [0] to spend all coins including unconfirmed; this\n" +
    "is not advisable.",
    "minimum_makers": "The minimum number of counterparties for the transaction\n" +
    "to complete (default 2). If set to a high value it can cause transactions\n" +
    "to fail much more frequently.",
    "max_sats_freeze_reuse": "Threshold number of satoshis below which an\n" +
    "incoming utxo to a reused address in the wallet will\n" +
    "be AUTOMATICALLY frozen. -1 means always freeze reuse.",
}

#Temporarily disabled
donation_more_message = "Currently disabled"
"""
donation_more_message = '\n'.join(
            ['If the calculated change for your transaction',
             'is smaller than the value you choose (default 0.01 btc)',
             'then that change is sent as a donation. If your change',
             'is larger than that, there will be no donation.', '',
             'As well as helping the developers, this feature can,',
             'in certain circumstances, improve privacy, because there',
             'is no change output that can be linked with your inputs later.'])
"""

def JMQtMessageBox(obj, msg, mbtype='info', title='', detailed_text= None):
    mbtypes = {'info': QMessageBox.information,
               'crit': QMessageBox.critical,
               'warn': QMessageBox.warning,
               'question': QMessageBox.question}
    title = "JoinmarketQt - " + title
    if mbtype == 'question':
        return QMessageBox.question(obj, title, msg, QMessageBox.Yes,
                                    QMessageBox.No)
    else:
        if detailed_text:
            assert mbtype == 'info'

            class JMQtDMessageBox(QMessageBox):
                def __init__(self):
                    QMessageBox.__init__(self)
                    self.setSizeGripEnabled(True)
                    self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
                    self.layout().setSizeConstraint(QLayout.SetMaximumSize)
                def resizeEvent(self, event):
                    self.setMinimumHeight(0)
                    self.setMaximumHeight(16777215)
                    self.setMinimumWidth(0)
                    self.setMaximumWidth(16777215)
                    result = super().resizeEvent(event)
                    details_box = self.findChild(QTextEdit)
                    if details_box is not None:
                        details_box.setMinimumHeight(0)
                        details_box.setMaximumHeight(16777215)
                        details_box.setMinimumWidth(0)
                        details_box.setMaximumWidth(16777215)
                        details_box.setSizePolicy(QSizePolicy.Expanding,
                                                  QSizePolicy.Expanding)
                    return result

            b = JMQtDMessageBox()
            b.setIcon(QMessageBox.Information)
            b.setWindowTitle(title)
            b.setText(msg)
            b.setDetailedText(detailed_text)
            b.setStandardButtons(QMessageBox.Ok)
            retval = b.exec_()
        else:
            mbtypes[mbtype](obj, title, msg)

class QtHandler(logging.Handler):

    def __init__(self):
        logging.Handler.__init__(self)

    def emit(self, record):
        record = self.format(record)
        if record: XStream.stdout().write('%s\n' % record)


class XStream(QtCore.QObject):
    _stdout = None
    _stderr = None
    messageWritten = QtCore.Signal(str)

    def flush(self):
        pass

    def fileno(self):
        return -1

    def write(self, msg):
        if (not self.signalsBlocked()):
            self.messageWritten.emit(msg)

    @staticmethod
    def stdout():
        if (not XStream._stdout):
            XStream._stdout = XStream()
            # temporarily removed, seems not needed
            #sys.stdout = XStream._stdout
        return XStream._stdout

    @staticmethod
    def stderr():
        if (not XStream._stderr):
            XStream._stderr = XStream()
            # temporarily removed, seems not needed
            #sys.stderr = XStream._stderr
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


def make_password_dialog(self, msg):

    self.new_pw = QLineEdit()
    self.new_pw.setEchoMode(QLineEdit.EchoMode(2))
    self.conf_pw = QLineEdit()
    self.conf_pw.setEchoMode(QLineEdit.EchoMode(2))

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

    grid.addWidget(QLabel('New Passphrase'), 1, 0)
    grid.addWidget(self.new_pw, 1, 1)

    grid.addWidget(QLabel('Confirm Passphrase'), 2, 0)
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
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Create a new passphrase')
        msg = "Enter a new passphrase"
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
            #note, a single stretch column is currently not used.
            self.header().setSectionResizeMode(col, QHeaderView.Interactive)

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
        key = str(item.data(0, Qt.UserRole))
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

# TODO implement this option
#class SchStaticPage(QWizardPage):
#    def __init__(self, parent):
#        super().__init__(parent)
#        self.setTitle("Manually create a schedule entry")
#        layout = QGridLayout()
#        wdgts = getSettingsWidgets()
#        for i, x in enumerate(wdgts):
#            layout.addWidget(x[0], i + 1, 0)
#            layout.addWidget(x[1], i + 1, 1, 1, 2)
#        wdgts[0][1].editingFinished.connect(
#                    lambda: checkAddress(self, wdgts[0][1].text()))
#        self.setLayout(layout)

class JMIntValidator(QIntValidator):
    def __init__(self, minval, maxval):
        super().__init__(minval, maxval)
        self.minval = minval
        self.maxval = maxval
        self.allowed = set(string.digits)

    def validate(self, arg__1, arg__2):
        if not arg__1:
            return QValidator.Intermediate
        if not set(arg__1) <= self.allowed:
            return QValidator.Invalid
        # above guarantees integer
        if not (int(arg__1) <= self.maxval and int(arg__1) >= self.minval):
            return QValidator.Invalid
        return super().validate(arg__1, arg__2)

class BitcoinAmountBTCValidator(QDoubleValidator):

    def __init__(self):
        super().__init__(0.00000000, 20999999.9769, 8)
        self.setLocale(QtCore.QLocale.c())
        # Only numbers and "." as a decimal separator must be allowed,
        # no thousands separators, as per BIP21
        self.allowed = set(string.digits + ".")

    def validate(self, arg__1, arg__2):
        if not arg__1:
            return QValidator.Intermediate
        if not set(arg__1) <= self.allowed:
            return QValidator.Invalid
        return super().validate(arg__1, arg__2)


class BitcoinAmountSatValidator(JMIntValidator):

    def __init__(self):
        super().__init__(0, 2147483647)

class BitcoinAmountEdit(QWidget):

    def __init__(self, default_value):
        super().__init__()
        layout = QHBoxLayout()
        layout.setSizeConstraint(QLayout.SetMaximumSize)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(1)
        self.valueInputBox = QLineEdit()
        self.editingFinished = self.valueInputBox.editingFinished
        layout.addWidget(self.valueInputBox)
        self.unitChooser = QComboBox()
        self.unitChooser.setInsertPolicy(QComboBox.NoInsert)
        self.unitChooser.addItems(["BTC", "sat"])
        self.unitChooser.currentIndexChanged.connect(self.onUnitChanged)
        self.BTCValidator = BitcoinAmountBTCValidator()
        self.SatValidator = BitcoinAmountSatValidator()
        self.setModeBTC()
        layout.addWidget(self.unitChooser)
        if default_value:
            self.valueInputBox.setText(str(sat_to_btc(amount_to_sat(
                default_value))))
        self.setLayout(layout)

    def setModeBTC(self):
        self.valueInputBox.setPlaceholderText("0.00000000")
        self.valueInputBox.setMaxLength(17)
        self.valueInputBox.setValidator(self.BTCValidator)

    def setModeSat(self):
        self.valueInputBox.setPlaceholderText("0")
        self.valueInputBox.setMaxLength(16)
        self.valueInputBox.setValidator(self.SatValidator)

    # index: 0 - BTC, 1 - sat
    def onUnitChanged(self, index):
        if index == 0:
            # switch from sat to BTC
            sat_amount = self.valueInputBox.text()
            self.setModeBTC()
            if sat_amount:
                self.valueInputBox.setText('%.8f' % sat_to_btc(sat_amount))
        else:
            # switch from BTC to sat
            btc_amount = self.valueInputBox.text()
            self.setModeSat()
            if btc_amount:
                self.valueInputBox.setText(str(btc_to_sat(btc_amount)))

    def setText(self, text):
        if text:
            if self.unitChooser.currentIndex() == 0:
                self.valueInputBox.setText(str(sat_to_btc(text)))
            else:
                self.valueInputBox.setText(str(text))
        else:
            self.valueInputBox.setText('')

    def setEnabled(self, enabled):
        self.valueInputBox.setEnabled(enabled)
        self.unitChooser.setEnabled(enabled)

    def text(self):
        if len(self.valueInputBox.text()) == 0:
            return ''
        elif self.unitChooser.currentIndex() == 0:
            return str(btc_to_sat(self.valueInputBox.text()))
        else:
            return self.valueInputBox.text()


class SchDynamicPage1(QWizardPage):
    def __init__(self, parent):
        super().__init__(parent)
        self.setTitle("Tumble schedule generation")
        self.setSubTitle("Set parameters for the sequence of transactions in the tumble.")
        results = []
        sN = ['Starting mixdepth', 'Average number of counterparties',
              'How many mixdepths to tumble through',
              'Average wait time between transactions, in minutes',
              'Average number of transactions per mixdepth']
        #Tooltips
        sH = ["The starting mixdepth can be decided from the Wallet tab; it must\n"
        "have coins in it, but it's OK if some coins are in other mixdepths.",
        "How many other participants are in each coinjoin, on average; but\n"
        "each individual coinjoin will have a number that's varied according to\n"
        "settings on the next page",
        "For example, if you start at mixdepth 1 and enter 4 here, the tumble\n"
        "will move coins from mixdepth 1 to mixdepth 5",
        "This is the time waited *after* 1 confirmation has occurred, and is\n"
        "varied randomly.",
        "Will be varied randomly, see advanced settings next page"]
        #types
        sT = [int, int, int, float, int]
        #constraints
        sMM = [(0, jm_single().config.getint("GUI", "max_mix_depth") - 1), (3, 20),
               (2, 7), (0.00000001, 100.0, 8), (2, 10)]
        sD = ['0', '9', '4', '60.0', '2']
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
        self.registerField("mixdepthsrc", results[0][1])
        self.registerField("makercount", results[1][1])
        self.registerField("mixdepthcount", results[2][1])
        self.registerField("timelambda", results[3][1])
        self.registerField("txcountparams", results[4][1])

class SchDynamicPage2(QWizardPage):

    def initializePage(self):
        addrLEs = []
        requested_mixdepths = int(self.field("mixdepthcount"))
        #for testing
        if jm_single().config.get("BLOCKCHAIN", "blockchain_source") == "regtest":
            testaddrs = ["mteaYsGsLCL9a4cftZFTpGEWXNwZyDt5KS",
                     "msFGHeut3rfJk5sKuoZNfpUq9MeVMqmido",
                     "mkZfBXCRPs8fCmwWLrspjCvYozDhK6Eepz"]
        else:
            testaddrs = ["","",""]
        #less than 3 is unacceptable for privacy effect, more is optional
        self.required_addresses = max(3, requested_mixdepths - 1)
        for i in range(self.required_addresses):
            if i >= self.addrfieldsused:
                self.layout.addWidget(QLabel("Destination address: " + str(i)), i, 0)
                if i < len(testaddrs):
                    addrLEs.append(QLineEdit(testaddrs[i]))
                else:
                    addrLEs.append(QLineEdit(""))
                self.layout.addWidget(addrLEs[-1], i, 1, 1, 2)
                #addrLEs[-1].editingFinished.connect(
                #    lambda: checkAddress(self, addrLEs[-1].text()))
                self.registerField("destaddr"+str(i), addrLEs[-1])
        self.addrfieldsused = self.required_addresses
        self.setLayout(self.layout)

    def __init__(self, parent):
        super().__init__(parent)
        self.setTitle("Destination addresses")
        self.setSubTitle("Enter destination addresses for coins; "
                        "minimum 3 for privacy. You may leave later ones blank.")
        self.layout = QGridLayout()
        self.layout.setSpacing(4)
        self.addrfieldsused = 0

class SchFinishPage(QWizardPage):
    def __init__(self, parent):
        super().__init__(parent)
        self.setTitle("Advanced options")
        self.setSubTitle("(the default values are usually sufficient)")
        layout = QGridLayout()
        layout.setSpacing(4)

        results = []
        sN = ['Makercount sdev',
              'Tx count sdev',
              'Minimum maker count',
              'Minimum transaction count',
              'Min coinjoin amount',
              'Response wait time',
              'Stage 1 transaction wait time increase',
              'Rounding Chance']
        for w in ["One", "Two", "Three", "Four", "Five"]:
            sN += [w + " significant figures rounding weight"]
        #Tooltips
        sH = ["Standard deviation of the number of makers to use in each "
                  "transaction.",
              "Standard deviation of the number of transactions to use in each "
                  "mixdepth",
              "The lowest allowed number of maker counterparties.",
              "The lowest allowed number of transactions in one mixdepth.",
              "The lowest allowed size of any coinjoin, in satoshis.",
              "The time in seconds to wait for response from counterparties.",
              "The factor increase in wait time for stage 1 sweep coinjoins",
              "The probability of non-sweep coinjoin amounts being rounded"]
        for w in ["one", "two", "three", "four", "five"]:
            sH += ["If rounding happens (determined by Rounding Chance) then this "
                "is the relative probability of rounding to " + w +
                " significant figures"]
        #types
        sT = [float, float, int, int, int, float, float, float] + [int]*5
        #constraints
        sMM = [(0.0, 10.0, 2), (0.0, 10.0, 2), (2,20),
               (1, 10), (100000, 100000000), (10.0, 500.0, 2), (0, 100, 1),
               (0.0, 1.0, 3)] + [(0, 10000)]*5
        sD = ['1.0', '1.0', '2', '2', '1000000', '20', '3', '0.25'] +\
                 ['55', '15', '25', '65', '40']
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
        self.registerField("minmakercount", results[2][1])
        self.registerField("mintxcount", results[3][1])
        self.registerField("mincjamount", results[4][1])
        self.registerField("waittime", results[5][1])
        self.registerField("stage1_timelambda_increase", results[6][1])
        self.registerField("rounding_chance", results[7][1])
        for i in range(5):
            self.registerField("rounding_sigfig_weight_" + str(i+1), results[8+i][1])

class SchIntroPage(QWizardPage):
    def __init__(self, parent):
        super().__init__(parent)
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
        super().__init__()
        self.setWindowTitle("Joinmarket schedule generator")
        self.setPage(0, SchIntroPage(self))
        self.setPage(1, SchDynamicPage1(self))
        self.setPage(2, SchDynamicPage2(self))
        #self.setPage(3, SchStaticPage(self))
        self.setPage(3, SchFinishPage(self))

    def get_name(self):
        #TODO de-hardcode generated name
        return "TUMBLE.schedule"


    def get_destaddrs(self):
        return self.destaddrs

    def get_schedule(self, wallet_balance_by_mixdepth):
        self.destaddrs = []
        for i in range(self.page(2).required_addresses):
            daddrstring = str(self.field("destaddr"+str(i)))
            if validate_address(daddrstring)[0]:
                self.destaddrs.append(daddrstring)
            elif daddrstring != "":
                JMQtMessageBox(self, "Error, invalid address", mbtype='crit',
                               title='Error')
                return None
        self.opts = {}
        self.opts['mixdepthsrc'] = int(self.field("mixdepthsrc"))
        self.opts['mixdepthcount'] = int(self.field("mixdepthcount"))
        self.opts['txfee'] = -1
        self.opts['addrcount'] = len(self.destaddrs)
        self.opts['makercountrange'] = (int(self.field("makercount")),
                                    float(self.field("makercountsdev")))
        self.opts['minmakercount'] = int(self.field("minmakercount"))
        self.opts['txcountparams'] = (int(self.field("txcountparams")),
                                    float(self.field("txcountsdev")))
        self.opts['mintxcount'] = int(self.field("mintxcount"))
        self.opts['timelambda'] = float(self.field("timelambda"))
        self.opts['waittime'] = float(self.field("waittime"))
        self.opts["stage1_timelambda_increase"] = float(self.field("stage1_timelambda_increase"))
        self.opts['mincjamount'] = int(self.field("mincjamount"))
        #needed for Taker to check:
        self.opts['rounding_chance'] = float(self.field("rounding_chance"))
        self.opts['rounding_sigfig_weights'] = tuple([int(self.field("rounding_sigfig_weight_" + str(i+1))) for i in range(5)])
        jm_single().mincjamount = self.opts['mincjamount']
        return get_tumble_schedule(self.opts, self.destaddrs,
            wallet_balance_by_mixdepth)

class TumbleRestartWizard(QWizard):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Restart tumbler schedule")
        self.setPage(0, RestartSettingsPage(self))

    def getOptions(self):
        self.opts = {}
        self.opts['mincjamount'] = int(self.field("mincjamount"))
        relfeeval = float(self.field("maxrelfee"))
        absfeeval = int(self.field("maxabsfee"))
        self.opts['maxcjfee'] = (relfeeval, absfeeval)
        #needed for Taker to check:
        jm_single().mincjamount = self.opts['mincjamount']
        return self.opts

class RestartSettingsPage(QWizardPage):

    def __init__(self, parent):
        super().__init__(parent)
        self.setTitle("Tumbler options")
        self.setSubTitle("Options settings that can be varied on restart")
        layout = QGridLayout()
        layout.setSpacing(4)

        results = []
        sN = ['Min coinjoin amount',
              'Max relative fee per counterparty (e.g. 0.005)',
              'Max fee per counterparty, satoshis (e.g. 10000)']
        #Tooltips
        sH = ["The lowest allowed size of any coinjoin, in satoshis.",
        "A decimal fraction (e.g. 0.001 = 0.1%) (this AND next must be violated to reject",
        "Integer number of satoshis (this AND previous must be violated to reject)"]
        #types
        sT = [int, float, int]
        #constraints
        sMM = [(100000, 100000000), (0.000001, 0.25, 6),
               (0, 10000000)]
        sD = ['1000000', '0.0005', '10000']
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
        self.registerField("mincjamount", results[0][1])
        self.registerField("maxrelfee", results[1][1])
        self.registerField("maxabsfee", results[2][1])

class CopyOnClickLineEdit(QLineEdit):
    """ Small wrapper class around QLineEdit
        to support copy-to-clipboard-on-click.
    """
    def __init__(self, s):
        # This is needed to prevent
        # infinite loop, but
        # TODO: This is very suboptimal
        # since the copy can only be done once.
        self.was_copied = False
        super().__init__(s)

    def focusInEvent(self, event):
        super().focusInEvent(event)
        self.selectAll()
        self.copy()
        if not self.was_copied:
            JMQtMessageBox(self,
                "URI copied to clipboard", mbtype="info")
        self.was_copied = True


class QRCodePopup(QDialog):

    def __init__(self, parent, title, data):
        super().__init__(parent)
        self.setWindowTitle(title)
        buf = BytesIO()
        img = qrcode.make(data)
        img.save(buf, "PNG")
        self.imageLabel = QLabel()
        qt_pixmap = QPixmap()
        qt_pixmap.loadFromData(buf.getvalue(), "PNG")
        self.imageLabel.setPixmap(qt_pixmap)
        layout = QVBoxLayout()
        layout.addWidget(self.imageLabel)
        self.setLayout(layout)
        self.initUI()

    def initUI(self):
        self.show()


class ReceiveBIP78Dialog(QDialog):

    parameter_names = ['Amount to receive', 'Mixdepth']
    parameter_tooltips = [
     "How much you should receive (after any fees) in BTC or sats.",
     "The mixdepth you source coins from to create inputs for the\n"
     "payjoin. Note your receiving address will be chosen from the\n"
     "*next* mixdepth after this (or 0 if last)."]
    parameter_types = ["btc", int]
    parameter_settings = ["", 0]

    def __init__(self, action_fn, cancel_fn, parameter_settings=None):
        """ Parameter action_fn:
        each time the user opens the dialog they will
        pass a function to be connected to the action-button.
        Signature: no arguments, return value False if action initiation
        is aborted, otherwise True.
        """
        super().__init__()
        if parameter_settings:
            self.parameter_settings = parameter_settings
        # these QLineEdit or QLabel objects will contain the
        # settings for the receiver as chosen by the user:
        self.receiver_settings_ql = []
        self.action_fn = action_fn
        # callback for actions to take when closing this dialog:
        self.cancel_fn = cancel_fn
        self.updates_final = False
        self.initUI()

    def initUI(self):
        self.setModal(1)
        self.setWindowTitle("Receive Payjoin")
        self.setLayout(self.get_receive_bip78_dialog())
        self.show()

    def info_update(self, msg):
        """ Sets update text in the dialog to the str
        parameter msg, but does not overwrite after that,
        if the message ends with ":FINAL".
        TODO: Info updates need to be richer, supporting
        multiple messages.
        """
        if not self.updates_final:
            if msg.endswith(":FINAL"):
                self.updates_final = True
                msg = msg.split(":FINAL")[0]
            self.updates_label.setText(msg)

    def get_amount_text(self):
        return self.receiver_settings_ql[0][1].text()

    def get_mixdepth(self):
        return int(self.receiver_settings_ql[1][1].text())

    def update_uri(self, uri):
        self.bip21_widget.setDisabled(False)
        self.bip21_widget.setText(uri)
        self.bip21_widget.was_copied = False

    def shutdown_actions(self):
        self.cancel_fn()
        self.close()

    def process_complete(self):
        """ Called by the owning Qt object
        when the BIP78 workflow is complete,
        whether successful or not.
        """
        # Give user indication that they
        # can quit without cancelling:
        self.close_btn.setVisible(True)
        self.qr_btn.setVisible(False)
        self.btnbox.button(QDialogButtonBox.Cancel).setDisabled(True)

    def start_generate(self):
        """ Before starting up the
        hidden service and initiating the payment
        workflow, disallow starting again; user
        will need to close and reopen to restart.
        If the 'start generate request' action is
        aborted, we reset the generate button.
        """
        self.generate_btn.setDisabled(True)
        if not self.action_fn():
            self.generate_btn.setDisabled(False)

    def get_receive_bip78_dialog(self):
        """ Displays editable parameters and
        BIP21 URI once the receiver is ready.
        """
        # TODO: allow custom mixdepths
        valid_ranges = [None, (0, 4)]

        # note that this iteration is not currently helpful,
        # if anything making the code *more* verbose, but could be
        # if we add several more fields:
        for x in zip(self.parameter_names, self.parameter_tooltips,
                     self.parameter_types, self.parameter_settings,
                     valid_ranges):
            ql = QLabel(x[0])
            ql.setToolTip(x[1])
            editfield = BitcoinAmountEdit if x[2] == "btc" else QLineEdit
            ql2 = editfield(str(x[3]))
            if x[4]:
                if x[2] == int:
                    ql2.setValidator(QIntValidator(*x[4]))
                elif x[2] == float:
                    ql2.setValidator(QDoubleValidator(*x[4]))
                # note no validators for the btc type as that
                # has its own internal validation.
            self.receiver_settings_ql.append((ql, ql2))
        layout = QGridLayout(self)
        layout.setSpacing(4)
        for i, x in enumerate(self.receiver_settings_ql):
            layout.addWidget(x[0], i + 1, 0)
            layout.addWidget(x[1], i + 1, 1, 1, 2)

        # As well as editable settings, we also need two more
        # fields: one for information updates, and one for the
        # final (copyable) URI:
        self.updates_label = QLabel("Waiting ...")
        self.bip21_widget = CopyOnClickLineEdit("")
        self.bip21_widget.setReadOnly(True)
        # Note that the initial state is disabled, meaning
        # click events won't register and it won't look editable:
        self.bip21_widget.setDisabled(True)
        layout.addWidget(self.updates_label, i+2, 0, 1, 2)
        layout.addWidget(self.bip21_widget, i+3, 0, 1, 2)

        # Buttons for start/cancel/close:
        self.btnbox = QDialogButtonBox()
        self.btnbox.setStandardButtons(QDialogButtonBox.Cancel)
        self.generate_btn = self.btnbox.addButton("&Generate request",
                                                  QDialogButtonBox.ActionRole)
        self.close_btn = self.btnbox.addButton("C&lose",
                                               QDialogButtonBox.AcceptRole)
        self.close_btn.setVisible(False)
        self.qr_btn = self.btnbox.addButton("Show &QR code",
                                            QDialogButtonBox.ActionRole)
        layout.addWidget(self.btnbox, i+4, 0)
        # note that we don't use a standard 'Close' button because
        # it is also associated with 'rejection' (and we don't use "OK" because
        # concept doesn't quite fit here:
        self.btnbox.rejected.connect(self.shutdown_actions)
        self.generate_btn.clicked.connect(self.start_generate)
        self.qr_btn.clicked.connect(self.open_qr_code_popup)
        # does not trigger cancel_fn callback:
        self.close_btn.clicked.connect(self.close)
        return layout

    def open_qr_code_popup(self):
        bip21_uri = self.bip21_widget.text()
        if bip21_uri:
            parsed_uri = decode_bip21_uri(bip21_uri)
            popup = QRCodePopup(self, parsed_uri['address'], bip21_uri)
            popup.show()
