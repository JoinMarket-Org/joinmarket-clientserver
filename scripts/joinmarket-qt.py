#!/usr/bin/env python3
from future.utils import iteritems

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

import sys, datetime, os, logging
import platform, json, threading, time
import qrcode
from optparse import OptionParser

from PySide2 import QtCore

from PySide2.QtGui import *

from PySide2.QtWidgets import *

from PIL.ImageQt import ImageQt

if platform.system() == 'Windows':
    MONOSPACE_FONT = 'Lucida Console'
elif platform.system() == 'Darwin':
    MONOSPACE_FONT = 'Monaco'
else:
    MONOSPACE_FONT = 'monospace'

import jmbitcoin as btc

# This is required to change the decimal separator
# to '.' regardless of the locale; TODO don't require
# this, but will require other edits for parsing amounts.
curL = QtCore.QLocale("en_US")
QtCore.QLocale.setDefault(curL)

app = QApplication(sys.argv)
if 'twisted.internet.reactor' in sys.modules:
    del sys.modules['twisted.internet.reactor']

import qt5reactor
qt5reactor.install()

#General Joinmarket donation address; TODO
donation_address = "1AZgQZWYRteh6UyF87hwuvyWj73NvWKpL"
donation_address_sw = "bc1q5x02zqj5nshw0yhx2s4tj75z6vkvuvww26jak5"
donation_address_url = "https://bitcoinprivacy.me/joinmarket-donations"

#Version of this Qt script specifically
JM_GUI_VERSION = '15'

from jmbase import get_log
from jmbase.support import DUST_THRESHOLD, EXIT_FAILURE, utxo_to_utxostr,\
    bintohex, hextobin, JM_CORE_VERSION
from jmclient import load_program_config, get_network, update_persist_config,\
    open_test_wallet_maybe, get_wallet_path,\
    jm_single, validate_address, weighted_order_choose, Taker,\
    JMClientProtocolFactory, start_reactor, get_schedule, schedule_to_text,\
    get_blockchain_interface_instance, direct_send, WalletService,\
    RegtestBitcoinCoreInterface, tumbler_taker_finished_update,\
    get_tumble_log, restart_wait, tumbler_filter_orders_callback,\
    wallet_generate_recover_bip39, wallet_display, get_utxos_enabled_disabled,\
    NO_ROUNDING, get_max_cj_fee_values, get_default_max_absolute_fee, \
    get_default_max_relative_fee, RetryableStorageError, add_base_options, \
    BTCEngine, BTC_P2SH_P2WPKH, FidelityBondMixin, wallet_change_passphrase, \
    parse_payjoin_setup, send_payjoin
from qtsupport import ScheduleWizard, TumbleRestartWizard, config_tips,\
    config_types, QtHandler, XStream, Buttons, OkButton, CancelButton,\
    PasswordDialog, MyTreeWidget, JMQtMessageBox, BLUE_FG,\
    donation_more_message, BitcoinAmountEdit, JMIntValidator

from twisted.internet import task

log = get_log()

def update_config_for_gui():
    '''The default joinmarket config does not contain these GUI settings
    (they are generally set by command line flags or not needed).
    If they are set in the file, use them, else set the defaults.
    '''
    gui_config_names = ['gaplimit', 'history_file', 'check_high_fee',
                        'max_mix_depth', 'order_wait_time', 'checktx']
    gui_config_default_vals = ['6', 'jm-tx-history.txt', '2', '5', '30',
                               'true']
    if "GUI" not in jm_single().config.sections():
        jm_single().config.add_section("GUI")
    gui_items = jm_single().config.items("GUI")
    for gcn, gcv in zip(gui_config_names, gui_config_default_vals):
        if gcn not in [_[0] for _ in gui_items]:
            jm_single().config.set("GUI", gcn, gcv)



handler = QtHandler()
handler.setFormatter(logging.Formatter("%(levelname)s:%(message)s"))
log.addHandler(handler)

class HelpLabel(QLabel):

    def __init__(self, text, help_text, wtitle):
        QLabel.__init__(self, text)
        self.help_text = help_text
        self.wtitle = wtitle
        self.font = QFont()
        self.setStyleSheet(BLUE_FG)

    def mouseReleaseEvent(self, x):
        QMessageBox.information(mainWindow, self.wtitle, self.help_text)

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

class SettingsTab(QDialog):

    def __init__(self):
        super().__init__()
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
            if section == 'TIMEOUT' and 'maker_timeout_sec' not in [
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
                mainWindow.setWindowTitle(appWindowTitle + add)
            else:
                oname = str(t[0].text())
                oval = 'true' if checked else 'false'
            log.debug('setting section: ' + section + ' and name: ' + oname +
                      ' to: ' + oval)
            if not update_persist_config(section, oname, oval):
                log.warn("Unable to persist config change to file: " + str(section) + str(oname) + str(oval))

        else:  #currently there is only QLineEdit
            log.debug('setting section: ' + section + ' and name: ' + str(t[
                0].text()) + ' to: ' + str(t[1].text()))
            if not update_persist_config(section, str(t[0].text()), str(t[1].text())):
                # we don't include GUI as it's not required to be persisted:
                if not section == "GUI":
                    log.warn("Unable to persist config change to file: " + str(
                        section) + str(t[0].text()) + str(t[1].text()))
            if str(t[0].text()) == 'blockchain_source':
                jm_single().bc_interface = get_blockchain_interface_instance(
                    jm_single().config)
            if str(t[0].text()) == 'maker_timeout_sec':
                jm_single().maker_timeout_sec = int(t[1].text())
                log.debug("Set maker timeout sec to : " + str(jm_single().maker_timeout_sec))

    def getSettingsFields(self, section, names):
        results = []
        for name in names:
            val = jm_single().config.get(section, name)
            if name in config_types:
                t = config_types[name]
                if t == bool:
                    sf = QCheckBox()
                    if val == 'testnet' or val.lower() == 'true':
                        sf.setChecked(True)
                elif t == 'amount':
                    sf = BitcoinAmountEdit(val)
                elif not t:
                    continue
                else:
                    sf = QLineEdit(val)
                    if t == int:
                        if name in ["port", "rpc_port", "socks5_port",
                                    "daemon_port"]:
                            sf.setValidator(JMIntValidator(1, 65535))
                        elif name == "tx_fees":
                            # must account for both tx_fees settings type,
                            # and we set upper limit well above default absurd
                            # check just in case a high value is needed:
                            sf.setValidator(JMIntValidator(1, 1000000))
            else:
                sf = QLineEdit(val)
            label = 'Testnet' if name == 'network' else name
            results.append((QLabel(label), sf))
        return results

class SpendStateMgr(object):
    """A primitive class keep track of the mode
    in which the spend tab is being run
    """
    def __init__(self, updatecallback):
        self.reset_vars()
        self.updatecallback = updatecallback

    def updateType(self, t):
        self.typestate = t
        self.updatecallback()

    def updateRun(self, r):
        self.runstate = r
        self.updatecallback()

    def reset_vars(self):
        self.typestate = 'single'
        self.runstate = 'ready'
        self.schedule_name = None
        self.loaded_schedule = None

    def reset(self):
        self.reset_vars()
        self.updatecallback()

class SpendTab(QWidget):

    def __init__(self):
        super().__init__()
        self.initUI()
        self.taker = None
        self.filter_offers_response = None
        self.clientfactory = None
        self.tumbler_options = None
        #timer for waiting for confirmation on restart
        self.restartTimer = QtCore.QTimer()
        #timer for wait for next transaction
        self.nextTxTimer = None
        #tracks which mode the spend tab is run in
        self.spendstate = SpendStateMgr(self.toggleButtons)
        self.spendstate.reset() #trigger callback to 'ready' state
        # needed to be saved for parse_payjoin_setup()
        self.bip21_uri = None

    def switchToBIP78Payjoin(self, endpoint_url):
        self.numCPLabel.setVisible(False)
        self.numCPInput.setVisible(False)
        self.pjEndpointInput.setText(endpoint_url)
        self.pjEndpointLabel.setVisible(True)
        self.pjEndpointInput.setVisible(True)

        # while user is attempting a payjoin, address
        # cannot be edited; to back out, they hit Abort.
        self.addressInput.setEnabled(False)
        self.abortButton.setEnabled(True)

    def switchToJoinmarket(self):
        self.pjEndpointLabel.setVisible(False)
        self.pjEndpointInput.setVisible(False)
        self.pjEndpointInput.setText('')
        self.numCPLabel.setVisible(True)
        self.numCPInput.setVisible(True)

    def clearFields(self, ignored):
        self.switchToJoinmarket()
        self.addressInput.setText('')
        self.amountInput.setText('')
        self.addressInput.setEnabled(True)
        self.pjEndpointInput.setEnabled(True)
        self.mixdepthInput.setEnabled(True)
        self.amountInput.setEnabled(True)
        self.startButton.setEnabled(True)
        self.abortButton.setEnabled(False)

    def checkAddress(self, addr):
        addr = addr.strip()
        if btc.is_bip21_uri(addr):
            try:
                parsed = btc.decode_bip21_uri(addr)
            except ValueError as e:
                JMQtMessageBox(self,
                    "Bitcoin URI not valid.\n" + str(e),
                    mbtype='warn',
                    title="Error")
                return
            self.bip21_uri = addr
            addr = parsed['address']
            if 'amount' in parsed:
                self.amountInput.setText(parsed['amount'])
            if 'pj' in parsed:
                self.switchToBIP78Payjoin(parsed['pj'])
            else:
                self.switchToJoinmarket()
        else:
            self.bip21_uri = None

        self.addressInput.setText(addr)
        valid, errmsg = validate_address(str(addr))
        if not valid:
            JMQtMessageBox(self,
                       "Bitcoin address not valid.\n" + errmsg,
                       mbtype='warn',
                       title="Error")

    def checkAmount(self, amount_str):
        if not amount_str:
            return False
        try:
            amount_sat = btc.amount_to_sat(amount_str)
        except ValueError as e:
            JMQtMessageBox(self, e.args[0], title="Error", mbtype="warn")
            return False
        if amount_sat < DUST_THRESHOLD:
            JMQtMessageBox(self,
                       "Amount " + btc.amount_to_str(amount_sat) +
                       " is below dust threshold " +
                       btc.amount_to_str(DUST_THRESHOLD) + ".",
                       mbtype='warn',
                       title="Error")
            return False
        return True

    def generateTumbleSchedule(self):
        if not mainWindow.wallet_service:
            JMQtMessageBox(self, "Cannot start without a loaded wallet.",
                           mbtype="crit", title="Error")
            return
        #needs a set of tumbler options and destination addresses, so needs
        #a wizard
        wizard = ScheduleWizard()
        wizard_return = wizard.exec_()
        if wizard_return == QDialog.Rejected:
            return
        self.spendstate.loaded_schedule = wizard.get_schedule(
            mainWindow.wallet_service.get_balance_by_mixdepth())
        self.spendstate.schedule_name = wizard.get_name()
        self.updateSchedView()
        self.tumbler_options = wizard.opts
        self.tumbler_destaddrs = wizard.get_destaddrs()
        #tumbler may require more mixdepths; update the wallet
        required_mixdepths = max([tx[0] for tx in self.spendstate.loaded_schedule])
        if required_mixdepths > jm_single().config.getint("GUI", "max_mix_depth"):
            jm_single().config.set("GUI", "max_mix_depth", str(required_mixdepths))
            #recreate wallet and sync again; needed due to cache.
            JMQtMessageBox(self,
            "Max mixdepth has been reset to: " + str(required_mixdepths) + ".\n" +
            "Please choose 'Load' from the Wallet menu and resync before running.",
            title='Wallet resync required')
            return
        self.sch_startButton.setEnabled(True)

    def selectSchedule(self):
        current_path = os.path.dirname(os.path.realpath(__file__))
        firstarg = QFileDialog.getOpenFileName(self,
                                               'Choose Schedule File',
                                               directory=current_path,
                                               options=QFileDialog.DontUseNativeDialog)
        #TODO validate the schedule
        log.debug('Looking for schedule in: ' + str(firstarg))
        if not firstarg:
            return
        #extract raw text before processing
        with open(firstarg[0], 'rb') as f:
            rawsched = f.read()

        res, schedule = get_schedule(firstarg[0])
        if not res:
            JMQtMessageBox(self, "Not a valid JM schedule file", mbtype='crit',
                           title='Error')
        else:
            mainWindow.statusBar().showMessage("Schedule loaded OK.")
            self.spendstate.loaded_schedule = schedule
            self.spendstate.schedule_name = os.path.basename(str(firstarg[0]))
            self.updateSchedView()
            if self.spendstate.schedule_name == "TUMBLE.schedule":
                reply = JMQtMessageBox(self, "An incomplete tumble run detected. "
                                       "\nDo you want to restart?",
                                       title="Restart detected", mbtype='question')
                if reply != QMessageBox.Yes:
                    self.giveUp()
                    return
                self.tumbler_options = True

    def updateSchedView(self):
        self.sch_label2.setText(self.spendstate.schedule_name)
        self.sched_view.setText(schedule_to_text(self.spendstate.loaded_schedule).decode('utf-8'))

    def getDonateLayout(self):
        donateLayout = QHBoxLayout()
        self.donateCheckBox = QCheckBox()
        self.donateCheckBox.setChecked(False)
        #Temporarily disabled
        self.donateCheckBox.setEnabled(False)
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
        label3 = HelpLabel('More', donation_more_message,
                           'About the donation feature')
        label3.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        donateLayout.setAlignment(label3, QtCore.Qt.AlignLeft)
        donateLayout.addWidget(label3)
        donateLayout.addStretch(1)
        return donateLayout

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
        current_schedule_layout = QVBoxLayout()
        sch_label1=QLabel("Current schedule: ")
        sch_label1.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.sch_label2 = QLabel("None")
        current_schedule_layout.addWidget(sch_label1)
        current_schedule_layout.addWidget(self.sch_label2)
        self.sched_view = QTextEdit()
        self.sched_view.setReadOnly(True)
        self.sched_view.setLineWrapMode(QTextEdit.NoWrap)
        current_schedule_layout.addWidget(self.sched_view)
        sch_layout.addLayout(current_schedule_layout, 0, 0, 1, 1)
        self.schedule_set_button = QPushButton('Choose schedule file')
        self.schedule_set_button.clicked.connect(self.selectSchedule)
        self.schedule_generate_button = QPushButton('Generate tumble schedule')
        self.schedule_generate_button.clicked.connect(self.generateTumbleSchedule)
        self.sch_startButton = QPushButton('Run schedule')
        self.sch_startButton.setEnabled(False) #not runnable until schedule chosen
        self.sch_startButton.clicked.connect(self.startMultiple)
        self.sch_abortButton = QPushButton('Abort')
        self.sch_abortButton.setEnabled(False)
        self.sch_abortButton.clicked.connect(self.abortTransactions)

        sch_buttons_box = QGroupBox("Actions")
        sch_buttons_layout = QVBoxLayout()
        sch_buttons_layout.addWidget(self.schedule_set_button)
        sch_buttons_layout.addWidget(self.schedule_generate_button)
        sch_buttons_layout.addWidget(self.sch_startButton)
        sch_buttons_layout.addWidget(self.sch_abortButton)
        sch_buttons_box.setLayout(sch_buttons_layout)
        sch_layout.addWidget(sch_buttons_box, 0, 1, 1, 1)

        innerTopLayout = QGridLayout()
        innerTopLayout.setSpacing(4)
        self.single_join_tab.setLayout(innerTopLayout)

        donateLayout = self.getDonateLayout()
        innerTopLayout.addLayout(donateLayout, 0, 0, 1, 2)

        recipientLabel = QLabel('Recipient address / URI')
        recipientLabel.setToolTip(
            'The address or bitcoin: URI you want to send the payment to')
        self.addressInput = QLineEdit()
        self.addressInput.editingFinished.connect(
            lambda: self.checkAddress(self.addressInput.text()))
        innerTopLayout.addWidget(recipientLabel, 1, 0)
        innerTopLayout.addWidget(self.addressInput, 1, 1, 1, 2)

        self.numCPLabel = QLabel('Number of counterparties')
        self.numCPLabel.setToolTip(
            'How many other parties to send to; if you enter 4\n' +
            ', there will be 5 participants, including you.\n' +
            'Enter 0 to send direct without coinjoin.')
        self.numCPInput = QLineEdit('9')
        self.numCPInput.setValidator(QIntValidator(0, 20))
        innerTopLayout.addWidget(self.numCPLabel, 2, 0)
        innerTopLayout.addWidget(self.numCPInput, 2, 1, 1, 2)

        self.pjEndpointLabel = QLabel('PayJoin endpoint')
        self.pjEndpointLabel.setVisible(False)
        self.pjEndpointInput = QLineEdit()
        self.pjEndpointInput.setVisible(False)
        innerTopLayout.addWidget(self.pjEndpointLabel, 2, 0)
        innerTopLayout.addWidget(self.pjEndpointInput, 2, 1, 1, 2)

        mixdepthLabel = QLabel('Mixdepth')
        mixdepthLabel.setToolTip(
            'The mixdepth of the wallet to send the payment from')
        self.mixdepthInput = QLineEdit('0')
        self.mixdepthInput.setValidator(QIntValidator(
            0, jm_single().config.getint("GUI", "max_mix_depth") - 1))
        innerTopLayout.addWidget(mixdepthLabel, 3, 0)
        innerTopLayout.addWidget(self.mixdepthInput, 3, 1, 1, 2)

        amountLabel = QLabel('Amount')
        amountLabel.setToolTip(
            'The amount to send.\n' +
            'If you enter 0, a SWEEP transaction\nwill be performed,' +
            ' spending all the coins \nin the given mixdepth.')
        self.amountInput = BitcoinAmountEdit('')
        innerTopLayout.addWidget(amountLabel, 4, 0)
        innerTopLayout.addWidget(self.amountInput, 4, 1, 1, 2)

        self.startButton = QPushButton('Start')
        self.startButton.setToolTip(
            'If "checktx" is selected in the Settings, you will be \n'
            'prompted to decide whether to accept\n'
            'the transaction after connecting, and shown the\n'
            'fees to pay; you can cancel at that point, or by \n'
             'pressing "Abort".')
        self.startButton.clicked.connect(self.startSingle)
        self.abortButton = QPushButton('Abort')
        self.abortButton.setEnabled(False)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.startButton)
        buttons.addWidget(self.abortButton)
        self.abortButton.clicked.connect(self.abortTransactions)
        innerTopLayout.addLayout(buttons, 5, 0, 1, 2)
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
        #colored is better
        #However, the transaction confirmation dialog
        #will at least show both in RED and BOLD, and they will be more prominent.
        #TODO in new daemon this is not accessible? Or?
        """
        if joinmarket_alert[0]:
            mainWindow.statusBar().showMessage("JOINMARKET ALERT: " + joinmarket_alert[
                0])
        """
        self.textedit.insertPlainText(txt)

    def resizeScroll(self, mini, maxi):
        self.textedit.verticalScrollBar().setValue(maxi)

    def restartWaitWrap(self):
        if restart_wait(self.waitingtxid):
            self.restartTimer.stop()
            self.waitingtxid = None
            mainWindow.statusBar().showMessage("Transaction in a block, now continuing.")
            self.startJoin()

    def startMultiple(self):
        if jm_single().bc_interface is None:
            log.info("Cannot start join, blockchain source not available.")
            return
        if not self.spendstate.runstate == 'ready':
            log.info("Cannot start join, already running.")
            return
        if not self.spendstate.loaded_schedule:
            log.info("Cannot start, no schedule loaded.")
            return
        self.spendstate.updateType('multiple')
        self.spendstate.updateRun('running')

        if self.tumbler_options:
            #Uses the flag 'True' value from selectSchedule to recognize a restart,
            #which needs new dynamic option values. The rationale for using input
            #is in case the user can increase success probability by changing them.
            if self.tumbler_options == True:
                wizard = TumbleRestartWizard()
                wizard_return = wizard.exec_()
                if wizard_return == QDialog.Rejected:
                    return
                self.tumbler_options = wizard.getOptions()
            #check for a partially-complete schedule; if so,
            #follow restart logic
            #1. filter out complete:
            self.spendstate.loaded_schedule = [
                s for s in self.spendstate.loaded_schedule if s[-1] != 1]
            #reload destination addresses
            self.tumbler_destaddrs = [x[3] for x in self.spendstate.loaded_schedule
                                     if x not in ["INTERNAL", "addrask"]]
            #2 Check for unconfirmed
            if isinstance(self.spendstate.loaded_schedule[0][-1], str) and len(
                self.spendstate.loaded_schedule[0][-1]) == 64:
                #ensure last transaction is confirmed before restart
                tumble_log.info("WAITING TO RESTART...")
                mainWindow.statusBar().showMessage("Waiting for confirmation to restart..")
                txid = self.spendstate.loaded_schedule[0][-1]
                #remove the already-done entry (this connects to the other TODO,
                #probably better *not* to truncate the done-already txs from file,
                #but simplest for now.
                self.spendstate.loaded_schedule = self.spendstate.loaded_schedule[1:]
                #defers startJoin() call until tx seen on network. Note that
                #since we already updated state to running, user cannot
                #start another transactions while waiting. Also, use :0 because
                #it always exists
                self.waitingtxid=txid
                self.restartTimer.timeout.connect(self.restartWaitWrap)
                self.restartTimer.start(5000)
                self.updateSchedView()
                return
            self.updateSchedView()
        self.startJoin()

    def checkDirectSend(self, dtx, destaddr, amount, fee):
        """Give user info to decide whether to accept a direct send;
        note the callback includes the full prettified transaction,
        but currently not printing it for space reasons.
        """
        mbinfo = ["Sending " + btc.amount_to_str(amount) + ",",
                  "to: " + destaddr + ",",
                  "Fee: " + btc.amount_to_str(fee) + ".",
                  "Accept?"]
        reply = JMQtMessageBox(self, '\n'.join([m + '<p>' for m in mbinfo]),
                               mbtype='question', title="Direct send")
        if reply == QMessageBox.Yes:
            self.direct_send_amount = amount
            return True
        else:
            return False

    def infoDirectSend(self, msg):
        JMQtMessageBox(self, msg, title="Success")

    def errorDirectSend(self, msg):
        JMQtMessageBox(self, msg, mbtype="warn", title="Error")

    def startSingle(self):
        if not self.spendstate.runstate == 'ready':
            log.info("Cannot start join, already running.")
        if not self.validateSettings():
            return

        destaddr = str(self.addressInput.text().strip())
        try:
            amount = btc.amount_to_sat(self.amountInput.text())
        except ValueError as e:
            JMQtMessageBox(self, e.args[0], title="Error", mbtype="warn")
            return
        makercount = int(self.numCPInput.text())
        mixdepth = int(self.mixdepthInput.text())
        bip78url = self.pjEndpointInput.text()

        if makercount == 0 and not bip78url:
            try:
                txid = direct_send(mainWindow.wallet_service, amount, mixdepth,
                                  destaddr, accept_callback=self.checkDirectSend,
                                  info_callback=self.infoDirectSend,
                                  error_callback=self.errorDirectSend)
            except Exception as e:
                JMQtMessageBox(self, e.args[0], title="Error", mbtype="warn")
                return
            if not txid:
                self.giveUp()
            else:
                # since direct_send() assumes a one-shot processing, it does
                # not add a callback for confirmation, so that event could
                # get lost; we do that here to ensure that the confirmation
                # event is noticed:
                def qt_directsend_callback(rtxd, rtxid, confs):
                    if rtxid == txid:
                        return True
                    return False
                mainWindow.wallet_service.active_txids.append(txid)
                mainWindow.wallet_service.register_callbacks([qt_directsend_callback],
                                                    txid, cb_type="confirmed")
                self.persistTxToHistory(destaddr, self.direct_send_amount, txid)
                self.cleanUp()
            return

        if bip78url:
            manager = parse_payjoin_setup(self.bip21_uri,
                mainWindow.wallet_service, mixdepth, "joinmarket-qt")
            # disable form fields until payment is done
            self.addressInput.setEnabled(False)
            self.pjEndpointInput.setEnabled(False)
            self.mixdepthInput.setEnabled(False)
            self.amountInput.setEnabled(False)
            self.startButton.setEnabled(False)
            d = task.deferLater(reactor, 0.0, send_payjoin, manager,
                    accept_callback=self.checkDirectSend,
                    info_callback=self.infoDirectSend)
            d.addCallback(self.clearFields)
            return

        # for coinjoin sends no point to send below dust threshold, likely
        # there will be no makers for such amount.
        if amount != 0 and not self.checkAmount(amount):
            return

        if makercount < jm_single().config.getint(
            "POLICY", "minimum_makers"):
            JMQtMessageBox(self, "Number of counterparties (" + str(
                makercount) + ") below minimum_makers (" + str(
                jm_single().config.getint("POLICY", "minimum_makers")) +
                ") in configuration.",
                title="Error", mbtype="warn")
            return

        #note 'amount' is integer, so not interpreted as fraction
        #see notes in sample testnet schedule for format
        self.spendstate.loaded_schedule = [[mixdepth, amount, makercount,
                                            destaddr, 0, NO_ROUNDING, 0]]
        self.spendstate.updateType('single')
        self.spendstate.updateRun('running')
        self.startJoin()

    def getMaxCJFees(self, relfee, absfee):
        """ Used as a callback to decide relative and absolute
        maximum fees for coinjoins, in cases where the user has not
        set these values in the config (which is the default)."""
        if relfee is None:
            relfee = get_default_max_relative_fee()
        if absfee is None:
            absfee = get_default_max_absolute_fee()
        msg = ("Your maximum absolute fee in from one counterparty has been "
              "set to: " + str(absfee) + " satoshis.\n"
              "Your maximum relative fee from one counterparty has been set "
              "to: " + str(relfee) + ".\n"
              "To change these, please edit the config file and change the "
              "settings:\n"
              "max_cj_fee_abs = your-value-in-satoshis\n"
              "max_cj_fee_rel = your-value-as-decimal\n"
              "in the [POLICY] section.\n"
              "Note: If you don't do this, this dialog will interrupt the tumbler.")
        JMQtMessageBox(self, msg, mbtype="info", title="Setting fee limits.")
        return relfee, absfee

    def startJoin(self):
        if not mainWindow.wallet_service:
            JMQtMessageBox(self, "Cannot start without a loaded wallet.",
                           mbtype="crit", title="Error")
            return
        log.debug('starting coinjoin ..')
        #Decide whether to interrupt processing to sanity check the fees
        if self.tumbler_options:
            check_offers_callback = self.checkOffersTumbler
        elif jm_single().config.get("GUI", "checktx") == "true":
            check_offers_callback = self.checkOffers
        else:
            check_offers_callback = None

        destaddrs = self.tumbler_destaddrs if self.tumbler_options else []
        maxcjfee = get_max_cj_fee_values(jm_single().config, None,
                                         user_callback=self.getMaxCJFees)
        log.info("Using maximum coinjoin fee limits per maker of {:.4%}, {} "
                     "".format(maxcjfee[0], btc.amount_to_str(maxcjfee[1])))
        self.taker = Taker(mainWindow.wallet_service,
                           self.spendstate.loaded_schedule,
                           maxcjfee,
                           order_chooser=weighted_order_choose,
                           callbacks=[check_offers_callback,
                                      self.takerInfo,
                                      self.takerFinished],
                           tdestaddrs=destaddrs,
                           ignored_makers=ignored_makers)
        if not self.clientfactory:
            #First run means we need to start: create clientfactory
            #and start reactor connections
            self.clientfactory = JMClientProtocolFactory(self.taker)
            daemon = jm_single().config.getint("DAEMON", "no_daemon")
            daemon = True if daemon == 1 else False
            start_reactor("localhost",
                   jm_single().config.getint("DAEMON", "daemon_port"),
                   self.clientfactory,
                   ish=False,
                   daemon=daemon,
                   gui=True)
        else:
            #This will re-use IRC connections in background (daemon), no restart
            self.clientfactory.getClient().client = self.taker
            self.clientfactory.getClient().clientStart()
        mainWindow.statusBar().showMessage("Connecting to IRC ...")

    def takerInfo(self, infotype, infomsg):
        if infotype == "INFO":
            #use of a dialog interrupts processing?, investigate.
            if len(infomsg) > 200:
                log.info("INFO: " + infomsg)
            else:
                mainWindow.statusBar().showMessage(infomsg)
        elif infotype == "ABORT":
            JMQtMessageBox(self, infomsg,
                           mbtype='warn')
            #Abort signal explicitly means this transaction will not continue.
            self.abortTransactions()
        else:
            raise NotImplementedError

    def checkOffersTumbler(self, offers_fees, cjamount):
        return tumbler_filter_orders_callback(offers_fees, cjamount,
                                              self.taker)

    def checkOffers(self, offers_fee, cjamount):
        """Parse offers and total fee from client protocol,
        allow the user to agree or decide.
        """
        if self.taker.aborted:
            log.debug("Not processing offers, user has aborted.")
            return False

        if not offers_fee:
            JMQtMessageBox(self,
                           "Not enough matching offers found.",
                           mbtype='warn',
                           title="Error")
            self.giveUp()
            return
        offers, total_cj_fee = offers_fee
        total_fee_pc = 1.0 * total_cj_fee / self.taker.cjamount

        mbinfo = []
        mbinfo.append("Sending amount: " + btc.amount_to_str(self.taker.cjamount))
        mbinfo.append("to address: " + self.taker.my_cj_addr)
        mbinfo.append(" ")
        mbinfo.append("Counterparties chosen:")
        mbinfo.append('Name,     Order id, Coinjoin fee (sat.)')
        for k, o in iteritems(offers):
            if o['ordertype'] in ['swreloffer', 'reloffer']:
                display_fee = int(self.taker.cjamount *
                                  float(o['cjfee'])) - int(o['txfee'])
            elif o['ordertype'] in ['swabsoffer', 'absoffer']:
                display_fee = int(o['cjfee']) - int(o['txfee'])
            else:
                log.debug("Unsupported order type: " + str(o['ordertype']) +
                          ", aborting.")
                self.giveUp()
                return False
            mbinfo.append(k + ', ' + str(o['oid']) + ',         ' + str(
                display_fee))
        mbinfo.append('Total coinjoin fee = ' + btc.amount_to_str(total_cj_fee) +
                      ', or ' + str(float('%.3g' % (
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
            #amount is now accepted;
            #The user is now committed to the transaction
            self.abortButton.setEnabled(False)
            return True
        else:
            self.filter_offers_response = "REJECT"
            self.giveUp()
            return False

    def startNextTransaction(self):
        self.clientfactory.getClient().clientStart()

    def takerFinished(self, res, fromtx=False, waittime=0.0, txdetails=None):
        """Callback (after pass-through signal) for jmclient.Taker
        on completion of each join transaction.
        """
        #non-GUI-specific state updates first:
        if self.tumbler_options:
            sfile = os.path.join(logsdir, 'TUMBLE.schedule')
            tumbler_taker_finished_update(self.taker, sfile, tumble_log,
                                      self.tumbler_options, res,
                                      fromtx,
                                      waittime,
                                      txdetails)

        self.spendstate.loaded_schedule = self.taker.schedule
        #Shows the schedule updates in the GUI; TODO make this more visual
        if self.spendstate.typestate == 'multiple':
            self.updateSchedView()

        #GUI-specific updates; QTimer.singleShot serves the role
        #of reactor.callLater
        if fromtx == "unconfirmed":
            mainWindow.statusBar().showMessage(
                "Transaction seen on network: " + self.taker.txid)
            if self.spendstate.typestate == 'single':
                JMQtMessageBox(self, "Transaction broadcast OK. You can safely \n"
                               "shut down if you don't want to wait.",
                               title="Success")
            #TODO: theoretically possible to miss this if confirmed event
            #seen before unconfirmed.
            self.persistTxToHistory(self.taker.my_cj_addr, self.taker.cjamount,
                                                        self.taker.txid)

            #TODO prob best to completely fold multiple and tumble to reduce
            #complexity/duplication
            if self.spendstate.typestate == 'multiple' and not self.tumbler_options:
                self.taker.wallet_service.save_wallet()
            return
        if fromtx:
            if res:
                mainWindow.statusBar().showMessage("Transaction confirmed: " + self.taker.txid)
                #singleShot argument is in milliseconds
                if self.nextTxTimer:
                    self.nextTxTimer.stop()
                self.nextTxTimer = QtCore.QTimer()
                self.nextTxTimer.setSingleShot(True)
                self.nextTxTimer.timeout.connect(self.startNextTransaction)
                self.nextTxTimer.start(int(waittime*60*1000))
                #QtCore.QTimer.singleShot(int(self.taker_finished_waittime*60*1000),
                #                         self.startNextTransaction)
            else:
                if self.tumbler_options:
                    mainWindow.statusBar().showMessage("Transaction failed, trying again...")
                    QtCore.QTimer.singleShot(0, self.startNextTransaction)
                else:
                    #currently does not continue for non-tumble schedules
                    self.giveUp()
        else:
            if res:
                mainWindow.statusBar().showMessage("All transaction(s) completed successfully.")
                if len(self.taker.schedule) == 1:
                    msg = "Transaction has been confirmed.\n" + "Txid: " + \
                                           str(self.taker.txid)
                else:
                    msg = "All transactions have been confirmed."
                JMQtMessageBox(self, msg, title="Success")
                self.cleanUp()
            else:
                self.giveUp()

    def persistTxToHistory(self, addr, amt, txid):
        #persist the transaction to history
        with open(jm_single().config.get("GUI", "history_file"), 'ab') as f:
            f.write((','.join([addr, btc.amount_to_btc_str(amt), txid,
                              datetime.datetime.now(
                                  ).strftime("%Y/%m/%d %H:%M:%S")])).encode('utf-8'))
            f.write(b'\n')  #TODO: Windows
        #update the TxHistory tab
        txhist = mainWindow.centralWidget().widget(3)
        txhist.updateTxInfo()

    def toggleButtons(self):
        """Refreshes accessibility of buttons in the (single, multiple) join
        tabs based on the current state as defined by the SpendStateMgr instance.
        Thus, should always be called on any update to that instance.
        """
        #The first two buttons are for the single join tab; the remaining 4
        #are for the multijoin tab.
        btns = (self.startButton, self.abortButton,
                self.schedule_set_button, self.schedule_generate_button,
                self.sch_startButton, self.sch_abortButton)
        if self.spendstate.runstate == 'ready':
            btnsettings = (True, False, True, True, True, False)
        elif self.spendstate.runstate == 'running':
            if self.spendstate.typestate == 'single':
                #can only abort current run, nothing else
                btnsettings = (False, True, False, False, False, False)
            elif self.spendstate.typestate == 'multiple':
                btnsettings = (False, False, False, False, False, True)
            else:
                assert False
        else:
            assert False

        for b, s in zip(btns, btnsettings):
            b.setEnabled(s)

    def abortTransactions(self):
        if self.pjEndpointInput.isVisible():
            self.clearFields(None)
        else:
            self.taker.aborted = True
            self.giveUp()

    def giveUp(self):
        """Inform the user that the transaction failed, then reset state.
        """
        log.debug("Transaction aborted.")
        mainWindow.statusBar().showMessage("Transaction aborted.")
        if self.taker and len(self.taker.ignored_makers) > 0:
            JMQtMessageBox(self, "These Makers did not respond, and will be \n"
                           "ignored in future: \n" + str(
                            ','.join(self.taker.ignored_makers)),
                           title="Transaction aborted")
            ignored_makers.extend(self.taker.ignored_makers)
        self.cleanUp()

    def cleanUp(self):
        """Reset state to 'ready'
        """
        #Qt specific: because schedules can restart in same app instance,
        #we must clean up any existing delayed actions via singleShot.
        #Currently this should only happen via self.abortTransactions.
        if self.nextTxTimer:
            self.nextTxTimer.stop()
        self.spendstate.reset()
        self.tumbler_options = None
        self.tumbler_destaddrs = None

    def validateSettings(self):
        if jm_single().bc_interface is None:
            JMQtMessageBox(
                self,
                "Sending coins not possible without blockchain source.",
                mbtype='warn', title="Error")
            return False
        valid, errmsg = validate_address(
            str(self.addressInput.text().strip()))
        if not valid:
            JMQtMessageBox(self, errmsg, mbtype='warn', title="Error")
            return False
        if len(self.numCPInput.text()) == 0:
            JMQtMessageBox(
                self,
                "Non-zero number of counterparties must be provided.",
                mbtype='warn', title="Error")
            return False
        if len(self.mixdepthInput.text()) == 0:
            JMQtMessageBox(
                self,
                "Mixdepth must be chosen.",
                mbtype='warn', title="Error")
            return False
        if len(self.amountInput.text()) == 0:
            JMQtMessageBox(
                self,
                "Amount, in bitcoins, must be provided.",
                mbtype='warn', title="Error")
        if not mainWindow.wallet_service:
            JMQtMessageBox(self,
                           "There is no wallet loaded.",
                           mbtype='warn',
                           title="Error")
            return False
        return True

class TxHistoryTab(QWidget):

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.tHTW = MyTreeWidget(self, self.create_menu, self.getHeaders())
        self.tHTW.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.tHTW.header().setSectionResizeMode(QHeaderView.Interactive)
        self.tHTW.header().setStretchLastSection(False)
        self.tHTW.on_update = self.updateTxInfo
        vbox = QVBoxLayout()
        self.setLayout(vbox)
        vbox.setContentsMargins(0,0,0,0)
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
            if mainWindow:
                mainWindow.statusBar().showMessage("No transaction history found.")
            return []
        txhist = []
        with open(hf, 'rb') as f:
            txlines = f.readlines()
            for tl in txlines:
                txhist.append(tl.decode('utf-8').strip().split(','))
                if not len(txhist[-1]) == 4:
                    JMQtMessageBox(self,
                                   "Incorrectedly formatted file " + hf,
                                   mbtype='warn',
                                   title="Error")
                    mainWindow.statusBar().showMessage("No transaction history found.")
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
            address_valid = validate_address(address)

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

class CoinsTab(QWidget):

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.cTW = MyTreeWidget(self, self.create_menu, self.getHeaders())
        self.cTW.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.cTW.header().setSectionResizeMode(QHeaderView.Interactive)
        self.cTW.header().setStretchLastSection(False)
        self.cTW.on_update = self.updateUtxos

        vbox = QVBoxLayout()
        self.setLayout(vbox)
        vbox.setContentsMargins(0,0,0,0)
        vbox.setSpacing(0)
        vbox.addWidget(self.cTW)
        self.updateUtxos()
        self.show()

    def getHeaders(self):
        '''Function included in case dynamic in future'''
        return ['Txid:n', 'Amount in BTC', 'Address']

    def updateUtxos(self):
        """ Note that this refresh of the display only accesses in-process
        utxo database (no sync e.g.) so can be immediate.
        """
        self.cTW.clear()
        def show_blank():
            m_item = QTreeWidgetItem(["No coins", "", ""])
            self.cTW.addChild(m_item)
            self.cTW.show()

        if not mainWindow.wallet_service:
            show_blank()
            return
        utxos_enabled = {}
        utxos_disabled = {}
        for i in range(jm_single().config.getint("GUI", "max_mix_depth")):
            utxos_e, utxos_d = get_utxos_enabled_disabled(mainWindow.wallet_service, i)
            if utxos_e != {}:
                utxos_enabled[i] = utxos_e
            if utxos_d != {}:
                utxos_disabled[i] = utxos_d
        if utxos_enabled == {} and utxos_disabled == {}:
            show_blank()
            return

        for i in range(jm_single().config.getint("GUI", "max_mix_depth")):
            uem = utxos_enabled.get(i)
            udm = utxos_disabled.get(i)
            m_item = QTreeWidgetItem(["Mixdepth " + str(i), '', ''])
            self.cTW.addChild(m_item)
            for heading in ["NOT FROZEN", "FROZEN"]:
                um = uem if heading == "NOT FROZEN" else udm
                seq_item = QTreeWidgetItem([heading, '', ''])
                m_item.addChild(seq_item)
                seq_item.setExpanded(True)
                if um is None:
                    item = QTreeWidgetItem(['None', '', ''])
                    seq_item.addChild(item)
                else:
                    for k, v in um.items():
                        # txid:index, btc, address
                        success, t = utxo_to_utxostr(k)
                        # keys must be utxo format else a coding error:
                        assert success
                        s = "{0:.08f}".format(v['value']/1e8)
                        a = mainWindow.wallet_service.script_to_addr(v["script"])
                        item = QTreeWidgetItem([t, s, a])
                        item.setFont(0, QFont(MONOSPACE_FONT))
                        #if rows[i][forchange][j][3] != 'new':
                        #    item.setForeground(3, QBrush(QColor('red')))
                        seq_item.addChild(item)
                    m_item.setExpanded(True)

    def toggle_utxo_disable(self, txids, idxs):
        for i in range(0, len(txids)):
            txid = txids[i]
            txid_bytes = hextobin(txid)
            mainWindow.wallet_service.toggle_disable_utxo(txid_bytes, idxs[i])
        self.updateUtxos()

    def create_menu(self, position):
        # all selected items
        selected_items = self.cTW.selectedItems()
        txids = []
        idxs = []
        if len(selected_items) == 0:
            return
        try:
            for item in selected_items:
                txid, idx = item.text(0).split(":")
                assert len(txid) == 64
                idx = int(idx)
                assert idx >= 0
                txids.append(txid)
                idxs.append(idx)
        except Exception as e:
            log.error("Error retrieving txids in Coins tab: " + repr(e))
            return
        # current item
        item = self.cTW.currentItem()
        txid, idx = item.text(0).split(":")

        menu = QMenu()
        menu.addAction("Freeze/un-freeze utxo(s) (toggle)",
                           lambda: self.toggle_utxo_disable(txids, idxs))
        menu.addAction("Copy transaction id to clipboard",
                       lambda: app.clipboard().setText(txid))
        menu.exec_(self.cTW.viewport().mapToGlobal(position))

class BitcoinQRCodePopup(QDialog):

    def __init__(self, parent, address):
        super().__init__(parent)
        self.address = address
        self.setWindowTitle(address)
        img = qrcode.make('bitcoin:' + address)
        self.imageLabel = QLabel()
        self.imageLabel.setPixmap(QPixmap.fromImage(ImageQt(img)))
        layout = QVBoxLayout()
        layout.addWidget(self.imageLabel)
        self.setLayout(layout)
        self.initUI()

    def initUI(self):
        self.show()


class JMWalletTab(QWidget):

    def __init__(self):
        super().__init__()
        self.wallet_name = 'NONE'
        self.initUI()

    def initUI(self):
        self.label1 = QLabel(
            'No wallet loaded. Use "Wallet > Load" to load existing wallet ' +
            'or "Wallet > Generate" to create a new wallet.',
            self)
        self.label1.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)
        v = MyTreeWidget(self, self.create_menu, self.getHeaders())
        v.header().resizeSection(0, 400)    # size of "Address" column
        v.header().resizeSection(1, 130)    # size of "Index" column
        v.setSelectionMode(QAbstractItemView.ExtendedSelection)
        v.on_update = self.updateWalletInfo
        v.hide()
        self.walletTree = v
        vbox = QVBoxLayout()
        self.setLayout(vbox)
        vbox.setContentsMargins(0,0,0,0)
        vbox.setSpacing(0)
        vbox.addWidget(self.label1)
        vbox.addWidget(v)
        buttons = QWidget()
        vbox.addWidget(buttons)
        self.updateWalletInfo()
        self.show()

    def getHeaders(self):
        '''Function included in case dynamic in future'''
        return ['Address', 'Index', 'Balance', 'Used/New']

    def create_menu(self, position):
        item = self.walletTree.currentItem()
        address_valid = False
        xpub_exists = False
        if item:
            txt = str(item.text(0))
            if validate_address(txt)[0]:
                address_valid = True
            if "EXTERNAL" in txt:
                parsed = txt.split()
                if len(parsed) > 1:
                    xpub = parsed[1]
                    xpub_exists = True

        menu = QMenu()
        if address_valid:
            menu.addAction("Copy address to clipboard",
                           lambda: app.clipboard().setText(txt))
            # Show QR code option only for new addresses to avoid address reuse
            if item.text(3) == "new":
                menu.addAction("Show QR code",
                               lambda: self.openQRCodePopup(txt))
        if xpub_exists:
            menu.addAction("Copy extended pubkey to clipboard",
                           lambda: app.clipboard().setText(xpub))
        #TODO add more items to context menu
        if address_valid or xpub_exists:
            menu.exec_(self.walletTree.viewport().mapToGlobal(position))

    def openQRCodePopup(self, address):
        popup = BitcoinQRCodePopup(self, address)
        popup.show()

    def updateWalletInfo(self, walletinfo=None):
        nm = jm_single().config.getint("GUI", "max_mix_depth")
        l = self.walletTree

        # before deleting, note whether items were expanded
        esrs = []
        for i in range(l.topLevelItemCount()):
            tli = l.invisibleRootItem().child(i)
            # must check top and also the two subitems (branches):
            expandedness = tuple(
                x.isExpanded() for x in [tli, tli.child(0), tli.child(1)])
            esrs.append(expandedness)
        l.clear()
        if walletinfo:
            rows, mbalances, xpubs, total_bal = walletinfo
            if jm_single().config.get("BLOCKCHAIN", "blockchain_source") == "regtest":
                self.wallet_name = mainWindow.testwalletname
            else:
                self.wallet_name = os.path.basename(
                    mainWindow.wallet_service.get_storage_location())
            if total_bal is None:
                if jm_single().bc_interface is not None:
                    total_bal = " (syncing..)"
                else:
                    total_bal = " (unknown, no blockchain source available)"
            self.label1.setText("CURRENT WALLET: " + self.wallet_name +
                                ', total balance: ' + total_bal)
            l.show()

        if jm_single().bc_interface is None and self.wallet_name != 'NONE':
            return

        for i in range(nm):
            if walletinfo:
                mdbalance = mbalances[i]
            else:
                mdbalance = "{0:.8f}".format(0)
            m_item = QTreeWidgetItem(["Mixdepth " + str(i) + " , balance: " +
                                      mdbalance, '', '', '', ''])
            l.addChild(m_item)
            # if expansion states existed, reinstate them:
            if len(esrs) == nm:
                m_item.setExpanded(esrs[i][0])

            for forchange in [0, 1]:
                heading = "EXTERNAL" if forchange == 0 else "INTERNAL"
                if walletinfo and heading == "EXTERNAL":
                    heading_end = ' ' + xpubs[i][forchange]
                    heading += heading_end
                seq_item = QTreeWidgetItem([heading, '', '', '', ''])
                m_item.addChild(seq_item)
                # by default, external is expanded, but remember user choice:
                if not forchange:
                    seq_item.setExpanded(True)
                if len(esrs) == nm:
                    seq_item.setExpanded(esrs[i][forchange+1])
                if not walletinfo:
                    item = QTreeWidgetItem(['None', '', '', ''])
                    seq_item.addChild(item)
                else:
                    for j in range(len(rows[i][forchange])):
                        item = QTreeWidgetItem(rows[i][forchange][j])
                        item.setFont(0, QFont(MONOSPACE_FONT))
                        if rows[i][forchange][j][3] != 'new':
                            item.setForeground(3, QBrush(QColor('red')))
                        seq_item.addChild(item)


class JMMainWindow(QMainWindow):

    computing_privkeys_signal = QtCore.Signal()
    show_privkeys_signal = QtCore.Signal()

    def __init__(self, reactor):
        super().__init__()
        # the wallet service that encapsulates
        # the wallet we will interact with
        self.wallet_service = None

        # the monitoring loop that queries
        # the walletservice to update the GUI
        self.walletRefresh = None

        # keep track of whether wallet sync message
        # was already shown
        self.syncmsg = ""

        self.reactor = reactor
        self.initUI()

    def closeEvent(self, event):
        quit_msg = "Are you sure you want to quit?"
        reply = JMQtMessageBox(self, quit_msg, mbtype='question')
        if reply == QMessageBox.Yes:
            event.accept()
            if self.reactor.threadpool is not None:
                self.reactor.threadpool.stop()
            if reactor.running:
                self.reactor.stop()
        else:
            event.ignore()

    def initUI(self):
        self.statusBar().showMessage("Ready")
        self.setGeometry(300, 300, 250, 150)
        loadAction = QAction('&Load...', self)
        loadAction.setStatusTip('Load wallet from file')
        loadAction.triggered.connect(self.selectWallet)
        generateAction = QAction('&Generate...', self)
        generateAction.setStatusTip('Generate new wallet')
        generateAction.triggered.connect(self.generateWallet)
        recoverAction = QAction('&Recover...', self)
        recoverAction.setStatusTip('Recover wallet from seed phrase')
        recoverAction.triggered.connect(self.recoverWallet)
        showSeedAction = QAction('&Show seed', self)
        showSeedAction.setStatusTip('Show wallet seed phrase')
        showSeedAction.triggered.connect(self.showSeedDialog)
        exportPrivAction = QAction('&Export keys', self)
        exportPrivAction.setStatusTip('Export all private keys to a  file')
        exportPrivAction.triggered.connect(self.exportPrivkeysJson)
        changePassAction = QAction('&Change passphrase...', self)
        changePassAction.setStatusTip('Change wallet encryption passphrase')
        changePassAction.triggered.connect(self.changePassphrase)
        quitAction = QAction(QIcon('exit.png'), '&Quit', self)
        quitAction.setShortcut('Ctrl+Q')
        quitAction.setStatusTip('Quit application')
        quitAction.triggered.connect(qApp.quit)

        aboutAction = QAction('About Joinmarket', self)
        aboutAction.triggered.connect(self.showAboutDialog)

        menubar = self.menuBar()
        walletMenu = menubar.addMenu('&Wallet')
        walletMenu.addAction(loadAction)
        walletMenu.addAction(generateAction)
        walletMenu.addAction(recoverAction)
        walletMenu.addAction(showSeedAction)
        walletMenu.addAction(exportPrivAction)
        walletMenu.addAction(changePassAction)
        walletMenu.addAction(quitAction)
        aboutMenu = menubar.addMenu('&About')
        aboutMenu.addAction(aboutAction)

        self.show()

    def showAboutDialog(self):
        msgbox = QDialog(self)
        lyt = QVBoxLayout(msgbox)
        msgbox.setWindowTitle(appWindowTitle)
        about_text_label = QLabel()
        about_text_label.setText(
            "<a href=" + "'https://github.com/joinmarket-org/joinmarket-clientserver/'>"
            + "Read more about Joinmarket</a><p>" + "<p>".join(
                ["Joinmarket core software version: " + JM_CORE_VERSION + "<br/>JoinmarketQt version: "
                    + JM_GUI_VERSION + "<br/>Messaging protocol version:" + " %s" % (
                     str(jm_single().JM_VERSION)
                 ), "JoinMarket is an open source project which does not have a funding model, "
                  + "fortunately the project itself has very low running costs as it is almost-fully "
                  + "decentralized and available to everyone for free. Developers contribute only as "
                  + "volunteers and donations are divided amongst them. Many developers have also been "
                  + "important in advocating for privacy and educating the wider bitcoin user base. "
                  + "Be part of the effort to improve bitcoin privacy and fungibility. Every donated "
                  + "coin helps us spend more time on JoinMarket instead of doing other stuff."]))
        about_text_label.setWordWrap(True)
        donation_url_label = QLabel(donation_address_url)
        donation_addr_label = QLabel(donation_address)
        donation_addr_sw_label = QLabel(donation_address_sw)
        for l in [about_text_label, donation_url_label, donation_addr_label, donation_addr_sw_label]:
            l.setTextFormat(QtCore.Qt.RichText)
            l.setTextInteractionFlags(QtCore.Qt.TextBrowserInteraction)
            l.setOpenExternalLinks(True)
        donation_url_label.setText("<a href='" + donation_address_url + "'>" +
            donation_address_url + "</a>")
        donation_addr_label.setText("<a href='bitcoin:" + donation_address + "'>" +
            donation_address + "</a>")
        donation_addr_sw_label.setText("<a href='bitcoin:" + donation_address_sw + "'>" +
            donation_address_sw + "</a>")
        lyt.addWidget(about_text_label)
        lyt.addWidget(donation_url_label)
        lyt.addWidget(QLabel("Old donation addresses below. Ideally use the above URL."))
        lyt.addWidget(donation_addr_label)
        lyt.addWidget(donation_addr_sw_label)
        btnbox = QDialogButtonBox(msgbox)
        btnbox.setStandardButtons(QDialogButtonBox.Ok)
        btnbox.accepted.connect(msgbox.accept)
        lyt.addWidget(btnbox)
        msgbox.exec_()

    def exportPrivkeysJson(self):
        if not self.wallet_service:
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
        rows = get_wallet_printout(self.wallet_service)
        addresses = []
        for forchange in rows[0]:
            for mixdepth in forchange:
                for addr_info in mixdepth:
                    if float(addr_info[2]) > 0:
                        addresses.append(addr_info[0])
        done = False

        def privkeys_thread():
            # To explain this (given setting was already done in
            # load_program_config), see:
            # https://github.com/Simplexum/python-bitcointx/blob/9f1fa67a5445f8c187ef31015a4008bc5a048eea/bitcointx/__init__.py#L242-L243
            # note, we ignore the return value as we only want to apply
            # the chainparams setting logic:
            get_blockchain_interface_instance(jm_single().config)
            for addr in addresses:
                time.sleep(0.1)
                if done:
                    break
                priv = self.wallet_service.get_key_from_addr(addr)
                private_keys[addr] = BTCEngine.privkey_to_wif(priv)
                self.computing_privkeys_signal.emit()
            self.show_privkeys_signal.emit()

        def show_privkeys():
            s = "\n".join(map(lambda x: x[0] + "\t" + x[1], private_keys.items(
            )))
            e.setText(s)
            b.setEnabled(True)

        self.computing_privkeys_signal.connect(lambda: e.setText(
            "Please wait... %d/%d" % (len(private_keys), len(addresses))))
        self.show_privkeys_signal.connect(show_privkeys)

        threading.Thread(target=privkeys_thread).start()
        if not d.exec_():
            done = True
            return
        privkeys_fn_base = 'joinmarket-private-keys'
        i = 0
        privkeys_fn = privkeys_fn_base
        # Updated to use json format, simply because L1354 writer
        # has some extremely weird behaviour cross Py2/Py3
        while os.path.isfile(os.path.join(jm_single().datadir,
                                          privkeys_fn + '.json')):
            i += 1
            privkeys_fn = privkeys_fn_base + str(i)
        try:
            with open(os.path.join(jm_single().datadir,
                                   privkeys_fn + '.json'), "wb") as f:
                for addr, pk in private_keys.items():
                    # sanity check
                    rawpriv, _ = BTCEngine.wif_to_privkey(pk)
                    if not addr == self.wallet_service._ENGINE.privkey_to_address(rawpriv):
                        JMQtMessageBox(None, "Failed to create privkey export -" +\
                                       " critical error in key parsing.",
                                       mbtype='crit')
                        return
                f.write(json.dumps(private_keys, indent=4).encode('utf-8'))
        except (IOError, os.error) as reason:
            export_error_label = "JoinmarketQt was unable to produce a private key-export."
            JMQtMessageBox(None,
                           export_error_label + "\n" + str(reason),
                           mbtype='crit',
                           title="Unable to create json file")

        except Exception as er:
            JMQtMessageBox(self, str(er), mbtype='crit', title="Error")
            return

        JMQtMessageBox(self,
                       "Private keys exported to: " + os.path.join(jm_single().datadir,
                        privkeys_fn) + '.json', title="Success")

    def seedEntry(self):
        d = QDialog(self)
        d.setModal(1)
        d.setWindowTitle('Recover from mnemonic phrase')
        layout = QGridLayout(d)
        message_e = QTextEdit()
        layout.addWidget(QLabel('Enter 12 words'), 0, 0)
        layout.addWidget(message_e, 1, 0)

        pp_hbox = QHBoxLayout()
        pp_field = QLineEdit()
        pp_field.setEnabled(False)
        use_pp = QCheckBox('Input Mnemonic Extension', self)
        use_pp.setCheckState(QtCore.Qt.CheckState(False))
        use_pp.stateChanged.connect(lambda state: pp_field.setEnabled(state
            == QtCore.Qt.Checked))
        pp_hbox.addWidget(use_pp)
        pp_hbox.addWidget(pp_field)

        hbox = QHBoxLayout()
        buttonBox = QDialogButtonBox(self)
        buttonBox.setStandardButtons(QDialogButtonBox.Ok |
                                     QDialogButtonBox.Cancel)
        buttonBox.button(QDialogButtonBox.Ok).clicked.connect(d.accept)
        buttonBox.button(QDialogButtonBox.Cancel).clicked.connect(d.reject)
        hbox.addWidget(buttonBox)
        layout.addLayout(hbox, 4, 0)
        layout.addLayout(pp_hbox, 3, 0)
        result = d.exec_()
        if result != QDialog.Accepted:
            return None, None
        mn_extension = None
        if use_pp.checkState() == QtCore.Qt.Checked:
            mn_extension = pp_field.text()
        return message_e.toPlainText(), mn_extension

    def autofreeze_warning_cb(self, utxostr):
        """ Handles coins sent to reused addresses,
        preventing forced address reuse, according to value of
        POLICY setting `max_sats_freeze_reuse` (see
        WalletService.check_for_reuse()).
        """
        msg = "New utxo has been automatically " +\
             "frozen to prevent forced address reuse:\n" + utxostr +\
             "\n You can unfreeze this utxo via the Coins tab."
        JMQtMessageBox(self, msg, mbtype='info',
                       title="New utxo frozen")

    def restartWithMsg(self, msg):
        JMQtMessageBox(self, msg, mbtype='info',
                       title="Restart")
        self.close()

    def recoverWallet(self):
        try:
            success = wallet_generate_recover_bip39(
                "recover", os.path.join(jm_single().datadir, 'wallets'),
                "wallet.jmdat",
                display_seed_callback=None,
                enter_seed_callback=self.seedEntry,
                enter_wallet_password_callback=self.getPassword,
                enter_wallet_file_name_callback=self.getWalletFileName,
                enter_if_use_seed_extension=None,
                enter_seed_extension_callback=None,
                enter_do_support_fidelity_bonds=lambda: False)
            if not success:
                JMQtMessageBox(self,
                           "Failed to recover wallet.",
                           mbtype='warn',
                           title="Error")
                return
        except Exception as e:
            JMQtMessageBox(self, e.args[0], title="Error", mbtype="warn")
            return

        JMQtMessageBox(self, 'Wallet saved to ' + self.walletname,
                                   title="Wallet created")
        self.initWallet(seed=self.walletname)

    def selectWallet(self, testnet_seed=None):
        if jm_single().config.get("BLOCKCHAIN", "blockchain_source") != "regtest":
            # guaranteed to exist as load_program_config was called on startup:
            wallets_path = os.path.join(jm_single().datadir, 'wallets')
            firstarg = QFileDialog.getOpenFileName(self,
                                                   'Choose Wallet File',
                                                   wallets_path,
                                                   options=QFileDialog.DontUseNativeDialog)
            #TODO validate the file looks vaguely like a wallet file
            log.debug('Looking for wallet in: ' + str(firstarg))
            if not firstarg or not firstarg[0]:
                return
            decrypted = False
            while not decrypted:
                text, ok = QInputDialog.getText(self,
                                                'Decrypt wallet',
                                                'Enter your password:',
                                                echo=QLineEdit.Password)
                if not ok:
                    return
                pwd = str(text).strip()
                try:
                    decrypted = self.loadWalletFromBlockchain(firstarg[0], pwd)
                except Exception as e:
                    JMQtMessageBox(self,
                               str(e),
                               mbtype='warn',
                               title="Error")
                    return
        else:
            if not testnet_seed:
                testnet_seed, ok = QInputDialog.getText(self,
                                                        'Load Testnet wallet',
                                                        'Enter a testnet seed:',
                                                        QLineEdit.Normal)
                if not ok:
                    return
            firstarg = str(testnet_seed)
            pwd = None
            #ignore return value as there is no decryption failure possible
            self.loadWalletFromBlockchain(firstarg, pwd)

    def loadWalletFromBlockchain(self, firstarg=None, pwd=None):
        if firstarg:
            wallet_path = get_wallet_path(str(firstarg), None)
            try:
                wallet = open_test_wallet_maybe(wallet_path, str(firstarg),
                        None, ask_for_password=False, password=pwd.encode('utf-8') if pwd else None,
                        gap_limit=jm_single().config.getint("GUI", "gaplimit"))
            except RetryableStorageError as e:
                JMQtMessageBox(self,
                               str(e),
                               mbtype='warn',
                               title="Error")
                return False
            # only used for GUI display on regtest:
            self.testwalletname = wallet.seed = str(firstarg)
        if isinstance(wallet, FidelityBondMixin):
            raise Exception("Fidelity bond wallets not supported by Qt")
        if 'listunspent_args' not in jm_single().config.options('POLICY'):
            jm_single().config.set('POLICY', 'listunspent_args', '[0]')
        assert wallet, "No wallet loaded"

        # shut down any existing wallet service
        # monitoring loops
        if self.wallet_service is not None:
            if self.wallet_service.isRunning():
                self.wallet_service.stopService()
        if self.walletRefresh is not None:
            self.walletRefresh.stop()

        self.wallet_service = WalletService(wallet)

        if jm_single().bc_interface is None:
            self.centralWidget().widget(0).updateWalletInfo(
                get_wallet_printout(self.wallet_service))
            return True

        # add information callbacks:
        self.wallet_service.add_restart_callback(self.restartWithMsg)
        self.wallet_service.autofreeze_warning_cb = self.autofreeze_warning_cb
        self.wallet_service.startService()
        self.syncmsg = ""
        self.walletRefresh = task.LoopingCall(self.updateWalletInfo)
        self.walletRefresh.start(5.0)

        self.statusBar().showMessage("Reading wallet from blockchain ...")
        return True

    def updateWalletInfo(self):
        t = self.centralWidget().widget(0)
        if not self.wallet_service:  #failure to sync in constructor means object is not created
            newsyncmsg = "Unable to sync wallet - see error in console."
        elif not self.wallet_service.isRunning():
            JMQtMessageBox(self,
                           "The Joinmarket wallet service has stopped; this is usually caused "
                           "by a Bitcoin Core RPC connection failure. Is your node running?",
                           mbtype='crit',
                           title="Error")
            qApp.exit(EXIT_FAILURE)
            return
        elif not self.wallet_service.synced:
            return
        else:
            try:
                t.updateWalletInfo(get_wallet_printout(self.wallet_service))
            except Exception:
                # this is very likely to happen in case Core RPC connection goes
                # down (but, order of events means it is not deterministic).
                log.debug("Failed to get wallet information, is there a problem with "
                          "the blockchain interface?")
                return
            newsyncmsg = "Wallet synced successfully."
        if newsyncmsg != self.syncmsg:
            self.syncmsg = newsyncmsg
            self.statusBar().showMessage(self.syncmsg)

    def generateWallet(self):
        log.debug('generating wallet')
        if jm_single().config.get("BLOCKCHAIN", "blockchain_source") == "regtest":
            seed = self.getTestnetSeed()
            self.selectWallet(testnet_seed=seed)
        else:
            self.initWallet()

    def checkPassphrase(self):
        match = False
        while not match:
            text, ok = QInputDialog.getText(self, 'Passphrase check',
                                            'Enter your passphrase:',
                                            echo=QLineEdit.Password)
            if not ok:
                return False
            pwd = str(text).strip().encode('utf-8')
            match = self.wallet_service.check_wallet_passphrase(pwd)
            if not match:
                JMQtMessageBox(self,
                               "Wrong passphrase.", mbtype='warn', title="Error")
        return True

    def changePassphrase(self):
        if not self.wallet_service:
            JMQtMessageBox(self, "Cannot change passphrase without loaded wallet.",
                           mbtype="crit", title="Error")
            return
        if not (self.checkPassphrase()
                and wallet_change_passphrase(self.wallet_service, self.getPassword)):
            JMQtMessageBox(self, "Failed to change passphrase.",
                           title="Error", mbtype="warn")
            return
        JMQtMessageBox(self, "Passphrase changed successfully.",
                       title="Passphrase changed")

    def getTestnetSeed(self):
        text, ok = QInputDialog.getText(
            self, 'Testnet seed', 'Enter a 32 char hex string as seed:')
        if not ok or not text:
            JMQtMessageBox(self,
                           "No seed entered, aborting",
                           mbtype='warn',
                           title="Error")
            return
        return str(text).strip()

    def showSeedDialog(self):
        if not self.wallet_service:
            JMQtMessageBox(self,
                           "No wallet loaded.",
                           mbtype='crit',
                           title="Error")
            return
        try:
            self.displayWords(*self.wallet_service.get_mnemonic_words())
        except NotImplementedError:
            JMQtMessageBox(self,
                           "Wallet does not support seed phrases",
                           mbtype='info',
                           title="Error")

    def getPassword(self):
        pd = PasswordDialog()
        while True:
            for child in pd.findChildren(QLineEdit):
                child.clear()
            pd.findChild(QLineEdit).setFocus()
            pd_return = pd.exec_()
            if pd_return == QDialog.Rejected:
                return None
            elif pd.new_pw.text() != pd.conf_pw.text():
                JMQtMessageBox(self,
                               "Passphrases don't match.",
                               mbtype='warn',
                               title="Error")
                continue
            elif pd.new_pw.text() == "":
                JMQtMessageBox(self,
                               "Passphrase must not be empty.",
                               mbtype='warn',
                               title="Error")
                continue
            break
        self.textpassword = str(pd.new_pw.text())
        return self.textpassword.encode('utf-8')

    def getWalletFileName(self):
        walletname, ok = QInputDialog.getText(self, 'Choose wallet name',
                                              'Enter wallet file name:',
                                              QLineEdit.Normal, "wallet.jmdat")
        if not ok:
            JMQtMessageBox(self, "Create wallet aborted", mbtype='warn')
            # cannot use None for a 'fail' condition, as this is used
            # for the case where the default wallet name is to be used in non-Qt.
            return "cancelled"
        self.walletname = str(walletname)
        return self.walletname

    def displayWords(self, words, mnemonic_extension):
        mb = QMessageBox(self)
        seed_recovery_warning = [
            "WRITE DOWN THIS WALLET RECOVERY SEED.",
            "If you fail to do this, your funds are",
            "at risk. Do NOT ignore this step!!!"
        ]
        mb.setText("<br/>".join(seed_recovery_warning))
        text = "<strong>" + words + "</strong>"
        if mnemonic_extension:
            text += "<br/><br/>Seed extension: <strong>" + mnemonic_extension.decode('utf-8') + "</strong>"
        mb.setInformativeText(text)
        mb.setStandardButtons(QMessageBox.Ok)
        ret = mb.exec_()

    def promptUseMnemonicExtension(self):
        msg = "Would you like to use a two-factor mnemonic recovery phrase?\nIf you don\'t know what this is press No."
        reply = QMessageBox.question(self, 'Use mnemonic extension?',
                    msg, QMessageBox.Yes, QMessageBox.No)
        return reply == QMessageBox.Yes

    def promptInputMnemonicExtension(self):
        mnemonic_extension, ok = QInputDialog.getText(self,
                                     'Input Mnemonic Extension',
                                     'Enter mnemonic Extension:',
                                     QLineEdit.Normal, "")
        if not ok:
            return None
        return str(mnemonic_extension)

    def initWallet(self, seed=None):
        '''Creates a new wallet if seed not provided.
        Initializes by syncing.
        '''
        if not seed:
            try:
                # guaranteed to exist as load_program_config was called on startup:
                wallets_path = os.path.join(jm_single().datadir, 'wallets')
                success = wallet_generate_recover_bip39(
                    "generate", wallets_path, "wallet.jmdat",
                    display_seed_callback=self.displayWords,
                    enter_seed_callback=None,
                    enter_wallet_password_callback=self.getPassword,
                    enter_wallet_file_name_callback=self.getWalletFileName,
                    enter_if_use_seed_extension=self.promptUseMnemonicExtension,
                    enter_seed_extension_callback=self.promptInputMnemonicExtension,
                    enter_do_support_fidelity_bonds=lambda: False)

                if not success:
                    JMQtMessageBox(self, "Failed to create new wallet file.",
                                   title="Error", mbtype="warn")
                    return
            except Exception as e:
                JMQtMessageBox(self, e.args[0], title="Error", mbtype="warn")
                return

            JMQtMessageBox(self, 'Wallet saved to ' + self.walletname,
                           title="Wallet created")
        self.loadWalletFromBlockchain(self.walletname, pwd=self.textpassword)

def get_wallet_printout(wallet_service):
    """Given a WalletService object, retrieve the list of
    addresses and corresponding balances to be displayed.
    We retrieve a WalletView abstraction, and iterate over
    sub-objects to arrange the per-mixdepth and per-address lists.
    The format of the returned data is:
    rows: is of format [[[addr,index,bal,used],[addr,...]]*5,
    [[addr, index,..], [addr, index..]]*5]
    mbalances: is a simple array of 5 mixdepth balances
    xpubs: [[xpubext, xpubint], ...]
    Bitcoin amounts returned are in btc, not satoshis
    """
    walletview = wallet_display(wallet_service, False, serialized=False)
    rows = []
    mbalances = []
    xpubs = []
    for j, acct in enumerate(walletview.children):
        mbalances.append(acct.get_fmt_balance())
        rows.append([])
        xpubs.append([])
        for i, branch in enumerate(acct.children):
            xpubs[j].append(branch.xpub)
            rows[j].append([])
            for entry in branch.children:
                rows[-1][i].append([entry.serialize_address(),
                                    entry.serialize_wallet_position(),
                                    entry.serialize_amounts(),
                                    entry.serialize_extra_data()])
    # in case the wallet is not yet synced, don't return an incorrect
    # 0 balance, but signal incompleteness:
    total_bal = walletview.get_fmt_balance() if wallet_service.synced else None
    return (rows, mbalances, xpubs, total_bal)

################################

parser = OptionParser(usage='usage: %prog [options]')
add_base_options(parser)
# wallet related base options are not applicable:
parser.remove_option("--recoversync")
parser.remove_option("--wallet-password-stdin")
(options, args) = parser.parse_args()

config_load_error = False
try:
    load_program_config(config_path=options.datadir)
except Exception as e:
    config_load_error = "Failed to setup joinmarket: "+repr(e)
    if "RPC" in repr(e):
        config_load_error += '\n'*3 + ''.join(
            ["Errors about failed RPC connections usually mean an incorrectly ",
             "configured instance of Bitcoin Core (e.g. it hasn't been started ",
             "or the rpc ports are not correct in your joinmarket.cfg or your ",
             "bitcoin.conf file)."
             ])
    JMQtMessageBox(None, config_load_error, mbtype='crit', title='failed to load')
    sys.exit(EXIT_FAILURE)
# Only partial functionality (see wallet info, change config) is possible
# without a blockchain interface.
if jm_single().bc_interface is None:
    blockchain_warning = ''.join([
        "No blockchain source currently configured. ",
        "You will be able to see wallet information and change configuration ",
        "but other functionality will be limited. ",
        "Go to the 'Settings' tab and configure blockchain settings there."])
    JMQtMessageBox(None, blockchain_warning, mbtype='warn',
        title='No blockchain source')
#refuse to load non-segwit wallet (needs extra work in wallet-utils).
if not jm_single().config.get("POLICY", "segwit") == "true":
    wallet_load_error = ''.join(["Joinmarket-Qt only supports segwit based wallets, ",
                                 "please edit the config file and remove any setting ",
                                 "of the field `segwit` in the `POLICY` section."])
    JMQtMessageBox(None, wallet_load_error, mbtype='crit',
                   title='Incompatible wallet type')
    sys.exit(EXIT_FAILURE)

update_config_for_gui()

def onTabChange(i):
    """ Respond to change of tab.
    """
    # TODO: hardcoded literal;
    # note that this is needed for an auto-update
    # of utxos on the Coins tab only atm.
    if i == 4:
        tabWidget.widget(4).updateUtxos()

#to allow testing of confirm/unconfirm callback for multiple txs
if isinstance(jm_single().bc_interface, RegtestBitcoinCoreInterface):
    jm_single().bc_interface.tick_forward_chain_interval = 10
    jm_single().bc_interface.simulating = True
    jm_single().maker_timeout_sec = 15
    #trigger start with a fake tx
    jm_single().bc_interface.pushtx(b"\x00"*20)

#prepare for logging
for dname in ['logs', 'wallets', 'cmtdata']:
    if not os.path.exists(dname):
        os.makedirs(dname)
logsdir = os.path.join(os.path.dirname(jm_single().config_location), "logs")
#tumble log will not always be used, but is made available anyway:
tumble_log = get_tumble_log(logsdir)
#ignored makers list persisted across entire app run
ignored_makers = []
appWindowTitle = 'JoinMarketQt'
from twisted.internet import reactor
mainWindow = JMMainWindow(reactor)
tabWidget = QTabWidget(mainWindow)
tabWidget.addTab(JMWalletTab(), "JM Wallet")
settingsTab = SettingsTab()
tabWidget.addTab(settingsTab, "Settings")
tabWidget.addTab(SpendTab(), "Coinjoins")
tabWidget.addTab(TxHistoryTab(), "Tx History")
tabWidget.addTab(CoinsTab(), "Coins")

mainWindow.resize(600, 500)
suffix = ' - Testnet' if get_network() == 'testnet' else ''
mainWindow.setWindowTitle(appWindowTitle + suffix)
tabWidget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
mainWindow.setCentralWidget(tabWidget)
tabWidget.currentChanged.connect(onTabChange)
mainWindow.show()
reactor.runReturn()
sys.exit(app.exec_())
