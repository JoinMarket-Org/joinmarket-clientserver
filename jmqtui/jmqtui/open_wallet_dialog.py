# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'open_wallet_dialog.ui'
##
## Created by: Qt User Interface Compiler version 5.14.2
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide2.QtCore import (QCoreApplication, QDate, QDateTime, QMetaObject,
    QObject, QPoint, QRect, QSize, QTime, QUrl, Qt)
from PySide2.QtGui import (QBrush, QColor, QConicalGradient, QCursor, QFont,
    QFontDatabase, QIcon, QKeySequence, QLinearGradient, QPalette, QPainter,
    QPixmap, QRadialGradient)
from PySide2.QtWidgets import *


class Ui_OpenWalletDialog(object):
    def setupUi(self, OpenWalletDialog):
        if not OpenWalletDialog.objectName():
            OpenWalletDialog.setObjectName(u"OpenWalletDialog")
        OpenWalletDialog.resize(590, 301)
        sizePolicy = QSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(OpenWalletDialog.sizePolicy().hasHeightForWidth())
        OpenWalletDialog.setSizePolicy(sizePolicy)
        OpenWalletDialog.setFocusPolicy(Qt.TabFocus)
        OpenWalletDialog.setModal(True)
        self.verticalLayout = QVBoxLayout(OpenWalletDialog)
        self.verticalLayout.setSpacing(10)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.verticalLayout.setContentsMargins(20, 20, 20, 20)
        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setSpacing(10)
        self.horizontalLayout.setObjectName(u"horizontalLayout")
        self.label = QLabel(OpenWalletDialog)
        self.label.setObjectName(u"label")
        sizePolicy1 = QSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        sizePolicy1.setHorizontalStretch(0)
        sizePolicy1.setVerticalStretch(0)
        sizePolicy1.setHeightForWidth(self.label.sizePolicy().hasHeightForWidth())
        self.label.setSizePolicy(sizePolicy1)

        self.horizontalLayout.addWidget(self.label)

        self.walletFileEdit = QLineEdit(OpenWalletDialog)
        self.walletFileEdit.setObjectName(u"walletFileEdit")
        sizePolicy2 = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        sizePolicy2.setHorizontalStretch(0)
        sizePolicy2.setVerticalStretch(0)
        sizePolicy2.setHeightForWidth(self.walletFileEdit.sizePolicy().hasHeightForWidth())
        self.walletFileEdit.setSizePolicy(sizePolicy2)
        self.walletFileEdit.setMinimumSize(QSize(400, 0))

        self.horizontalLayout.addWidget(self.walletFileEdit)

        self.chooseWalletButton = QPushButton(OpenWalletDialog)
        self.chooseWalletButton.setObjectName(u"chooseWalletButton")
        sizePolicy1.setHeightForWidth(self.chooseWalletButton.sizePolicy().hasHeightForWidth())
        self.chooseWalletButton.setSizePolicy(sizePolicy1)

        self.horizontalLayout.addWidget(self.chooseWalletButton)

        self.horizontalLayout.setStretch(1, 1)

        self.verticalLayout.addLayout(self.horizontalLayout)

        self.horizontalLayout_2 = QHBoxLayout()
        self.horizontalLayout_2.setSpacing(10)
        self.horizontalLayout_2.setObjectName(u"horizontalLayout_2")
        self.label_2 = QLabel(OpenWalletDialog)
        self.label_2.setObjectName(u"label_2")
        sizePolicy1.setHeightForWidth(self.label_2.sizePolicy().hasHeightForWidth())
        self.label_2.setSizePolicy(sizePolicy1)

        self.horizontalLayout_2.addWidget(self.label_2)

        self.passphraseEdit = QLineEdit(OpenWalletDialog)
        self.passphraseEdit.setObjectName(u"passphraseEdit")
        self.passphraseEdit.setMinimumSize(QSize(200, 0))
        self.passphraseEdit.setEchoMode(QLineEdit.Password)

        self.horizontalLayout_2.addWidget(self.passphraseEdit)

        self.horizontalSpacer = QSpacerItem(90, 20, QSizePolicy.Fixed, QSizePolicy.Minimum)

        self.horizontalLayout_2.addItem(self.horizontalSpacer)

        self.horizontalLayout_2.setStretch(1, 1)

        self.verticalLayout.addLayout(self.horizontalLayout_2)

        self.verticalSpacer = QSpacerItem(20, 150, QSizePolicy.Minimum, QSizePolicy.Minimum)

        self.verticalLayout.addItem(self.verticalSpacer)

        self.horizontalLayout_3 = QHBoxLayout()
        self.horizontalLayout_3.setSpacing(10)
        self.horizontalLayout_3.setObjectName(u"horizontalLayout_3")
        self.horizontalSpacer_2 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.horizontalLayout_3.addItem(self.horizontalSpacer_2)

        self.buttonBox = QDialogButtonBox(OpenWalletDialog)
        self.buttonBox.setObjectName(u"buttonBox")
        self.buttonBox.setOrientation(Qt.Horizontal)
        self.buttonBox.setStandardButtons(QDialogButtonBox.Cancel|QDialogButtonBox.Ok)

        self.horizontalLayout_3.addWidget(self.buttonBox)

        self.horizontalLayout_3.setStretch(0, 1)

        self.verticalLayout.addLayout(self.horizontalLayout_3)

        self.verticalLayout.setStretch(2, 1)
        QWidget.setTabOrder(self.passphraseEdit, self.chooseWalletButton)
        QWidget.setTabOrder(self.chooseWalletButton, self.walletFileEdit)

        self.retranslateUi(OpenWalletDialog)
        self.buttonBox.accepted.connect(OpenWalletDialog.accept)
        self.buttonBox.rejected.connect(OpenWalletDialog.reject)

        QMetaObject.connectSlotsByName(OpenWalletDialog)
    # setupUi

    def retranslateUi(self, OpenWalletDialog):
        OpenWalletDialog.setWindowTitle(QCoreApplication.translate("OpenWalletDialog", u"JoinMarket - Open Wallet", None))
        self.label.setText(QCoreApplication.translate("OpenWalletDialog", u"Wallet:", None))
        self.walletFileEdit.setText(QCoreApplication.translate("OpenWalletDialog", u"wallet.jmdat", None))
        self.walletFileEdit.setPlaceholderText("")
        self.chooseWalletButton.setText(QCoreApplication.translate("OpenWalletDialog", u"Choose...", None))
        self.label_2.setText(QCoreApplication.translate("OpenWalletDialog", u"Passphrase:", None))
    # retranslateUi

