import os

# The following command should be executed whenever `open_wallet_dialog.ui` is updated.
# `gui-dev` dependencies must be installed prior to execution.

def compile_ui():
    os.system('pyside2-uic jmqtui/open_wallet_dialog.ui -o jmqtui/open_wallet_dialog.py')
