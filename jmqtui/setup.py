from setuptools import setup

setup(name='joinmarketui',
      version='0.9.6',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='https://github.com/JoinMarket-Org/joinmarket-clientserver/tree/master/jmqtui',
      author='',
      author_email='',
      license='GPL',
      packages=['jmqtui'],
      install_requires=['PyQt5!=5.15.0,!=5.15.1,!=5.15.2,!=6.0'],
      python_requires='>=3.6',
      zip_safe=False)

# The following command should be executed whenever `open_wallet_dialog.ui` is updated.
# We have commented out this command so that we wouldn't require every user of JoinMarket-qt
# to install the correct version of pyside2-uic.
#import os
#os.system('pyside2-uic jmqtui/open_wallet_dialog.ui -o jmqtui/open_wallet_dialog.py')
