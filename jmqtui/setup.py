from setuptools import setup
import os

setup(name='joinmarketui',
      version='0.9.3',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='https://github.com/JoinMarket-Org/joinmarket-clientserver/tree/master/jmqtui',
      author='',
      author_email='',
      license='GPL',
      packages=['jmqtui'],
      install_requires=['PyQt5!=5.15.0,!=5.15.1,!=5.15.2,!=6.0'],
      python_requires='>=3.6',
      zip_safe=False)

os.system('pyside2-uic jmqtui/open_wallet_dialog.ui -o jmqtui/open_wallet_dialog.py')
