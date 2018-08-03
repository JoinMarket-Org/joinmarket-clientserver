from setuptools import setup


setup(name='joinmarketclient',
      version='0.3.5',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='http://github.com/Joinmarket-Org/joinmarket-clientserver/jmclient',
      author='',
      author_email='',
      license='GPL',
      packages=['jmclient'],
      install_requires=['joinmarketbase==0.3.5', 'mnemonic', 'qt4reactor'],
      zip_safe=False)
