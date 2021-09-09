from setuptools import setup


setup(name='joinmarketclient',
      version='0.9.2dev',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='https://github.com/JoinMarket-Org/joinmarket-clientserver/tree/master/jmclient',
      author='',
      author_email='',
      license='GPL',
      packages=['jmclient'],
      install_requires=['joinmarketbase==0.9.2dev', 'mnemonic', 'argon2_cffi',
                        'bencoder.pyx>=2.0.0', 'pyaes'],
      python_requires='>=3.6',
      zip_safe=False)
