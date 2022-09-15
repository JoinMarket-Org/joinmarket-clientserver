from setuptools import setup


setup(name='joinmarketclient',
      version='0.9.9dev',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='https://github.com/JoinMarket-Org/joinmarket-clientserver/tree/master/jmclient',
      author='',
      author_email='',
      license='GPL',
      packages=['jmclient'],
      install_requires=['joinmarketbase==0.9.9dev', 'mnemonic', 'argon2_cffi',
                        'bencoder.pyx>=2.0.0', 'pyaes', 'klein==20.6.0',
                        'pyjwt==2.4.0', 'autobahn==20.12.3'],
      python_requires='>=3.6',
      zip_safe=False)
