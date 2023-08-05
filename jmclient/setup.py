from setuptools import setup


setup(name='joinmarketclient',
      version='0.9.10dev',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='https://github.com/JoinMarket-Org/joinmarket-clientserver/tree/master/jmclient',
      author='',
      author_email='',
      license='GPL',
      packages=['jmclient'],
      install_requires=['joinmarketbase==0.9.10dev', 'mnemonic==0.20',
                        'argon2_cffi==21.3.0', 'bencoder.pyx==3.0.1',
                        'klein==20.6.0', 'pyjwt==2.4.0',
                        'autobahn==20.12.3', 'werkzeug==2.2.3'],
      python_requires='>=3.6',
      zip_safe=False)
