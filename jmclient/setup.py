from setuptools import setup


setup(name='joinmarketclient',
      version='0.7.0',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='http://github.com/Joinmarket-Org/joinmarket-clientserver/jmclient',
      author='',
      author_email='',
      license='GPL',
      packages=['jmclient'],
      install_requires=['joinmarketbase==0.7.0', 'mnemonic', 'argon2_cffi',
                        'bencoder.pyx>=2.0.0', 'pyaes'],
      python_requires='>=3.6',
      zip_safe=False)
