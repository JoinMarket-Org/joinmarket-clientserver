from setuptools import setup


setup(name='joinmarketclient',
      version='0.5.0',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='http://github.com/Joinmarket-Org/joinmarket-clientserver/jmclient',
      author='',
      author_email='',
      license='GPL',
      packages=['jmclient'],
      install_requires=['future', 'configparser;python_version<"3.2"',
                        'joinmarketbase==0.5.0', 'mnemonic', 'argon2_cffi',
                        'bencoder.pyx>=2.0.0', 'pyaes'],
      zip_safe=False)
