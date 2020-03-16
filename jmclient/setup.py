from setuptools import setup


setup(name='joinmarketclient',
      version='0.6.2',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='http://github.com/Joinmarket-Org/joinmarket-clientserver/jmclient',
      author='',
      author_email='',
      license='GPL',
      packages=['jmclient'],
      install_requires=['future', 'configparser;python_version<"3.2"',
                        'joinmarketbase==0.6.2', 'mnemonic', 'argon2_cffi',
                        'bencoder.pyx>=2.0.0', 'pyaes'],
      python_requires='>=3.3',
      zip_safe=False)
