from setuptools import setup


setup(name='joinmarketbitcoin',
      version='0.3.4',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='http://github.com/AdamISZ/joinmarket-clientserver/jmbitcoin',
      author='Adam Gibson',
      author_email='ekaggata@gmail.com',
      license='GPL',
      packages=['jmbitcoin'],
      install_requires=['secp256k1',],
      zip_safe=False)
