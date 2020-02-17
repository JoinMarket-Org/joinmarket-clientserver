from setuptools import setup


setup(name='joinmarketbitcoin',
      version='0.7.0dev',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='http://github.com/Joinmarket-Org/joinmarket-clientserver/jmbitcoin',
      author='',
      author_email='',
      license='GPL',
      packages=['jmbitcoin'],
      install_requires=['future', 'coincurve', 'python-bitcointx', 'urldecode'],
      python_requires='>=3.5',
      zip_safe=False)
