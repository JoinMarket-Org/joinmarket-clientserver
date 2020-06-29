from setuptools import setup


setup(name='joinmarketbitcoin',
      version='0.6.3.1',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='http://github.com/Joinmarket-Org/joinmarket-clientserver/jmbitcoin',
      author='',
      author_email='',
      license='GPL',
      packages=['jmbitcoin'],
      install_requires=['future', 'coincurve', 'urldecode'],
      python_requires='>=3.5',
      zip_safe=False)
