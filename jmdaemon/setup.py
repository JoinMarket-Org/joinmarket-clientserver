from setuptools import setup


setup(name='joinmarketdaemon',
      version='0.3.5',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='http://github.com/Joinmarket-Org/joinmarket-clientserver/jmdaemon',
      author='',
      author_email='',
      license='GPL',
      packages=['jmdaemon'],
      install_requires=['txsocksx', 'pyopenssl', 'libnacl', 'joinmarketbase==0.3.5'],
      zip_safe=False)
