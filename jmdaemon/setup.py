from setuptools import setup


setup(name='joinmarketdaemon',
      version='0.9.8',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='https://github.com/JoinMarket-Org/joinmarket-clientserver/tree/master/jmdaemon',
      author='',
      author_email='',
      license='GPL',
      packages=['jmdaemon'],
      install_requires=['txtorcon', 'cryptography==3.3.2', 'pyopenssl', 'libnacl', 'joinmarketbase==0.9.8'],
      python_requires='>=3.6',
      zip_safe=False)
