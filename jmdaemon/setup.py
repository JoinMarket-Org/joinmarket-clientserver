from setuptools import setup


setup(name='joinmarketdaemon',
      version='0.9.5dev',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='https://github.com/JoinMarket-Org/joinmarket-clientserver/tree/master/jmdaemon',
      author='',
      author_email='',
      license='GPL',
      packages=['jmdaemon'],
      install_requires=['txtorcon',
        # See https://github.com/JoinMarket-Org/joinmarket-clientserver/issues/1139
        'cryptography==3.3.2;platform_system!="Darwin"', 'cryptography;platform_system=="Darwin"',
        'pyopenssl', 'libnacl', 'joinmarketbase==0.9.5dev'],
      python_requires='>=3.6',
      zip_safe=False)
