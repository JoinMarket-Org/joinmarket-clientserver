from setuptools import setup


setup(name='joinmarketdaemon',
      version='0.9.9dev',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='https://github.com/JoinMarket-Org/joinmarket-clientserver/tree/master/jmdaemon',
      author='',
      author_email='',
      license='GPL',
      packages=['jmdaemon'],
      install_requires=['txtorcon==22.0.0', 'cryptography==3.3.2',
                        'pyopenssl==21.0.0', 'libnacl==1.8.0',
                        'joinmarketbase==0.9.9dev'],
      python_requires='>=3.6',
      zip_safe=False)
