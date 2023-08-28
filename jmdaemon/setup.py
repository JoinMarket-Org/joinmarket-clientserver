from setuptools import setup


setup(name='joinmarketdaemon',
      version='0.9.10',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='https://github.com/JoinMarket-Org/joinmarket-clientserver/tree/master/jmdaemon',
      author='',
      author_email='',
      license='GPL',
      packages=['jmdaemon'],
      install_requires=['txtorcon==22.0.0',
                        'cryptography==3.3.2; platform_machine != "aarch64" and platform_machine != "amd64" and platform_machine != "x86_64"',
                        'cryptography==41.0.2; platform_machine == "aarch64" or platform_machine == "amd64" or platform_machine == "x86_64"',
                        'pyopenssl==23.2.0', 'libnacl==1.8.0',
                        'joinmarketbase==0.9.10'],
      python_requires='>=3.7',
      zip_safe=False)
