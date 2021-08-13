from setuptools import setup


setup(name='joinmarketdaemon',
      version='0.9.1',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='http://github.com/Joinmarket-Org/joinmarket-clientserver/jmdaemon',
      author='',
      author_email='',
      license='GPL',
      packages=['jmdaemon'],
      install_requires=['txtorcon', 'cryptography==3.3.2', 'pyopenssl', 'libnacl', 'joinmarketbase==0.9.1'],
      python_requires='>=3.6',
      zip_safe=False)
