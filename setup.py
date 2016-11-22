from setuptools import setup
import sys
if '--client-only' in sys.argv:
    sys.argv.remove('--client-only')
    setup(name='joinmarketclient',
          version='0.1',
          description='Joinmarket client library for Bitcoin coinjoins',
          url='http://github.com/Joinmarket-Org/joinmarket-client',
          author='Adam Gibson',
          author_email='ekaggata@gmail.com',
          license='GPL',
          packages=['jmbase', 'jmclient'],
          install_requires=['twisted',],
          zip_safe=False)
elif '--client-bitcoin' in sys.argv:
    sys.argv.remove('--client-bitcoin')
    setup(name='joinmarketclient',
              version='0.1',
              description='Joinmarket client library for Bitcoin coinjoins',
              url='http://github.com/Joinmarket-Org/joinmarket-client',
              author='Adam Gibson',
              author_email='ekaggata@gmail.com',
              license='GPL',
              packages=['jmbase', 'jmbitcoin', 'jmclient'],
              install_requires=['twisted', 'secp256k1'],
              zip_safe=False)

elif '--backend' in sys.argv:
    sys.argv.remove('--backend')
    setup(name='joinmarketdaemon',
          version='0.1',
          description='Joinmarket daemon for Bitcoin coinjoins',
          author='Adam Gibson',
          author_email='ekaggata@gmail.com',
          license='GPL',
          packages=['jmbase','jmdaemon'],
          install_requires=['libnacl', 'twisted'],
          zip_safe=False)
else:
    raise Exception("Invalid arguments")
