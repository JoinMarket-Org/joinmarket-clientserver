from setuptools import setup


setup(name='joinmarketbase',
      version='0.9.11dev',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='https://github.com/JoinMarket-Org/joinmarket-clientserver/tree/master/jmbase',
      author='',
      author_email='',
      license='GPL',
      packages=['jmbase'],
      install_requires=['twisted==22.4.0', 'service-identity==21.1.0',
                        'chromalog==1.0.5', 'pyaes==1.6.1',
                        'txtorcon==22.0.0'],
      python_requires='>=3.7',
      zip_safe=False)
