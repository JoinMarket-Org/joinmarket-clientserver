from setuptools import setup


setup(name='joinmarketbase',
      version='0.9.3',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='https://github.com/JoinMarket-Org/joinmarket-clientserver/tree/master/jmbase',
      author='',
      author_email='',
      license='GPL',
      packages=['jmbase'],
      install_requires=['twisted==20.3.0', 'service-identity',
                        'chromalog==1.0.5'],
      python_requires='>=3.6',
      zip_safe=False)
