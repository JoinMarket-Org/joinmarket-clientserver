from setuptools import setup


setup(name='joinmarketbase',
      version='0.5.4',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='http://github.com/Joinmarket-Org/joinmarket-clientserver/jmbase',
      author='',
      author_email='',
      license='GPL',
      packages=['jmbase'],
      install_requires=['future', 'twisted==18.9.0', 'service-identity',
                        'chromalog==1.0.5'],
      zip_safe=False)
