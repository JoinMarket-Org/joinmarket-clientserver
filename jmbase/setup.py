from setuptools import setup


setup(name='joinmarketbase',
      version='0.3.2',
      description='Joinmarket client library for Bitcoin coinjoins',
      url='http://github.com/AdamISZ/joinmarket-clientserver/jmbase',
      author='Adam Gibson',
      author_email='ekaggata@gmail.com',
      license='GPL',
      packages=['jmbase'],
      install_requires=['twisted', 'service-identity'],
      zip_safe=False)
