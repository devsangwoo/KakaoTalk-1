#!/usr/bin/env python

from distutils.core import setup

setup(name='kakao',
      version='1.0.0',
      description='',
      author='s31z3th3d4y',
      author_email='',
      url='',
      packages=['kakao'],
      install_requires=[
        "pymongo >= 2.5.2",
        "rsa >= 3.1.1",
        "pycrypto >= 2.6",
      ],
     )
