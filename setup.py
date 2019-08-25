#!/usr/bin/env python

from distutils.core import setup
import sys

major, minor = sys.version_info[:2]
if not (major == 3 and minor >= 5):
    print('Only Python 3.5+ is supported')
    sys.exit(1)

setup(name='btclib',
      version='0.1.2',
      description="Badmofo's Btc Library",
      author='Lucas Ryan',
      author_email='badmofo@gmail.com',
      url='http://github.com/badmofo/btclib',
      packages=['btclib',],
      install_requires=[
                'simplejson',
            ],
      )
