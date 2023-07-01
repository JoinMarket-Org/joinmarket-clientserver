#!/usr/bin/env python
from __future__ import print_function
import sys, os, subprocess

"""A script to install in one of 3 modes:
(a) daemon - installs jmbase, jmdaemon
(b) client-only - installs jmbase, jmclient
(c) client-bitcoin - installs jmbase, jmclient, jmbitcoin
(d) all - installs jmbase, jmclient, jmbitcoin, jmdaemon
(e) develop - installs jmbase, jmclient, jmbitcoin, jmdaemon linked to the source directoy

Note that b and c are distinct mainly due to the fact that
the latter requires the secp256k1 (libsecp256k1 via the secp256k1-py binding),
which is something that would be an annoyance if you don't need it (wallets).
While only (a) has a similarly annoying dependency on libnacl as the binding
to libsodium.
All modes require and install twisted.
"""

if sys.version_info < (3, 6):
    raise RuntimeError("This package requres Python 3.6+")

def help():
    print("Usage: python setupall.py <mode>\n"
          "Mode is one of:\n"
          "`--all` - for the full joinmarket package with secp256k1\n"
          "`--daemon` - for joinmarketd\n"
          "`--client-only` - for client not using joinmarket's own bitcoin code\n"
          "`--client-bitcoin` - using joinmarket bitcoin code, installs secp256k1\n"
          "`--develop` - uses the local code for all packages (does not install to site-packages)."
          )
    sys.exit(2)

if len(sys.argv) != 2:
    help()

curdir = os.getcwd()

mode = sys.argv[1]

packages = {"--all": ["jmbase", "jmbitcoin", "jmclient", "jmdaemon"],
            "--daemon": ["jmbase", "jmdaemon"],
            "--client-only": ["jmbase", "jmclient"],
            "--client-bitcoin": ["jmbase", "jmbitcoin", "jmclient"],
            "--develop": ["jmbase", "jmbitcoin", "jmclient", "jmdaemon"]}
if mode not in packages:
    help()

for x in packages[mode]:
    dirtorun = os.path.join(curdir, x)

    cmd = ['pip', 'install', '--upgrade']
    if mode == "--develop":
        cmd.append('-e')
    cmd.append('.')

    p = subprocess.Popen(cmd, cwd=dirtorun)
    p.wait()
