#!/usr/bin/env python
from __future__ import print_function
import sys, os, subprocess

"""A script to install in one of 3 modes:
(a) daemon - installs jmbase, jmdaemon
(b) client-only - installs jmbase, jmclient
(c) client-bitcoin - installs jmbase, jmclient, jmbitcoin

Note that b and c are distinct mainly due to the fact that
the latter requires the secp256k1 (libsecp256k1 via the secp256k1-py binding),
which is something that would be an annoyance if you don't need it (wallets).
While only (a) has a similarly annoying dependency on libnacl as the binding
to libsodium.
All modes require and install twisted.
"""

def help():
    print("Usage: python setupall.py <mode>\n"
          "Mode is one of:\n"
          "`--daemon` - for joinmarketd\n"
          "`--client-only` - for client not using joinmarket's own bitcoin code\n"
          "`--client-bitcoin` - using joinmarket bitcoin code, installs secp256k1.")
    sys.exit(0)

if len(sys.argv) != 2:
    help()

curdir = os.getcwd()

mode = sys.argv[1]

packages = {"--daemon": ["jmbase", "jmdaemon"],
            "--client-only": ["jmbase", "jmclient"],
            "--client-bitcoin": ["jmbase", "jmbitcoin", "jmclient"]}
if mode not in packages:
    help()

for x in packages[mode]:
    dirtorun = os.path.join(curdir, x)
    p = subprocess.Popen(['python', 'setup.py', 'install'], cwd=dirtorun)
    p.wait()
