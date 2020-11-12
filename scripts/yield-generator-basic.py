#!/usr/bin/env python3

from jmbase import jmprint
from jmclient import YieldGeneratorBasic, ygmain

# YIELD GENERATOR SETTINGS ARE NOW IN YOUR joinmarket.cfg CONFIG FILE
# (You can also use command line flags; see --help for this script).

if __name__ == "__main__":
    ygmain(YieldGeneratorBasic, nickserv_password='')
    jmprint('done', "success")
