from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401

from jmbase import jmprint
from jmclient import wallet_tool_main

if __name__ == "__main__":
    jmprint(wallet_tool_main("wallets"), "success")