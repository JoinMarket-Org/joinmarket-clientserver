from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401

from jmclient import load_program_config, wallet_tool_main

if __name__ == "__main__":
    load_program_config()
    #JMCS follows same convention as JM original; wallet is in "wallets" localdir
    print(wallet_tool_main("wallets"))