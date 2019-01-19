from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401

from jmbase import jmprint
from jmclient import load_program_config, wallet_tool_main
from cli_options import check_regtest

if __name__ == "__main__":
    load_program_config()
    check_regtest(blockchain_start=False)
    #JMCS follows same convention as JM original; wallet is in "wallets" localdir
    jmprint(wallet_tool_main("wallets"), "success")