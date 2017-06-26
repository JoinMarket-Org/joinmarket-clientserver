from __future__ import absolute_import, print_function

from jmclient import load_program_config, wallet_tool_main
                      SegwitWallet, get_p2sh_vbyte)

if __name__ == "__main__":
    load_program_config()
    #JMCS follows same convention as JM original; wallet is in "wallets" localdir
    print(wallet_tool_main("wallets"))