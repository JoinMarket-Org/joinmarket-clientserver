#!/usr/bin/env python3

from jmbase import jmprint
from jmclient import YieldGeneratorBasic, ygmain

"""THESE SETTINGS CAN SIMPLY BE EDITED BY HAND IN THIS FILE:
"""

ordertype = 'reloffer' # [string, 'reloffer' or 'absoffer'], which fee type to actually use
cjfee_a = 500 # [satoshis, any integer] / absolute offer fee you wish to receive for coinjoins (cj)
cjfee_r = '0.00002' # [fraction, any str between 0-1] / relative offer fee you wish to receive based on a cj's amount
txfee = 100 # [satoshis, any integer] / the average transaction fee you're adding to coinjoin transactions
nickserv_password = ''
minsize = 100000 # [satoshis, any integer] / minimum size of your cj offer. Lower cj amounts will be disregarded
gaplimit = 6

if __name__ == "__main__":
    ygmain(YieldGeneratorBasic, txfee=txfee, cjfee_a=cjfee_a,
           cjfee_r=cjfee_r, ordertype=ordertype,
           nickserv_password=nickserv_password,
           minsize=minsize, gaplimit=gaplimit)
    jmprint('done', "success")
