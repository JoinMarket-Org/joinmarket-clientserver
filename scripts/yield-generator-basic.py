#!/usr/bin/env python3

from jmbase import jmprint
from jmclient import YieldGeneratorBasic, ygmain

"""THESE SETTINGS CAN SIMPLY BE EDITED BY HAND IN THIS FILE:
"""
txfee = 100
cjfee_a = 500
cjfee_r = '0.00002'
ordertype = 'swreloffer' #'swreloffer' or 'swabsoffer'
nickserv_password = ''
max_minsize = 100000
gaplimit = 6

if __name__ == "__main__":
    ygmain(YieldGeneratorBasic, txfee=txfee, cjfee_a=cjfee_a,
           cjfee_r=cjfee_r, ordertype=ordertype,
           nickserv_password=nickserv_password,
           minsize=max_minsize, gaplimit=gaplimit)
    jmprint('done', "success")
