#! /usr/bin/env python
from __future__ import absolute_import
'''test schedule module.'''

import pytest
from jmclient import (get_schedule, get_tumble_schedule, load_program_config)
import os

valids = """#sample for testing
1, 110000000, 3, INTERNAL, 0
0, 20000000, 2, mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw, 9.88
"""

invalids1 = """#sample for testing
1, 110000000, 3, 5, INTERNAL, 0
#pointless comment here; following line has trailing spaces
0, 20000000, 2, mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw ,0  
"""

invalids2 = """#sample for testing
1, 110000000, notinteger, INTERNAL, 0
0, 20000000, 2, mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw, 0
"""

invalids3 = """#sample for testing
1, 110000000, 3, INTERNAL
0, notinteger, 2, mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw, 0
"""

#invalid address
invalids4 = """#sample for testing
1, 110000000, 3, INTERNAL, 0
0, 20000000, 2, mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qq, 0
"""


def test_get_schedule():
    load_program_config()
    tsf = "schedulefortesting"
    for s in [valids, invalids1, invalids2, invalids3, invalids4]:
        if os.path.exists(tsf):
            os.remove(tsf)
        with open(tsf, "wb") as f:
            f.write(s)
        result = get_schedule(tsf)
        if s== valids:
            assert result[0]
            assert len(result[1])==2
        else:
            assert not result[0]

class Options(object):
    pass

def get_options():
    options = Options()
    options.mixdepthsrc = 0
    options.mixdepthcount = 4
    options.txcountparams = (18, 3)
    options.minmakercount = 2
    options.makercountrange = (6, 0)
    options.maxcjfee = (0.01, 10000)
    options.txfee = 5000
    options.addrcount = 3
    options.mintxcount = 1
    options.amountpower = 100
    options.timelambda = 0.2
    options.waittime = 10
    options.mincjamount = 1000000
    options.liquiditywait = 5
    options = vars(options)
    return options

@pytest.mark.parametrize(
    "destaddrs, txcparams, mixdepthcount",
    [
        (["mzzAYbtPpANxpNVGCVBAhZYzrxyZtoix7i",
          "mifCWfmygxKhsP3qM3HZi3ZjBEJu7m39h8",
          "mnTn9KVQQT9zy9R4E2ZGzWPK4EfcEcV9Y5"], (18,3), 4),
        #intended to trigger txcount=1 bump to 2
        (["mzzAYbtPpANxpNVGCVBAhZYzrxyZtoix7i",
          "mifCWfmygxKhsP3qM3HZi3ZjBEJu7m39h8",
          "mnTn9KVQQT9zy9R4E2ZGzWPK4EfcEcV9Y5"], (3,2), 80),
    ])
def test_tumble_schedule(destaddrs, txcparams, mixdepthcount):
    options = get_options()
    options['mixdepthcount'] = mixdepthcount
    options['txcountparams'] = txcparams
    schedule = get_tumble_schedule(options, destaddrs)
    dests = [x[3] for x in schedule]
    assert set(destaddrs).issubset(set(dests))
            
            

        
    