#! /usr/bin/env python
from __future__ import absolute_import
'''test schedule module.'''

import pytest
from jmclient import (get_schedule, get_tumble_schedule,
                      tweak_tumble_schedule, load_program_config)
import os

valids = """#sample for testing
1, 110000000, 3, INTERNAL, 0, 1
0, 20000000, 2, mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw, 9.88, 0
"""

invalids1 = """#sample for testing
1, 110000000, 3, 5, INTERNAL, 0
#pointless comment here; following line has trailing spaces
0, 20000000, 2, mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw ,0, 0,  
"""

invalids2 = """#sample for testing
1, 110000000, notinteger, INTERNAL, 0, 0
0, 20000000, 2, mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw, 0, 0
"""

invalids3 = """#sample for testing
1, 110000000, 3, INTERNAL, 0, 0
0, notinteger, 2, mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw, 0, 0
"""

#invalid address
invalids4 = """#sample for testing
1, 110000000, 3, INTERNAL, 0, 0
0, 20000000, 2, mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qq, 0, 0
"""


def test_get_schedule():
    load_program_config()
    tsf = "schedulefortesting"
    for s in [valids, invalids1, invalids2, invalids3, invalids4]:
        if os.path.exists(tsf):
            os.remove(tsf)
        with open(tsf, "wb") as f:
            f.write(s.encode("utf-8"))
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

@pytest.mark.parametrize(
    "destaddrs, txcparams, mixdepthcount, lastcompleted, makercountrange",
    [
        (["mzzAYbtPpANxpNVGCVBAhZYzrxyZtoix7i",
          "mifCWfmygxKhsP3qM3HZi3ZjBEJu7m39h8",
          "mnTn9KVQQT9zy9R4E2ZGzWPK4EfcEcV9Y5"], (6,0), 5, 17, (6,0)),
        #edge case: very first transaction
        (["mzzAYbtPpANxpNVGCVBAhZYzrxyZtoix7i",
          "mifCWfmygxKhsP3qM3HZi3ZjBEJu7m39h8",
          "mnTn9KVQQT9zy9R4E2ZGzWPK4EfcEcV9Y5"], (3,0), 4, -1, (6,0)),
        #edge case: hit minimum_makers limit
        (["mzzAYbtPpANxpNVGCVBAhZYzrxyZtoix7i",
          "mifCWfmygxKhsP3qM3HZi3ZjBEJu7m39h8",
          "mnTn9KVQQT9zy9R4E2ZGzWPK4EfcEcV9Y5"], (3,0), 4, -1, (2,0)),
        #edge case: it's a sweep
        (["mzzAYbtPpANxpNVGCVBAhZYzrxyZtoix7i",
          "mifCWfmygxKhsP3qM3HZi3ZjBEJu7m39h8",
          "mnTn9KVQQT9zy9R4E2ZGzWPK4EfcEcV9Y5"], (3,0), 4, 1, (5,0)),
        #mid-run case in 2nd mixdepth
        (["mzzAYbtPpANxpNVGCVBAhZYzrxyZtoix7i",
          "mifCWfmygxKhsP3qM3HZi3ZjBEJu7m39h8",
          "mnTn9KVQQT9zy9R4E2ZGzWPK4EfcEcV9Y5"], (6,0), 4, 7, (5,0)),
        #sanity check, typical parameters
        (["mzzAYbtPpANxpNVGCVBAhZYzrxyZtoix7i",
          "mifCWfmygxKhsP3qM3HZi3ZjBEJu7m39h8",
          "mnTn9KVQQT9zy9R4E2ZGzWPK4EfcEcV9Y5"], (4,1), 4, 6, (6,1)),
    ])
def test_tumble_tweak(destaddrs, txcparams, mixdepthcount, lastcompleted,
                      makercountrange):
    load_program_config()
    options = get_options()
    options['mixdepthcount'] = mixdepthcount
    options['txcountparams'] = txcparams
    options['makercountrange'] = makercountrange
    schedule = get_tumble_schedule(options, destaddrs)
    dests = [x[3] for x in schedule]
    assert set(destaddrs).issubset(set(dests))
    new_schedule = tweak_tumble_schedule(options, schedule, lastcompleted)
    #sanity check: each amount fraction list should add up to near 1.0,
    #so some is left over for sweep
    for i in range(mixdepthcount):
        entries = [x for x in new_schedule if x[0] == i]
        total_frac_for_mixdepth = sum([x[1] for x in entries])
        #TODO spurious failure is possible here, not an ideal check
        print('got total frac for mixdepth: ', str(total_frac_for_mixdepth))
        assert total_frac_for_mixdepth < 0.999
    from pprint import pformat
    print("here is the new schedule: ")
    print(pformat(new_schedule))
    print("and old:")
    print(pformat(schedule))
