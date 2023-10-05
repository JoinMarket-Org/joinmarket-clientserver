#! /usr/bin/env python
'''test schedule module.'''

import pytest
from jmclient import (get_schedule, get_tumble_schedule,
                      tweak_tumble_schedule, load_test_config)
import os

pytestmark = pytest.mark.usefixtures("setup_regtest_bitcoind")

valids = """#sample for testing
1, 110000000, 3, INTERNAL, 0, 16, 1
0, 20000000, 2, mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw, 9.88, 16, 0
"""

invalids1 = """#sample for testing
1, 110000000, 3, 5, INTERNAL, 16, 0
#pointless comment here; following line has trailing spaces
0, 20000000, 2, mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw ,0, 16, 0,  
"""

invalids2 = """#sample for testing
1, 110000000, notinteger, INTERNAL, 0, 16, 0
0, 20000000, 2, mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw, 0, 16, 0
"""

invalids3 = """#sample for testing
1, 110000000, 3, INTERNAL, 0, 16, 0
0, notinteger, 2, mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw, 0, 16, 0
"""

#invalid address
invalids4 = """#sample for testing
1, 110000000, 3, INTERNAL, 0, 16, 0
0, 20000000, 2, mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qq, 0, 16, 0
"""


def test_get_schedule():
    load_test_config()
    tsf = "schedulefortesting"
    for s in [valids, invalids1, invalids2, invalids3, invalids4]:
        if os.path.exists(tsf):
            os.remove(tsf)
        with open(tsf, "wb") as f:
            f.write(s.encode('utf-8'))
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
    options.mixdepthcount = 4
    options.txcountparams = (18, 3)
    options.minmakercount = 2
    options.makercountrange = (6, 0)
    options.txfee = 5000
    options.addrcount = 3
    options.mintxcount = 1
    options.timelambda = 0.2
    options.waittime = 10
    options.stage1_timelambda_increase = 3
    options.mincjamount = 1000000
    options.liquiditywait = 5
    options.rounding_chance = 0.25
    options.rounding_sigfig_weights = (55, 15, 25, 65, 40)
    options = vars(options)
    return options

@pytest.mark.parametrize(
    "destaddrs, txcparams, mixdepthcount, mixdepthbal",
    [
        # very simple case
        (["mzzAYbtPpANxpNVGCVBAhZYzrxyZtoix7i",
          "mifCWfmygxKhsP3qM3HZi3ZjBEJu7m39h8",
          "mnTn9KVQQT9zy9R4E2ZGzWPK4EfcEcV9Y5"], (3,0), 3,
        {0:1}),
        # with 2 non-empty mixdepths
        (["mzzAYbtPpANxpNVGCVBAhZYzrxyZtoix7i",
          "mifCWfmygxKhsP3qM3HZi3ZjBEJu7m39h8",
          "mnTn9KVQQT9zy9R4E2ZGzWPK4EfcEcV9Y5"], (7,0), 3,
         {2:1, 3: 1}),
        #intended to trigger txcount=1 bump to 2
        (["mzzAYbtPpANxpNVGCVBAhZYzrxyZtoix7i",
          "mifCWfmygxKhsP3qM3HZi3ZjBEJu7m39h8",
          "mnTn9KVQQT9zy9R4E2ZGzWPK4EfcEcV9Y5"], (3,2), 8,
         {2:1, 3: 1}),
        #slightly larger version
        (["mzzAYbtPpANxpNVGCVBAhZYzrxyZtoix7i",
          "mifCWfmygxKhsP3qM3HZi3ZjBEJu7m39h8",
          "mnTn9KVQQT9zy9R4E2ZGzWPK4EfcEcV9Y5",
          "bcrt1qcnv26w889eum5sekz5h8we45rxnr4sj5k08phv",
          "bcrt1qgs0t239gj2kqgnsrvetvsv2qdva8y3j74cta4d"], (4,3), 8,
         {0:2, 1: 1, 3: 1, 4: 1}),
    ])
def test_tumble_schedule(destaddrs, txcparams, mixdepthcount, mixdepthbal):
    # note that these tests are currently only leaving the default
    # value for the final argument to get_tumble_schedule, i.e. 4,
    # and will fail if this is changed:
    wallet_total_mixdepths = 5
    options = get_options()
    options['addrcount'] = len(destaddrs)
    options['mixdepthcount'] = mixdepthcount
    options['txcountparams'] = txcparams
    schedule = get_tumble_schedule(options, destaddrs, mixdepthbal)
    # first, examine the destination addresses; all the requested
    # ones should be in the list, and all the others should be one
    # of the two standard 'code' alternatives.
    dests = [x[3] for x in schedule]
    dests = [x for x in dests if x not in ["INTERNAL", "addrask"]]
    assert len(dests) == len(destaddrs)
    assert set(destaddrs) == set(dests)
    nondestaddrs = [x[3] for x in schedule if x[3] not in destaddrs]
    assert all([x in ["INTERNAL", "addrask"] for x in nondestaddrs])
    # check that the source mixdepths for the phase 1 transactions are the
    # expected, and that they are all sweeps:
    for i, s in enumerate(schedule[:len(mixdepthbal)]):
        assert s[1] == 0
        assert s[0] in mixdepthbal.keys()
    # check that the list of created transactions in Phase 2 only
    # progresses forward, one mixdepth at a time.
    # Note that due to the use of sdev calculation, we cannot check that
    # the number of transactions per mixdepth is anything in particular.
    for first, second in zip(schedule[len(mixdepthbal):-1],
                             schedule[len(mixdepthbal) + 1:]):
        assert (second[0] - first[0]) % wallet_total_mixdepths in [1, 0]
    # check that the amount fractions are always total < 1
    last_s = []
    for s in schedule:
        if last_s == []:
            last_s = s
            total_amt = 0
            continue
        if s[0] == last_s[0]:
            total_amt += s[1]
        else:
            assert total_amt < 1
            total_amt = 0
        last_s = s

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
          "mnTn9KVQQT9zy9R4E2ZGzWPK4EfcEcV9Y5"], (4,1), 7, 6, (6,1)),
    ])
def test_tumble_tweak(destaddrs, txcparams, mixdepthcount, lastcompleted,
                      makercountrange):
    load_test_config()
    options = get_options()
    options['mixdepthcount'] = mixdepthcount
    options['txcountparams'] = txcparams
    options['makercountrange'] = makercountrange
    schedule = get_tumble_schedule(options, destaddrs, {0:1})
    dests = [x[3] for x in schedule]
    assert set(destaddrs).issubset(set(dests))
    new_schedule = tweak_tumble_schedule(options, schedule, lastcompleted)
    #sanity check: each amount fraction list should add up to near 1.0,
    #so some is left over for sweep
    tally = 0
    current_mixdepth = new_schedule[0][0]
    for i in range(mixdepthcount):
        if new_schedule[i][0] != current_mixdepth:
            print('got total frac for mixdepth: ', tally)
            #TODO spurious failure is possible here, not an ideal check
            assert tally < 0.999
            tally = 0
        tally += new_schedule[i][1]
