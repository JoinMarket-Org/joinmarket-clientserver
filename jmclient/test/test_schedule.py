#! /usr/bin/env python
from __future__ import absolute_import
'''test schedule module.'''

import pytest
from jmclient import (get_schedule, load_program_config)
import os

valids = """#sample for testing
1, 110000000, 3, INTERNAL
0, 20000000, 2, mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw
"""

invalids1 = """#sample for testing
1, 110000000, 3, 5, INTERNAL
#pointless comment here; following line has trailing spaces
0, 20000000, 2, mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw   
"""

invalids2 = """#sample for testing
1, 110000000, notinteger, INTERNAL
0, 20000000, 2, mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw
"""

invalids3 = """#sample for testing
1, 110000000, 3, INTERNAL
0, notinteger, 2, mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw
"""

#invalid address
invalids4 = """#sample for testing
1, 110000000, 3, INTERNAL
0, 20000000, 2, mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qq
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
            
            

        
    