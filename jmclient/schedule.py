#!/usr/bin/env python
from __future__ import print_function
from jmclient import validate_address
"""Utility functions for dealing with Taker schedules.

- attempt to read the schedule from the provided file
- (TODO) generate a schedule for e.g. tumbling from a given wallet, with parameters
"""

def get_schedule(filename):
    with open(filename, "rb") as f:
        schedule = []
        schedule_lines = f.readlines()
        for sl in schedule_lines:
            if sl.startswith("#"):
                continue
            try:
                mixdepth, amount, makercount, destaddr = sl.split(',')
            except ValueError as e:
                return (False, "Failed to parse schedule line: " + sl)
            try:
                mixdepth = int(mixdepth)
                amount = int(amount)
                makercount = int(makercount)
                destaddr = destaddr.strip()
            except ValueError as e:
                return (False, "Failed to parse schedule line: " + sl)
            success, errmsg = validate_address(destaddr)
            if not success:
                return (False, "Invalid address: " + destaddr + "," + errmsg)
            schedule.append((mixdepth, amount, makercount, destaddr))
    return (True, schedule)
