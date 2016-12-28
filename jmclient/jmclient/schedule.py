#!/usr/bin/env python
from __future__ import print_function
from jmclient import (validate_address, rand_exp_array,
                      rand_norm_array, rand_pow_array)
"""Utility functions for dealing with Taker schedules.

- get_schedule(filename):
    attempt to read the schedule from the provided file
- get_tumble_schedule(options, destaddrs):
    generate a schedule for tumbling from a given wallet, using options dict
    and specified destinations
"""

def get_schedule(filename):
    with open(filename, "rb") as f:
        schedule = []
        schedule_lines = f.readlines()
        for sl in schedule_lines:
            if sl.startswith("#"):
                continue
            try:
                mixdepth, amount, makercount, destaddr, waittime = sl.split(',')
            except ValueError as e:
                return (False, "Failed to parse schedule line: " + sl)
            try:
                mixdepth = int(mixdepth)
                amount = int(amount)
                makercount = int(makercount)
                destaddr = destaddr.strip()
                waittime = float(waittime)
            except ValueError as e:
                return (False, "Failed to parse schedule line: " + sl)
            if destaddr != "INTERNAL":
                success, errmsg = validate_address(destaddr)
                if not success:
                    return (False, "Invalid address: " + destaddr + "," + errmsg)
            schedule.append((mixdepth, amount, makercount, destaddr, waittime))
    return (True, schedule)

def get_tumble_schedule(options, destaddrs):
    """for the general intent and design of the tumbler algo, see the docs in
    joinmarket-org/joinmarket.
    Alterations:
    Donation removed for now.
    Default final setting for "amount_fraction" is zero, for each mixdepth.
    This is because we now use a general "schedule" syntax for both tumbler and
    any other taker algo; it interprets floats as fractions and integers as satoshis,
    and zero as sweep (as before).
    This is a modified version of tumbler.py/generate_tumbler_tx()
    """
    def lower_bounded_int(thelist, lowerbound):
        return [int(l) if int(l) >= lowerbound else lowerbound for l in thelist]

    txcounts = rand_norm_array(options['txcountparams'][0],
                               options['txcountparams'][1], options['mixdepthcount'])
    txcounts = lower_bounded_int(txcounts, options['mintxcount'])
    tx_list = []
    for m, txcount in enumerate(txcounts):
        if options['mixdepthcount'] - options['addrcount'] <= m and m < \
                options['mixdepthcount'] - 1:
            #these mixdepths send to a destination address, so their
            # amount_fraction cant be 1.0, some coins must be left over
            if txcount == 1:
                txcount = 2
        # assume that the sizes of outputs will follow a power law
        amount_fractions = rand_pow_array(options['amountpower'], txcount)
        amount_fractions = [1.0 - x for x in amount_fractions]
        amount_fractions = [x / sum(amount_fractions) for x in amount_fractions]
        # transaction times are uncorrelated
        # time between events in a poisson process followed exp
        waits = rand_exp_array(options['timelambda'], txcount)
        # number of makers to use follows a normal distribution
        makercounts = rand_norm_array(options['makercountrange'][0],
                                      options['makercountrange'][1], txcount)
        makercounts = lower_bounded_int(makercounts, options['minmakercount'])

        for amount_fraction, wait, makercount in zip(amount_fractions, waits,
                                                     makercounts):
            tx = {'amount_fraction': amount_fraction,
                  'wait': round(wait, 2),
                  'srcmixdepth': m + options['mixdepthsrc'],
                  'makercount': makercount,
                  'destination': 'INTERNAL'}
            tx_list.append(tx)
        #reset the final amt_frac to zero, as it's the last one for this mixdepth:
        tx_list[-1]['amount_fraction'] = 0

    addrask = options['addrcount'] - len(destaddrs)
    external_dest_addrs = ['addrask'] * addrask + destaddrs
    for mix_offset in range(options['addrcount']):
        srcmix = (options['mixdepthsrc'] + options['mixdepthcount'] -
            mix_offset - 1)
        for tx in reversed(tx_list):
            if tx['srcmixdepth'] == srcmix:
                tx['destination'] = external_dest_addrs[mix_offset]
                break
        if mix_offset == 0:
            # setting last mixdepth to send all to dest
            tx_list_remove = []
            for tx in tx_list:
                if tx['srcmixdepth'] == srcmix:
                    if tx['destination'] == 'INTERNAL':
                        tx_list_remove.append(tx)
                    else:
                        tx['amount_fraction'] = 0
            [tx_list.remove(t) for t in tx_list_remove]
    schedule = []
    for t in tx_list:
        schedule.append((t['srcmixdepth'], t['amount_fraction'],
                  t['makercount'], t['destination'], t['wait']))
    return schedule