#!/usr/bin/env python
import copy
import random
import sys

from .configure import validate_address, jm_single
from .support import rand_exp_array, rand_norm_array, rand_weighted_choice
"""Utility functions for dealing with Taker schedules.

- get_schedule(filename):
    attempt to read the schedule from the provided file
- get_tumble_schedule(options, destaddrs):
    generate a schedule for tumbling from a given wallet, using options dict
    and specified destinations
- tweak_tumble_schedule(options, schedule, last_completed):
    make alterations to the remaining entries in a mixdepth to maximize
    the chance of success on re-trying
"""

NO_ROUNDING = 16 #max btc significant figures not including LN

def get_schedule(filename):
    with open(filename, "rb") as f:
        schedule = []
        schedule_lines = f.readlines()
        for sl in schedule_lines:
            sl = sl.decode('utf-8')
            if sl.startswith("#"):
                continue
            try:
                (mixdepth, amount, makercount, destaddr, waittime,
                    rounding, completed) = sl.split(',')
            except ValueError as e:
                return (False, "Failed to parse schedule line: " + sl)
            try:
                mixdepth = int(mixdepth)
                #TODO this isn't the right way, but floats must be allowed
                #for any persisted tumbler-style schedule
                if "." in amount:
                    amount = float(amount)
                else:
                    amount = int(amount)
                makercount = int(makercount)
                destaddr = destaddr.strip()
                waittime = float(waittime)
                rounding = int(rounding)
                completed = completed.strip()
                if not len(completed) == 64:
                    completed = int(completed)
            except ValueError as e:
                return (False, "Failed to parse schedule line: " + sl)
            if destaddr not in ["INTERNAL", "addrask"]:
                success, errmsg = validate_address(destaddr)
                if not success:
                    return (False, "Invalid address: " + destaddr + "," + errmsg)
            schedule.append([mixdepth, amount, makercount, destaddr,
                             waittime, rounding, completed])
    return (True, schedule)

def get_amount_fractions(count):
    """Get 'count' fractions following uniform distn
    Note that this function is not entirely generic; it ensures that
    the final entry is larger than a certain fraction, for a reason
    specific to the way the tumbler algo works: the last entry
    corresponds to a sweep which takes the remaining coins; if this
    ends up being too small, it cannot be tweaked using the mincjamount
    setting, so we make sure it's appreciable to begin with.
    """
    while True:
        knives = [random.random() for i in range(count-1)]
        knives = sorted(knives)[::-1]
        y = []
        l = 1
        k = 1
        for k in knives:
            y.append( l - k )
            l = k
        y.append(k)

        #Here we insist that the last entry in the list is more
        #than 5% of the total, to account for tweaks upwards
        #on previous joins.
        if y[-1] > 0.05:
            break
    return y

def get_tumble_schedule(options, destaddrs, mixdepth_balance_dict):
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
    #if options['mixdepthsrc'] != 0:
    #    raise NotImplementedError("Non-zero mixdepth source not supported; "
    #                              "restart the tumbler with --restart instead")

    def lower_bounded_int(thelist, lowerbound):
        return [int(l) if int(l) >= lowerbound else lowerbound for l in thelist]

    txcounts = rand_norm_array(options['txcountparams'][0],
                               options['txcountparams'][1], options['mixdepthcount'])
    txcounts = lower_bounded_int(txcounts, options['mintxcount'])
    tx_list = []
    ### stage 1 coinjoins, which sweep the entire mixdepth without creating change
    lowest_initial_filled_mixdepth = sys.maxsize
    sweep_mixdepths = []
    for mixdepth, balance in mixdepth_balance_dict.items():
        if balance > 0:
            lowest_initial_filled_mixdepth = min(mixdepth,
                lowest_initial_filled_mixdepth)
            sweep_mixdepths.append(mixdepth)
    waits = rand_exp_array(options['timelambda']*options[
        'stage1_timelambda_increase'], len(sweep_mixdepths))
    makercounts = rand_norm_array(options['makercountrange'][0],
        options['makercountrange'][1], len(sweep_mixdepths))
    makercounts = lower_bounded_int(makercounts, options['minmakercount'])
    sweep_mixdepths = sorted(sweep_mixdepths)[::-1]
    for mixdepth, wait, makercount in zip(sweep_mixdepths, waits, makercounts):
        tx = {'amount_fraction': 0,
              'wait': round(wait, 2),
              'srcmixdepth': mixdepth,
              'makercount': makercount,
              'destination': 'INTERNAL',
              'rounding': NO_ROUNDING
        }
        tx_list.append(tx)
    ### stage 2 coinjoins, which create a number of random-amount coinjoins from each mixdepth
    for m, txcount in enumerate(txcounts):
        if options['mixdepthcount'] - options['addrcount'] <= m and m < \
                options['mixdepthcount'] - 1:
            #these mixdepths send to a destination address, so their
            # amount_fraction cant be 1.0, some coins must be left over
            if txcount == 1:
                txcount = 2
        amount_fractions = get_amount_fractions(txcount)
        # transaction times are uncorrelated
        # time between events in a poisson process followed exp
        waits = rand_exp_array(options['timelambda'], txcount)
        # number of makers to use follows a normal distribution
        makercounts = rand_norm_array(options['makercountrange'][0],
                                      options['makercountrange'][1], txcount)
        makercounts = lower_bounded_int(makercounts, options['minmakercount'])
        do_rounds = [random.random() < options['rounding_chance'] for _ in range(txcount)]
        for amount_fraction, wait, makercount, do_round in zip(amount_fractions, waits,
                                                     makercounts, do_rounds):
            rounding = NO_ROUNDING
            if do_round:
                weight_sum = 1.0*sum(options['rounding_sigfig_weights'])
                weight_prob = [a/weight_sum for a in options['rounding_sigfig_weights']]
                rounding = rand_weighted_choice(len(weight_prob), weight_prob) + 1
            tx = {'amount_fraction': amount_fraction,
                  'wait': round(wait, 2),
                  'srcmixdepth': lowest_initial_filled_mixdepth + m + options['mixdepthsrc'] + 1,
                  'makercount': makercount,
                  'destination': 'INTERNAL',
                  'rounding': rounding
            }
            tx_list.append(tx)
        #reset the final amt_frac to zero, as it's the last one for this mixdepth:
        tx_list[-1]['amount_fraction'] = 0
        tx_list[-1]['rounding'] = NO_ROUNDING

    addrask = options['addrcount'] - len(destaddrs)
    external_dest_addrs = ['addrask'] * addrask + destaddrs[::-1]
    for mix_offset in range(options['addrcount']):
        srcmix = (lowest_initial_filled_mixdepth + options['mixdepthsrc']
            + options['mixdepthcount'] - mix_offset)
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
        schedule.append([t['srcmixdepth'], t['amount_fraction'],
                  t['makercount'], t['destination'], t['wait'],
                  t['rounding'], 0])
    return schedule

def tweak_tumble_schedule(options, schedule, last_completed, destaddrs=[]):
    """If a tx in a schedule failed for some reason, and we want
    to make a best effort to complete the schedule, we can tweak
    the failed entry to improve the odds of success on re-try.
    Both the size/amount and the number of counterparties may have
    been a cause for failure, so we change both of those where
    possible.
    Returns a new, altered schedule file (should continue at same index)
    """
    new_schedule = copy.deepcopy(schedule)
    altered = new_schedule[last_completed + 1]
    if not altered[3] in destaddrs:
        altered[3] = "INTERNAL"
    #For sweeps, we'll try with a lower number of counterparties if we can.
    #Note that this is usually counterproductive for non-sweeps, which fall
    #back and so benefit in reliability from *higher* counterparty numbers.
    if altered[1] == 0:
        new_n_cp = altered[2] - 1
        if new_n_cp < jm_single().config.getint("POLICY", "minimum_makers"):
            new_n_cp = jm_single().config.getint("POLICY", "minimum_makers")
        altered[2] = new_n_cp
    if not altered[1] == 0:
        #For non-sweeps, there's a fractional amount (tumbler).
        #Increasing or decreasing the amount could improve the odds of success,
        #since it depends on liquidity and minsizes, so we tweak in both
        #directions randomly.
        #Strategy:
        #1. calculate the total percentage remaining in the mixdepth.
        #2. calculate the number remaining incl. sweep.
        #3. Re-use 'getamountfracs' algo for this reduced number, then scale it
        #to the number remaining.
        #4. As before, reset the final to '0' for sweep.
        #find the number of entries remaining, not including the final sweep,
        #for this mixdepth:

        #First get all sched entries for this mixdepth
        this_mixdepth_entries = [s for s in new_schedule if s[0] == altered[0]]
        already_done = this_mixdepth_entries[:this_mixdepth_entries.index(altered)]
        tobedone = this_mixdepth_entries[this_mixdepth_entries.index(altered):]

        #find total frac left to be spent
        alreadyspent = sum([x[1] for x in already_done])
        tobespent = 1.0 - alreadyspent
        #power law for what's left:
        new_fracs = get_amount_fractions(len(tobedone))
        #rescale; the sum must be 'tobespent':
        new_fracs = [x*tobespent for x in new_fracs]
        #starting from the known 'last_completed+1' index, apply these new
        #fractions, with 0 at the end for sweep
        for i, j in enumerate(range(
            last_completed + 1, last_completed + 1 + len(tobedone))):
            new_schedule[j][1] = new_fracs[i]
        #reset the sweep
        new_schedule[last_completed + 1 + len(tobedone) - 1][1] = 0
    return new_schedule

def human_readable_schedule_entry(se, amt=None, destn=None):
    hrs = []
    hrs.append("From mixdepth " + str(se[0]))
    amt_info = str(amt) if amt else str(se[1])
    hrs.append("sends amount: " + amt_info + " satoshis")
    dest_info = destn if destn else str(se[3])
    hrs.append(("rounded to " + str(se[5]) + " significant figures"
        if se[5] != NO_ROUNDING else "without rounding"))
    hrs.append("to destination address: " + dest_info)
    hrs.append("after coinjoin with " + str(se[2]) + " counterparties.")
    return ", ".join(hrs)

def schedule_to_text(schedule):
    return "\n".join([",".join([str(y) for y in x]) for x in schedule]).encode('utf-8')
