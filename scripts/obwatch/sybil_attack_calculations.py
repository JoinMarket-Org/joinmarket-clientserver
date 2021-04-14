
##this file calculates the success probability of a sybil attack on the
# orderbook with fidelity bonds used in joinmarket
# see https://gist.github.com/chris-belcher/87ebbcbb639686057a389acb9ab3e25b


#precomputed
#what sybil weight is required per-maker to sybil attack joinmarket with 95% success rate
#this is for when the honest weight (i.e. value of all fidelity bonds added up) equals 1
#however it is linear, so to calculate for another honest_weight just multiply
#see
#https://gist.github.com/chris-belcher/87ebbcbb639686057a389acb9ab3e25b#appendix-1---fit-to-unit-honest-weight-sybil-attack
successful_attack_95pc_sybil_weight = {
    1: 19.2125,
    2: 28.829523311823312,
    3: 35.37299702466422,
    4: 40.27618399827166,
    5: 44.19631358837695,
    6: 47.46160578701477,
    7: 50.25944623742167,
    8: 52.706868994753286,
    9: 54.881852860047836,
    10: 56.8389576639515,
    11: 58.61784778500215,
    12: 60.248261563672784,
    13: 61.75306801,
    14: 62.97189476,
    15: 64.28155594,
    16: 65.21832112385313,
    17: 66.29765063354174,
    18: 67.315269563541,
    19: 68.27785449480159,
    20: 69.19105386203657,
    21: 70.05968878944397,
    22: 70.88790716279642,
    23: 71.67930342495613,
    24: 72.43701285697972,
    25: 73.16378660022
}

def descend_probability_tree(weights, remaining_descents, branch_probability):
    if remaining_descents == 0:
        return branch_probability
    else:
        total_weight = sum(weights)
        result = 0
        for i, w in enumerate(weights):
            #honest makers are at index 0
            if i == 0:
                #an honest maker being chosen means the sybil attack failed
                #so this branch contributes zero to the attack success prob
                continue
            if w == 0:
                continue
            weight_cache = weights[i]
            weights[i] = 0
            result += descend_probability_tree(weights,
                remaining_descents-1, branch_probability*w/total_weight)
            weights[i] = weight_cache
        return result

def calculate_top_makers_sybil_attack_success_probability(weights, taker_peer_count):
    honest_weight = sum(weights[taker_peer_count:])
    weights = [honest_weight] + weights[:taker_peer_count]
    return descend_probability_tree(weights, taker_peer_count, 1.0)


def weight_to_burned_coins(w):
    #calculates how many coins need to be burned to produce a certain bond
    return w**0.5

def weight_to_locked_coins(w, r, locktime_months):
    #calculates how many coins need to be locked to produce a certain bond
    return w**0.5 / r / locktime_months * 12

def coins_locked_to_weight(c, r, locktime_months):
    return (c*r*locktime_months/12.0)**2

def coins_burned_to_weight(c):
    return c*c

