"""
Utilities to calculate fidelity bonds values and statistics.
"""
from bisect import bisect_left
from datetime import datetime
from statistics import quantiles
from typing import Optional, Dict, Any, Mapping, Tuple, List

from jmclient import FidelityBondMixin, jm_single, get_interest_rate


def get_next_locktime(dt: datetime) -> datetime:
    """
    Return the next valid fidelity bond locktime.
    """
    year = dt.year + dt.month // 12
    month = dt.month % 12 + 1
    return datetime(year, month, 1)


def get_bond_values(amount: int,
                    months: int,
                    confirm_time: Optional[float] = None,
                    interest: Optional[float] = None,
                    exponent: Optional[float] = None,
                    orderbook: Optional[Mapping[str, Any]] = None) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Conveniently generate values [and statistics] for multiple possible fidelity bonds.

    Args:
        amount: Fidelity bond UTXO amount in satoshi
        months: For how many months to calculate the results
        confirm_time: Fidelity bond UTXO confirmation time as timestamp, if None, current time is used.
                      I.e., like if the fidelity bond UTXO with given amount has just confirmed on the blockchain.
        interest: Interest rate, if None, value is taken from config
        exponent: Exponent, if None, value is taken from config
        orderbook: Orderbook data, if given, additional statistics are included in the results.
    Returns:
        A tuple with 2 elements.
         First is a dictionary with all the parameters used to perform fidelity bond calculations.
         Second is a list of dictionaries, one for each month, with the results.
    """
    current_time = datetime.now().timestamp()
    if confirm_time is None:
        confirm_time = current_time
    if interest is None:
        interest = get_interest_rate()
    if exponent is None:
        exponent = jm_single().config.getfloat("POLICY", "bond_value_exponent")
        use_config_exp = True
    else:
        old_exponent = jm_single().config.get("POLICY", "bond_value_exponent")
        jm_single().config.set("POLICY", "bond_value_exponent", str(exponent))
        use_config_exp = False
    if orderbook:
        bond_values = [fb["bond_value"] for fb in orderbook["fidelitybonds"]]
        bonds_sum = sum(bond_values)
        percentiles = quantiles(bond_values, n=100, method="inclusive")

    parameters = {
        "amount": amount,
        "confirm_time": confirm_time,
        "current_time": current_time,
        "interest": interest,
        "exponent": exponent,
    }
    locktime = get_next_locktime(datetime.fromtimestamp(current_time))
    results = []
    for _ in range(months):
        fb_value = FidelityBondMixin.calculate_timelocked_fidelity_bond_value(
            amount,
            confirm_time,
            locktime.timestamp(),
            current_time,
            interest,
        )
        result = {"locktime": locktime.timestamp(),
                  "value": fb_value}
        if orderbook:
            result["weight"] = fb_value / (bonds_sum + fb_value)
            result["percentile"] = 100 - bisect_left(percentiles, fb_value)
        results.append(result)
        locktime = get_next_locktime(locktime)
    if not use_config_exp:
        # We don't want the modified exponent value to persist in memory, so we reset to whatever it was before
        jm_single().config.set("POLICY", "bond_value_exponent", old_exponent)
    return parameters, results
