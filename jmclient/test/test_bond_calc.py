from datetime import datetime

import pytest
from jmclient import jm_single, load_test_config, FidelityBondMixin
from jmclient.bond_calc import get_next_locktime, get_bond_values


@pytest.mark.parametrize(('date', 'next_locktime'),
                         ((datetime(2022, 1, 1, 1, 1), datetime(2022, 2, 1)),
                          (datetime(2022, 11, 1, 1, 1), datetime(2022, 12, 1)),
                          (datetime(2022, 12, 1, 1, 1), datetime(2023, 1, 1))))
def test_get_next_locktime(date: datetime, next_locktime: datetime) -> None:
    assert get_next_locktime(date) == next_locktime


def test_get_bond_values() -> None:
    load_test_config()
    # 1 BTC
    amount = pow(10, 8)
    months = 1
    interest = jm_single().config.getfloat("POLICY", "interest_rate")
    exponent = jm_single().config.getfloat("POLICY", "bond_value_exponent")
    parameters, results = get_bond_values(amount, months)
    assert parameters["amount"] == amount
    assert parameters["current_time"] == parameters["confirm_time"]
    assert parameters["interest"] == interest
    assert parameters["exponent"] == exponent
    assert len(results) == months
    locktime = datetime.fromtimestamp(results[0]["locktime"])
    assert locktime.month == get_next_locktime(datetime.now()).month
    value = FidelityBondMixin.calculate_timelocked_fidelity_bond_value(
        parameters["amount"],
        parameters["confirm_time"],
        results[0]["locktime"],
        parameters["current_time"],
        parameters["interest"],
    )
    assert results[0]["value"] == value

    months = 12
    interest = 0.02
    exponent = 2
    confirm_time = datetime(2021, 12, 1).timestamp()
    parameters, results = get_bond_values(amount,
                                          months,
                                          confirm_time,
                                          interest,
                                          exponent)
    assert parameters["amount"] == amount
    assert parameters["current_time"] != parameters["confirm_time"]
    assert parameters["confirm_time"] == confirm_time
    assert parameters["interest"] == interest
    assert parameters["exponent"] == exponent
    assert len(results) == months
    current_time = datetime.now()
    # get_bond_values(), at the end, reset the exponent to the config one.
    # So we have to set the exponent here, otherwise the bond value calculation
    # won't match and the assert would fail.
    old_exponent = jm_single().config.get("POLICY", "bond_value_exponent")
    jm_single().config.set("POLICY", "bond_value_exponent", str(exponent))
    for result in results:
        locktime = datetime.fromtimestamp(result["locktime"])
        assert locktime.month == get_next_locktime(current_time).month
        current_time = locktime
        value = FidelityBondMixin.calculate_timelocked_fidelity_bond_value(
            parameters["amount"],
            parameters["confirm_time"],
            result["locktime"],
            parameters["current_time"],
            parameters["interest"],
        )
        assert result["value"] == value
    jm_single().config.set("POLICY", "bond_value_exponent", old_exponent)
