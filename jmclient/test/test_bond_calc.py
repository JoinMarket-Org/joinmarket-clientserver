from datetime import datetime

import pytest
from jmclient import jm_single, load_test_config, FidelityBondMixin
from jmclient.bond_calc import get_next_locktime, get_bond_values, get_percentiles


@pytest.mark.parametrize(('date', 'next_locktime'),
                         ((datetime(2022, 1, 1, 1, 1), datetime(2022, 2, 1)),
                          (datetime(2022, 11, 1, 1, 1), datetime(2022, 12, 1)),
                          (datetime(2022, 12, 1, 1, 1), datetime(2023, 1, 1))))
def test_get_next_locktime(date: datetime, next_locktime: datetime) -> None:
    assert get_next_locktime(date) == next_locktime


@pytest.mark.parametrize(("data", "percentiles"),
                         (([1, 2],
                          [1.01, 1.02, 1.03, 1.04, 1.05, 1.06, 1.07, 1.08, 1.09, 1.1, 1.11, 1.12, 1.13, 1.14, 1.15,
                           1.16, 1.17, 1.18, 1.19, 1.2, 1.21, 1.22, 1.23, 1.24, 1.25, 1.26, 1.27, 1.28, 1.29, 1.3, 1.31,
                           1.32, 1.33, 1.34, 1.35, 1.36, 1.37, 1.38, 1.39, 1.4, 1.41, 1.42, 1.43, 1.44, 1.45, 1.46,
                           1.47, 1.48, 1.49, 1.5, 1.51, 1.52, 1.53, 1.54, 1.55, 1.56, 1.57, 1.58, 1.59, 1.6, 1.61, 1.62,
                           1.63, 1.64, 1.65, 1.66, 1.67, 1.68, 1.69, 1.7, 1.71, 1.72, 1.73, 1.74, 1.75, 1.76, 1.77,
                           1.78, 1.79, 1.8, 1.81, 1.82, 1.83, 1.84, 1.85, 1.86, 1.87, 1.88, 1.89, 1.9, 1.91, 1.92, 1.93,
                           1.94, 1.95, 1.96, 1.97, 1.98, 1.99]),
                         ([1, 2, 10, 100],
                          [1.03, 1.06, 1.09, 1.12, 1.15, 1.18, 1.21, 1.24, 1.27, 1.3, 1.33, 1.36, 1.39, 1.42, 1.45,
                           1.48, 1.51, 1.54, 1.57, 1.6, 1.63, 1.66, 1.69, 1.72, 1.75, 1.78, 1.81, 1.84, 1.87, 1.9, 1.93,
                           1.96, 1.99, 2.16, 2.4, 2.64, 2.88, 3.12, 3.36, 3.6, 3.84, 4.08, 4.32, 4.56, 4.8, 5.04, 5.28,
                           5.52, 5.76, 6.0, 6.24, 6.48, 6.72, 6.96, 7.2, 7.44, 7.68, 7.92, 8.16, 8.4, 8.64, 8.88, 9.12,
                           9.36, 9.6, 9.84, 10.9, 13.6, 16.3, 19.0, 21.7, 24.4, 27.1, 29.8, 32.5, 35.2, 37.9, 40.6,
                           43.3, 46.0, 48.7, 51.4, 54.1, 56.8, 59.5, 62.2, 64.9, 67.6, 70.3, 73.0, 75.7, 78.4, 81.1,
                           83.8, 86.5, 89.2, 91.9, 94.6, 97.3]),
                         ((0.1, 0.2, 1.1, 2.3, 4.7),
                          [0.10400000000000002, 0.10800000000000001, 0.11200000000000002, 0.11600000000000002, 0.12,
                           0.12400000000000003, 0.128, 0.132, 0.136, 0.14, 0.14400000000000002, 0.14800000000000002,
                           0.15200000000000002, 0.15600000000000003, 0.16, 0.16400000000000003, 0.168, 0.172,
                           0.17600000000000002, 0.18, 0.18400000000000002, 0.188, 0.19200000000000003, 0.196, 0.2,
                           0.23600000000000002, 0.272, 0.30800000000000005, 0.3440000000000001, 0.38,
                           0.41600000000000004, 0.452, 0.48800000000000004, 0.524, 0.56, 0.5960000000000001, 0.632,
                           0.6680000000000001, 0.7040000000000001, 0.74, 0.7760000000000001, 0.8120000000000002, 0.848,
                           0.884, 0.92, 0.9560000000000001, 0.9920000000000002, 1.028, 1.064, 1.1, 1.1480000000000001,
                           1.196, 1.244, 1.2919999999999998, 1.34, 1.3880000000000001, 1.436, 1.484, 1.5319999999999998,
                           1.58, 1.6280000000000001, 1.676, 1.724, 1.7719999999999998, 1.82, 1.8679999999999999,
                           1.9159999999999997, 1.964, 2.012, 2.06, 2.1079999999999997, 2.1559999999999997, 2.204, 2.252,
                           2.3, 2.396, 2.492, 2.5879999999999996, 2.6839999999999997, 2.78, 2.8760000000000003, 2.972,
                           3.0679999999999996, 3.1639999999999997, 3.26, 3.3560000000000003, 3.4520000000000004, 3.548,
                           3.6439999999999997, 3.74, 3.8360000000000003, 3.9320000000000004, 4.0280000000000005, 4.124,
                           4.22, 4.316, 4.412000000000001, 4.508, 4.604])))
def test_get_percentiles(data, percentiles):
    assert get_percentiles(data) == percentiles


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
