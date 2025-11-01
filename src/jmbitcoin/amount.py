import re
from bitcointx.core import coins_to_satoshi, satoshi_to_coins
from decimal import Decimal
from typing import Any, Tuple, Union


def bitcoin_unit_to_power(btc_unit: str) -> int:
    # https://en.bitcoin.it/wiki/Units
    unit_to_power = {
        'BTC': 8,
        'mBTC': 5,  # milli-bitoin, 0.001 BTC
        'μBTC': 2,  # micro-bitcoin (bit), 0.000001 BTC
        'bit': 2,
        'satoshi': 0,
        'sat': 0,
    }
    if btc_unit not in unit_to_power:
        raise ValueError(f"Invalid bitcoin unit: {btc_unit}")
    return unit_to_power[btc_unit]


def btc_to_sat(btc: Union[int, str, Tuple, float, Decimal]) -> int:
    return coins_to_satoshi(Decimal(btc))


def sat_to_unit_power(sat: int, power: int) -> Decimal:
    return Decimal(f"%.{power}f" % float(Decimal(sat) / Decimal(10**power)))


def sat_to_unit(sat: int, btc_unit: str) -> Decimal:
    return sat_to_unit_power(sat, bitcoin_unit_to_power(btc_unit))


def sat_to_btc(sat: int) -> Decimal:
    return sat_to_unit(sat, 'BTC')


# 1             = 0.00000001 BTC = 1sat
# 1sat          = 0.00000001 BTC = 1sat
# 1.123sat      = 0.00000001 BTC = 1sat
# 0.00000001    = 0.00000001 BTC = 1sat
# 0.00000001btc = 0.00000001 BTC = 1sat
# 1.00000000    = 1.00000000 BTC = 100000000sat
# 1.12300000sat = 0.00000001 BTC = 1sat
# 1btc          = 1.00000000 BTC = 10000000sat


def amount_to_sat(amount_str: str) -> int:
    amount_str = str(amount_str).strip()
    if (
        re.compile(r"^[0-9]{1,8}(\.)?([0-9]{1,8})?(btc|sat)?$").match(
            amount_str.lower()
        )
        is None
    ):
        raise ValueError("Invalid BTC amount string " + amount_str)
    if amount_str.lower().endswith("btc"):
        return int(btc_to_sat(amount_str[:-3]))
    elif amount_str.lower().endswith("sat"):
        return int(Decimal(amount_str[:-3]))
    elif "." in amount_str:
        return int(btc_to_sat(amount_str))
    else:
        return int(Decimal(amount_str))


def amount_to_btc(amount_str: str) -> Decimal:
    return amount_to_sat(amount_str) / Decimal('1e8')


def amount_to_sat_str(amount_str: str) -> str:
    return str(amount_to_sat(amount_str)) + " sat"


def amount_to_btc_str(amount_str: str) -> str:
    return '%.8f' % amount_to_btc(amount_str) + " BTC"


def amount_to_str(amount_str: str) -> str:
    return (
        amount_to_btc_str(amount_str)
        + " ("
        + amount_to_sat_str(amount_str)
        + ")"
    )


def sat_to_str(sat: int) -> str:
    return '%.8f' % satoshi_to_coins(sat)


def sat_to_str_p(sat: int) -> str:
    return '%+.8f' % satoshi_to_coins(sat, check_range=False)


def fee_per_kb_to_str(feerate: Any) -> str:
    return (
        str(int(feerate))
        + " sat/kvB ("
        + '%.1f' % (int(feerate / 100) / 10)
        + " sat/vB)"
    )
