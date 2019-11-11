from decimal import Decimal

def btc_to_sat(btc):
    return int(Decimal(btc) * Decimal('1e8'))

def sat_to_btc(sat):
    return Decimal(sat) / Decimal('1e8')

# 1             = 0.00000001 BTC = 1sat
# 1sat          = 0.00000001 BTC = 1sat
# 1.123sat      = 0.00000001 BTC = 1sat
# 0.00000001    = 0.00000001 BTC = 1sat
# 0.00000001btc = 0.00000001 BTC = 1sat
# 1.00000000    = 1.00000000 BTC = 100000000sat
# 1.12300000sat = 0.00000001 BTC = 1sat
# 1btc          = 1.00000000 BTC = 10000000sat

def amount_to_sat(amount_str):
    amount_str = str(amount_str)
    if amount_str.lower().endswith("btc"):
        return int(btc_to_sat(amount_str[:-3]))
    elif amount_str.lower().endswith("sat"):
        return int(Decimal(amount_str[:-3]))
    elif "." in amount_str:
        return int(btc_to_sat(amount_str))
    else:
        return int(Decimal(amount_str))

def amount_to_btc(amount_str):
    return amount_to_sat(amount_str) / Decimal('1e8')

def amount_to_sat_str(amount_str):
    return str(amount_to_sat(amount_str)) + " sat"

def amount_to_btc_str(amount_str):
    return str(amount_to_btc(amount_str)) + " BTC"

def amount_to_str(amount_str):
    return amount_to_btc_str(amount_str) + " (" + amount_to_sat_str(amount_str) + ")"

def sat_to_str(sat):
    return '%.8f' % sat_to_btc(sat)

def sat_to_str_p(sat):
    return '%+.8f' % sat_to_btc(sat)

