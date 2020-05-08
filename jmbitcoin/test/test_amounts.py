import jmbitcoin as btc
import pytest
from decimal import Decimal


def test_btc_to_sat():
    assert(btc.btc_to_sat(Decimal("0.00000001")) == 1)
    assert(btc.btc_to_sat(Decimal("1.00000000")) == 100000000)


def test_sat_to_btc():
    assert(btc.sat_to_btc(1) == Decimal("0.00000001"))
    assert(btc.sat_to_btc(100000000) == Decimal("1.00000000"))


def test_amount_to_sat():
    assert(btc.amount_to_sat("1") == 1)
    assert(btc.amount_to_sat("1sat") == 1)
    assert(btc.amount_to_sat("1.123sat") == 1)
    assert(btc.amount_to_sat("0.00000001") == 1)
    assert(btc.amount_to_sat("0.00000001btc") == 1)
    assert(btc.amount_to_sat("0.00000001BTC") == 1)
    assert(btc.amount_to_sat("1.00000000") == 100000000)
    assert(btc.amount_to_sat("1.12300000sat") == 1)
    assert(btc.amount_to_sat("1btc") == 100000000)
    assert(btc.amount_to_sat("1BTC") == 100000000)


def test_amount_to_btc():
    assert(btc.amount_to_btc("1") == Decimal("0.00000001"))
    assert(btc.amount_to_btc("1sat") == Decimal("0.00000001"))
    assert(btc.amount_to_btc("1.123sat") == Decimal("0.00000001"))
    assert(btc.amount_to_btc("0.00000001") == Decimal("0.00000001"))
    assert(btc.amount_to_btc("0.00000001btc") == Decimal("0.00000001"))
    assert(btc.amount_to_btc("0.00000001BTC") == Decimal("0.00000001"))
    assert(btc.amount_to_btc("1.00000000") == 1)
    assert(btc.amount_to_btc("1.12300000sat") == Decimal("0.00000001"))
    assert(btc.amount_to_btc("1btc") == 1)
    assert(btc.amount_to_btc("1BTC") == 1)


def test_amount_to_sat_str():
    assert(btc.amount_to_sat_str("1") == "1 sat")
    assert(btc.amount_to_sat_str("1sat") == "1 sat")
    assert(btc.amount_to_sat_str("1.123sat") == "1 sat")
    assert(btc.amount_to_sat_str("0.00000001") == "1 sat")
    assert(btc.amount_to_sat_str("0.00000001btc") == "1 sat")
    assert(btc.amount_to_sat_str("0.00000001BTC") == "1 sat")
    assert(btc.amount_to_sat_str("1.00000000") == "100000000 sat")
    assert(btc.amount_to_sat_str("1.12300000sat") == "1 sat")
    assert(btc.amount_to_sat_str("1btc") == "100000000 sat")
    assert(btc.amount_to_sat_str("1BTC") == "100000000 sat")


def test_amount_to_btc_str():
    assert(btc.amount_to_btc_str("1") == "0.00000001 BTC")
    assert(btc.amount_to_btc_str("1sat") == "0.00000001 BTC")
    assert(btc.amount_to_btc_str("1.123sat") == "0.00000001 BTC")
    assert(btc.amount_to_btc_str("0.00000001") == "0.00000001 BTC")
    assert(btc.amount_to_btc_str("0.00000001btc") == "0.00000001 BTC")
    assert(btc.amount_to_btc_str("0.00000001BTC") == "0.00000001 BTC")
    assert(btc.amount_to_btc_str("1.00000000") == "1.00000000 BTC")
    assert(btc.amount_to_btc_str("1.12300000sat") == "0.00000001 BTC")
    assert(btc.amount_to_btc_str("1btc") == "1.00000000 BTC")
    assert(btc.amount_to_btc_str("1BTC") == "1.00000000 BTC")


def test_amount_to_str():
    assert(btc.amount_to_str("1") == "0.00000001 BTC (1 sat)")
    assert(btc.amount_to_str("1sat") == "0.00000001 BTC (1 sat)")
    assert(btc.amount_to_str("1.123sat") == "0.00000001 BTC (1 sat)")
    assert(btc.amount_to_str("0.00000001") == "0.00000001 BTC (1 sat)")
    assert(btc.amount_to_str("0.00000001btc") == "0.00000001 BTC (1 sat)")
    assert(btc.amount_to_str("0.00000001BTC") == "0.00000001 BTC (1 sat)")
    assert(btc.amount_to_str("1.00000000") == "1.00000000 BTC (100000000 sat)")
    assert(btc.amount_to_str("1.12300000sat") == "0.00000001 BTC (1 sat)")
    assert(btc.amount_to_str("1btc") == "1.00000000 BTC (100000000 sat)")
    assert(btc.amount_to_str("1BTC") == "1.00000000 BTC (100000000 sat)")


def test_sat_to_str():
    assert(btc.sat_to_str(1) == "0.00000001")
    assert(btc.sat_to_str(100000000) == "1.00000000")


def test_sat_to_str_p():
    assert(btc.sat_to_str_p(1) == "+0.00000001")
    assert(btc.sat_to_str_p(-1) == "-0.00000001")
    assert(btc.sat_to_str_p(100000000) == "+1.00000000")
    assert(btc.sat_to_str_p(-100000000) == "-1.00000000")


def test_fee_per_kb_to_str():
    assert(btc.fee_per_kb_to_str(1000) == "1000 sat/vkB (1.0 sat/vB)")
