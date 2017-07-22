#! /usr/bin/env python
from __future__ import absolute_import
'''support functions for jmclient tests.'''

import pytest
from jmclient import (select, select_gradual, select_greedy, select_greediest,
                      choose_orders, choose_sweep_orders, weighted_order_choose)
from jmclient.support import (calc_cj_fee, rand_exp_array, rand_pow_array,
                              rand_norm_array, rand_weighted_choice,
                              cheapest_order_choose)
from taker_test_data import t_orderbook
import copy

def test_utxo_selection():
    """Check that all the utxo selection algorithms work with a random
    variety of wallet contents.
    """
    unspent = [{'utxo':'a', 'value': 10000000},
               {'utxo':'b', 'value': 20000000},
               {'utxo':'c', 'value': 50000000},
               {'utxo':'d', 'value': 50000000}]
    for selector in [select, select_gradual, select_greedy, select_greediest]:
        for amt in [9999999, 10000000, 110000000, 19999999, 20000000,
                49999999, 50000000, 99999999, 100000000]:
            selector(unspent, amt)
        for amt in [1300000010, 2000000000]:
            with pytest.raises(Exception) as e_info:
                x = selector(unspent, amt)
                print(x)
            assert e_info.match("Not enough funds")

def test_random_funcs():
    x1 = rand_norm_array(5, 2, 10)
    assert len(x1) == 10
    for x in x1:
        assert x > -7 #6 sigma!
    x2 = rand_exp_array(100, 10)
    assert len(x2) == 10
    for x in x2:
        assert x > 0
    x3 = rand_pow_array(100, 10)
    assert len(x3) == 10
    for x in x3:
        assert x > 0
        assert x < 1
    x4 = rand_weighted_choice(5, [0.2, 0.1, 0.3, 0.15, 0.25])
    assert x4 in range(5)
    #test weighted choice fails with invalid inputs
    with pytest.raises(ValueError) as e_info:
        x = rand_weighted_choice(5, [0.2, 0.1, 0.3, 0.15, 0.26])
    assert e_info.match("Sum of probabilities")
    with pytest.raises(ValueError) as e_info:
        x = rand_weighted_choice(5, [0.25, 0.25, 0.25, 0.25])
    assert e_info.match("Need: 5 probabilities.")

def test_calc_cjfee():
    assert calc_cj_fee("swabsoffer", 3000, 200000000) == 3000
    assert calc_cj_fee("swreloffer", "0.01", 100000000) == 1000000
    with pytest.raises(RuntimeError) as e_info:
        calc_cj_fee("dummyoffer", 2, 3)

def test_choose_orders():
    orderbook = copy.deepcopy(t_orderbook)
    #test not enough liquidity
    orders_fees = choose_orders(orderbook, 10000000, 7, weighted_order_choose)
    assert orders_fees == (None, 0)
    orders_fees = choose_orders(orderbook, 10000000, 3, weighted_order_choose)
    #need variable fee sizes
    for i, o in enumerate(orderbook):
        o['cjfee'] = str(float(o['cjfee']) + 0.0001*i)
    #test phi not zero
    orders_fees = choose_orders(orderbook, 10000000, 3, weighted_order_choose)
    assert len(orders_fees[0]) == 3
    #test M < orderbook size for weighted
    orders_fees = choose_orders(orderbook, 10000000, 1, weighted_order_choose)
    assert len(orders_fees[0]) == 1
    #test the hated 'cheapest'
    orders_fees = choose_orders(orderbook, 100000000, 3, cheapest_order_choose)
    assert len(orders_fees[0]) == 3
    #test sweep
    result, cjamount, total_fee = choose_sweep_orders(orderbook, 50000000,
                                                      30000,
                                                      3,
                                                      weighted_order_choose,
                                                      None)
    assert cjamount >= 49800000
    assert cjamount <= 50000000
    assert total_fee >= 30000
    assert total_fee <= 100000
    assert len(result) == 3
    #test not enough liquidity
    result, cjamount, total_fee = choose_sweep_orders(orderbook, 50000000,
                                                      30000, 7,
                                                      weighted_order_choose,
                                                      None)
    assert result == None
    assert cjamount == 0
    assert total_fee == 0
    
    #here we doctor the orderbook; (a) include an absfee
    #(b) add an unrecognized ordertype
    #(c) put an order with wrong minsize
    orderbook.append({u'counterparty': u'fake',
                      u'ordertype': u'swabsoffer', u'oid': 0,
                      u'minsize': 7500000, u'txfee': 1000,
                      u'maxsize': 599972700, u'cjfee': 9000})
    result, cjamount, total_fee = choose_sweep_orders(orderbook, 50000000,
                                                30000, 7,
                                                cheapest_order_choose,
                                                None)
    assert total_fee > 0
    #(b)
    orderbook.append({u'counterparty': u'fake2',
                         u'ordertype': u'dummyoffer', u'oid': 0,
                         u'minsize': 7500000, u'txfee': 1000,
                         u'maxsize': 599972700, u'cjfee': 9000})
    with pytest.raises(RuntimeError) as e_info:
        result, cjamount, total_fee = choose_sweep_orders(orderbook,
                                                      50000000,
                                                      30000,
                                                      8,
                                                      weighted_order_choose,
                                                      None)
    #(c)
    #remove bad offer
    orderbook = orderbook[:-1]
    for i in range(7):
        orderbook[i]['minsize'] = 49999999
    result, cjamount, total_fee = choose_sweep_orders(orderbook,
                                                      50000000,
                                                      30000,
                                                      4,
                                                      weighted_order_choose,
                                                      None)
    assert result == None
    assert cjamount == 0
    assert total_fee == 0