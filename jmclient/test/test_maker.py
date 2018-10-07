#!/usr/bin/env python

from __future__ import print_function

from jmclient import Maker, btc, get_p2sh_vbyte, get_p2pk_vbyte, \
    load_program_config, jm_single
import jmclient
from commontest import DummyBlockchainInterface
from test_taker import DummyWallet

import struct
import binascii
from itertools import chain
import pytest


class OfflineMaker(Maker):
    def try_to_create_my_orders(self):
        self.sync_wait_loop.stop()


def construct_tx_offerlist(cjaddr, changeaddr, maker_utxos, maker_utxos_value,
                           cj_value, ordertype):
    offer = {
        'cjfee': '0',
        'maxsize': cj_value*3,
        'minsize': 7500000,
        'oid': 0,
        'ordertype': ordertype,
        'txfee': 0
    }

    utxos = { utxo['outpoint']['hash'] + ':' + str(utxo['outpoint']['index']):
                {'utxo': utxo, 'value': maker_utxos_value} for utxo in maker_utxos }

    offerlist = {
        'utxos': utxos,
        'cjaddr': cjaddr,
        'changeaddr': changeaddr,
        'amount': cj_value,
        'offer': offer
    }

    return offerlist


def create_tx_inputs(count=1):
    inp = []
    for i in xrange(count):
        inp.append({'outpoint': {'hash': '0'*64, 'index': i},
                    'script': '',
                    'sequence': 4294967295})
    return inp


def create_tx_outputs(*scripts_amount):
    outp = []
    for script, amount in scripts_amount:
        outp.append({'script': script, 'value': amount})
    return outp


def address_p2pkh_generator():
    return get_address_generator(b'\x76\xa9\x14', b'\x88\xac', get_p2pk_vbyte())


def address_p2sh_generator():
    return get_address_generator(b'\xa9\x14', b'\x87', get_p2sh_vbyte())


def get_address_generator(script_pre, script_post, vbyte):
    counter = 0
    while True:
        script = script_pre + struct.pack('=LQQ', 0, 0, counter) + script_post
        addr = btc.script_to_address(script, vbyte)
        yield addr, binascii.hexlify(script)
        counter += 1


def create_tx_and_offerlist(cj_addr, cj_change_addr, other_output_scripts,
                            cj_script=None, cj_change_script=None, offertype='swreloffer'):
    assert len(other_output_scripts) % 2 == 0, "bug in test"

    cj_value = 100000000
    maker_total_value = cj_value*3

    if cj_script is None:
        cj_script = btc.address_to_script(cj_addr)
    if cj_change_script is None:
        cj_change_script = btc.address_to_script(cj_change_addr)

    inputs = create_tx_inputs(3)
    outputs = create_tx_outputs(
        (cj_script, cj_value),
        (cj_change_script, maker_total_value - cj_value),  # cjfee=0, txfee=0
        *((script, cj_value + (i%2)*(50000000+i)) \
            for i, script in enumerate(other_output_scripts))
    )

    maker_utxos = [inputs[0]]

    tx = btc.deserialize(btc.mktx(inputs, outputs))
    offerlist = construct_tx_offerlist(cj_addr, cj_change_addr, maker_utxos,
                                       maker_total_value, cj_value, offertype)

    return tx, offerlist


def test_verify_unsigned_tx_sw_valid(setup_env_nodeps):
    jm_single().config.set("POLICY", "segwit", "true")

    p2sh_gen = address_p2sh_generator()
    p2pkh_gen = address_p2pkh_generator()

    wallet = DummyWallet()
    maker = OfflineMaker(wallet)

    cj_addr, cj_script = next(p2sh_gen)
    changeaddr, cj_change_script = next(p2sh_gen)

    # test standard cj
    tx, offerlist = create_tx_and_offerlist(cj_addr, changeaddr,
        [next(p2sh_gen)[1] for s in xrange(4)], cj_script, cj_change_script)

    assert maker.verify_unsigned_tx(tx, offerlist) == (True, None), "standard sw cj"

    # test cj with mixed outputs
    tx, offerlist = create_tx_and_offerlist(cj_addr, changeaddr,
        list(chain((next(p2sh_gen)[1] for s in xrange(3)),
                   (next(p2pkh_gen)[1] for s in xrange(1)))),
        cj_script, cj_change_script)

    assert maker.verify_unsigned_tx(tx, offerlist) == (True, None), "sw cj with p2pkh output"

    # test cj with only p2pkh outputs
    tx, offerlist = create_tx_and_offerlist(cj_addr, changeaddr,
        [next(p2pkh_gen)[1] for s in xrange(4)], cj_script, cj_change_script)

    assert maker.verify_unsigned_tx(tx, offerlist) == (True, None), "sw cj with only p2pkh outputs"


def test_verify_unsigned_tx_nonsw_valid(setup_env_nodeps):
    jm_single().config.set("POLICY", "segwit", "false")

    p2sh_gen = address_p2sh_generator()
    p2pkh_gen = address_p2pkh_generator()

    wallet = DummyWallet()
    maker = OfflineMaker(wallet)

    cj_addr, cj_script = next(p2pkh_gen)
    changeaddr, cj_change_script = next(p2pkh_gen)

    # test standard cj
    tx, offerlist = create_tx_and_offerlist(cj_addr, changeaddr,
        [next(p2pkh_gen)[1] for s in xrange(4)], cj_script, cj_change_script, 'reloffer')

    assert maker.verify_unsigned_tx(tx, offerlist) == (True, None), "standard nonsw cj"

    # test cj with mixed outputs
    tx, offerlist = create_tx_and_offerlist(cj_addr, changeaddr,
        list(chain((next(p2sh_gen)[1] for s in xrange(1)),
                   (next(p2pkh_gen)[1] for s in xrange(3)))),
        cj_script, cj_change_script, 'reloffer')

    assert maker.verify_unsigned_tx(tx, offerlist) == (True, None), "nonsw cj with p2sh output"

    # test cj with only p2sh outputs
    tx, offerlist = create_tx_and_offerlist(cj_addr, changeaddr,
        [next(p2sh_gen)[1] for s in xrange(4)], cj_script, cj_change_script, 'reloffer')

    assert maker.verify_unsigned_tx(tx, offerlist) == (True, None), "nonsw cj with only p2sh outputs"


@pytest.fixture
def setup_env_nodeps(monkeypatch):
    monkeypatch.setattr(jmclient.configure, 'get_blockchain_interface_instance',
                        lambda x: DummyBlockchainInterface())
    load_program_config()
