import datetime

import jmbitcoin as btc
from jmclient import Maker, load_test_config, jm_single, WalletService, VolatileStorage, \
    SegwitWalletFidelityBonds, get_network
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

    utxos = { utxo: {'utxo': utxo, 'value': maker_utxos_value} for utxo in maker_utxos }

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
    for i in range(count):
        inp.append((b"\x00"*32, i))
    return inp


def create_tx_outputs(*addrs_amount):
    outp = []
    for addr, amount in addrs_amount:
        outp.append({'address': addr, 'value': amount})
    return outp


def address_p2pkh_generator():
    return get_address_generator(b'\x76\xa9\x14', b'\x88\xac')


def address_p2sh_generator():
    return get_address_generator(b'\xa9\x14', b'\x87', p2sh=True)


def get_address_generator(script_pre, script_post, p2sh=False):
    counter = 0
    while True:
        script = script_pre + struct.pack(b'=LQQ', 0, 0, counter) + script_post
        if p2sh:
            addr = btc.CCoinAddress.from_scriptPubKey(
                btc.CScript(script).to_p2sh_scriptPubKey())
        else:
            addr = btc.CCoinAddress.from_scriptPubKey(btc.CScript(script))
        yield str(addr), binascii.hexlify(script).decode('ascii')
        counter += 1


def create_tx_and_offerlist(cj_addr, cj_change_addr, other_output_addrs,
                            offertype='sw0reloffer'):
    assert len(other_output_addrs) % 2 == 0, "bug in test"

    cj_value = 100000000
    maker_total_value = cj_value*3

    inputs = create_tx_inputs(3)
    outputs = create_tx_outputs(
        (cj_addr, cj_value),
        (cj_change_addr, maker_total_value - cj_value),  # cjfee=0, txfee=0
        *((addr, cj_value + (i%2)*(50000000+i)) \
            for i, addr in enumerate(other_output_addrs))
    )

    maker_utxos = [inputs[0]]

    tx = btc.mktx(inputs, outputs)
    offerlist = construct_tx_offerlist(cj_addr, cj_change_addr, maker_utxos,
                                       maker_total_value, cj_value, offertype)

    return tx, offerlist


def test_verify_unsigned_tx_sw_valid(setup_env_nodeps):
    jm_single().config.set("POLICY", "segwit", "true")

    p2sh_gen = address_p2sh_generator()
    p2pkh_gen = address_p2pkh_generator()

    wallet = DummyWallet()
    maker = OfflineMaker(WalletService(wallet))

    cj_addr, cj_script = next(p2sh_gen)
    changeaddr, cj_change_script = next(p2sh_gen)

    # test standard cj
    tx, offerlist = create_tx_and_offerlist(cj_addr, changeaddr,
        [next(p2sh_gen)[0] for s in range(4)])

    assert maker.verify_unsigned_tx(tx, offerlist) == (True, None), "standard sw cj"

    # test cj with mixed outputs
    tx, offerlist = create_tx_and_offerlist(cj_addr, changeaddr,
        list(chain((next(p2sh_gen)[0] for s in range(3)),
                   (next(p2pkh_gen)[0] for s in range(1)))))

    assert maker.verify_unsigned_tx(tx, offerlist) == (True, None), "sw cj with p2pkh output"

    # test cj with only p2pkh outputs
    tx, offerlist = create_tx_and_offerlist(cj_addr, changeaddr,
        [next(p2pkh_gen)[0] for s in range(4)])

    assert maker.verify_unsigned_tx(tx, offerlist) == (True, None), "sw cj with only p2pkh outputs"


def test_verify_unsigned_tx_nonsw_valid(setup_env_nodeps):
    jm_single().config.set("POLICY", "segwit", "false")

    p2sh_gen = address_p2sh_generator()
    p2pkh_gen = address_p2pkh_generator()

    wallet = DummyWallet()
    maker = OfflineMaker(WalletService(wallet))

    cj_addr, cj_script = next(p2pkh_gen)
    changeaddr, cj_change_script = next(p2pkh_gen)

    # test standard cj
    tx, offerlist = create_tx_and_offerlist(cj_addr, changeaddr,
        [next(p2pkh_gen)[0] for s in range(4)], offertype='reloffer')

    assert maker.verify_unsigned_tx(tx, offerlist) == (True, None), "standard nonsw cj"

    # test cj with mixed outputs
    tx, offerlist = create_tx_and_offerlist(cj_addr, changeaddr,
        list(chain((next(p2sh_gen)[0] for s in range(1)),
                   (next(p2pkh_gen)[0] for s in range(3)))), offertype='reloffer')

    assert maker.verify_unsigned_tx(tx, offerlist) == (True, None), "nonsw cj with p2sh output"

    # test cj with only p2sh outputs
    tx, offerlist = create_tx_and_offerlist(cj_addr, changeaddr,
        [next(p2sh_gen)[0] for s in range(4)], offertype='reloffer')

    assert maker.verify_unsigned_tx(tx, offerlist) == (True, None), "nonsw cj with only p2sh outputs"


def test_freeze_timelocked_utxos(setup_env_nodeps):
    storage = VolatileStorage()
    SegwitWalletFidelityBonds.initialize(storage, get_network())
    wallet = SegwitWalletFidelityBonds(storage)
    ts = wallet.datetime_to_time_number(
        datetime.datetime.strptime("2021-07", "%Y-%m"))
    tl_path = wallet.get_path(
        wallet.FIDELITY_BOND_MIXDEPTH, wallet.BIP32_TIMELOCK_ID, ts)
    tl_script = wallet.get_script_from_path(tl_path)
    utxo = (b'a'*32, 0)
    wallet.add_utxo(utxo[0], utxo[1], tl_script, 100000000)
    assert not wallet._utxos.is_disabled(*utxo)

    maker = OfflineMaker(WalletService(wallet))
    maker.freeze_timelocked_utxos()
    assert wallet._utxos.is_disabled(*utxo)


@pytest.fixture
def setup_env_nodeps(monkeypatch):
    monkeypatch.setattr(jmclient.configure, 'get_blockchain_interface_instance',
                        lambda x: DummyBlockchainInterface())
    btc.select_chain_params("bitcoin/regtest")
    load_test_config()
