#!/usr/bin/env python
from __future__ import print_function
from commontest import DummyBlockchainInterface
import jmbitcoin as bitcoin
import binascii
import os
import copy
import shutil
import pytest
import json
from base64 import b64encode
from jmclient import (load_program_config, jm_single, set_commitment_file,
                      get_commitment_file, AbstractWallet, Taker)
from taker_test_data import (t_utxos_by_mixdepth, t_selected_utxos, t_orderbook,
                             t_maker_response, t_chosen_orders, t_dummy_ext)

class DummyWallet(AbstractWallet):

    def __init__(self):
        super(DummyWallet, self).__init__()
        self.max_mix_depth = 5
        self.inject_addr_get_failure = False

    def get_utxos_by_mixdepth(self):
        return t_utxos_by_mixdepth

    def select_utxos(self, mixdepth, amount):
        if amount > self.get_balance_by_mixdepth()[mixdepth]:
            raise Exception("Not enough funds")
        return self.get_utxos_by_mixdepth()[mixdepth]

    def get_internal_addr(self, mixing_depth):
        if self.inject_addr_get_failure:
            raise Exception("address get failure")
        return "mxeLuX8PP7qLkcM8uarHmdZyvP1b5e1Ynf"

    def sign_tx(self, tx, addrs):
        print("Pretending to sign on addresses: " + str(addrs))
        return tx

    def get_key_from_addr(self, addr):
        """usable addresses: privkey all 1s, 2s, 3s, ... :"""
        privs = [x*32 + "\x01" for x in [chr(y) for y in range(1,6)]]
        addrs = {}
        """
        mrcNu71ztWjAQA6ww9kHiW3zBWSQidHXTQ
        n31WD8pkfAjg2APV78GnbDTdZb1QonBi5D
        mmVEKH61BZbLbnVEmk9VmojreB4G4PmBPd
        msxyyydNXTiBmt3SushXbH5Qh2ukBAThk3
        musGZczug3BAbqobmYherywCwL9REgNaNm
        """
        for p in privs:
            addrs[p] = bitcoin.privkey_to_address(p, False, magicbyte=0x6f)
        for p, a in addrs.iteritems():
            if a == addr:
                return binascii.hexlify(p)
        raise ValueError("No such keypair")

def dummy_order_chooser():
    return t_chosen_orders

def taker_finished(res, fromtx=False):
    print("called taker finished callback")

def dummy_filter_orderbook(orders_fees, cjamount):
    print("calling dummy filter orderbook")
    return True

def get_taker(schedule=None, schedule_len=0, sign_method=None, on_finished=None,
              filter_orders=None):
    if not schedule:
        schedule = ['a']*schedule_len #note, for taker.initalize() this will result in junk
    print("Using schedule: " + str(schedule))
    on_finished_callback = on_finished if on_finished else taker_finished
    filter_orders_callback = filter_orders if filter_orders else dummy_filter_orderbook
    return Taker(DummyWallet(), schedule,
                  callbacks=[filter_orders_callback, None, on_finished_callback],
                  sign_method=sign_method)

def test_filter_rejection(createcmtdata):
    def filter_orders_reject(orders_feesl, cjamount):
        print("calling filter orders rejection")
        return False
    taker = get_taker(filter_orders=filter_orders_reject)
    taker.schedule = [(0, 20000000, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw")]
    res = taker.initialize(t_orderbook)
    assert not res[0]
    taker = get_taker(filter_orders=filter_orders_reject)
    taker.schedule = [(0, 0, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw")]
    res = taker.initialize(t_orderbook)
    assert not res[0]

@pytest.mark.parametrize(
    "failquery, external",
    [
        (False, False),
        (True, False),
        (False, True),
    ])
def test_make_commitment(createcmtdata, failquery, external):
    def clean_up():
        jm_single().config.set("POLICY", "taker_utxo_age", old_taker_utxo_age)
        jm_single().config.set("POLICY", "taker_utxo_amtpercent", old_taker_utxo_amtpercent)
        set_commitment_file(old_commitment_file)
        jm_single().bc_interface.setQUSFail(False)
        os.remove('dummyext')
    old_commitment_file = get_commitment_file()
    with open('dummyext', 'wb') as f:
        f.write(json.dumps(t_dummy_ext, indent=4))
    if external:
        set_commitment_file('dummyext')
    old_taker_utxo_age = jm_single().config.get("POLICY", "taker_utxo_age")
    old_taker_utxo_amtpercent = jm_single().config.get("POLICY", "taker_utxo_amtpercent")
    jm_single().config.set("POLICY", "taker_utxo_age", "5")
    jm_single().config.set("POLICY", "taker_utxo_amtpercent", "20")
    mixdepth = 0
    amount = 110000000
    taker = get_taker([(mixdepth, amount, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw")])
    taker.wallet.unspent = {'f34b635ed8891f16c4ec5b8236ae86164783903e8e8bb47fa9ef2ca31f3c2d7a:0':
                            {'address': u'n31WD8pkfAjg2APV78GnbDTdZb1QonBi5D',
                             'value': 10000000},
                            'f780d6e5e381bff01a3519997bb4fcba002493103a198fde334fd264f9835d75:1':
                            {'address': u'mmVEKH61BZbLbnVEmk9VmojreB4G4PmBPd',
                             'value': 20000000},
                            'fe574db96a4d43a99786b3ea653cda9e4388f377848f489332577e018380cff1:0':
                            {'address': u'msxyyydNXTiBmt3SushXbH5Qh2ukBAThk3',
                             'value': 500000000},
                            'fd9711a2ef340750db21efb761f5f7d665d94b312332dc354e252c77e9c48349:0':
                            {'address': u'musGZczug3BAbqobmYherywCwL9REgNaNm',
                             'value': 500000000}}
    taker.cjamount = amount
    taker.input_utxos = {'f34b635ed8891f16c4ec5b8236ae86164783903e8e8bb47fa9ef2ca31f3c2d7a:0':
                            {'address': u'n31WD8pkfAjg2APV78GnbDTdZb1QonBi5D',
                             'value': 10000000}}
    if failquery:
        jm_single().bc_interface.setQUSFail(True)
    taker.make_commitment()
    clean_up()
    
def test_not_found_maker_utxos(createcmtdata):
    taker = get_taker([(0, 20000000, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw")])
    orderbook = copy.deepcopy(t_orderbook)
    res = taker.initialize(orderbook)
    taker.orderbook = copy.deepcopy(t_chosen_orders) #total_cjfee unaffected, all same
    maker_response = copy.deepcopy(t_maker_response)
    jm_single().bc_interface.setQUSFail(True)
    res = taker.receive_utxos(maker_response)
    assert not res[0]
    assert res[1] == "Not enough counterparties responded to fill, giving up"
    jm_single().bc_interface.setQUSFail(False)

def test_auth_pub_not_found(createcmtdata):
    taker = get_taker([(0, 20000000, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw")])
    orderbook = copy.deepcopy(t_orderbook)
    res = taker.initialize(orderbook)
    taker.orderbook = copy.deepcopy(t_chosen_orders) #total_cjfee unaffected, all same
    maker_response = copy.deepcopy(t_maker_response)
    utxos = ["03243f4a659e278a1333f8308f6aaf32db4692ee7df0340202750fd6c09150f6:1",
             "498faa8b22534f3b443c6b0ce202f31e12f21668b4f0c7a005146808f250d4c3:0",
             "3f3ea820d706e08ad8dc1d2c392c98facb1b067ae4c671043ae9461057bd2a3c:1"]
    fake_query_results = [{'value': 200000000,
                            'address': "blah",
                            'utxo': utxos[i],
                            'confirms': 20} for i in range(3)]
    jm_single().bc_interface.insert_fake_query_results(fake_query_results)
    res = taker.receive_utxos(maker_response)
    assert not res[0]
    assert res[1] == "Not enough counterparties responded to fill, giving up"
    jm_single().bc_interface.insert_fake_query_results(None)

@pytest.mark.parametrize(
    "schedule, highfee, toomuchcoins, minmakers, notauthed, ignored, nocommit",
    [
        ([(0, 20000000, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw")], False, False,
         2, False, None, None),
        ([(0, 0, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw")], False, False,
         2, False, None, None), #sweep
        #edge case triggers that don't fail
        ([(0, 0, 4, "mxeLuX8PP7qLkcM8uarHmdZyvP1b5e1Ynf")], False, False,
         2, False, None, None), #sweep rounding error case
        ([(0, 199850001, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw")], False, False,
         2, False, None, None), #trigger sub dust change for taker
        #edge case triggers that do fail
        ([(0, 199850000, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw")], False, False,
         2, False, None, None), #trigger negative change        
        ([(0, 199599800, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw")], False, False,
         2, False, None, None), #trigger sub dust change for maker
        ([(0, 20000000, 3, "INTERNAL")], True, False,
         2, False, None, None), #test high fee
        ([(0, 20000000, 3, "INTERNAL")], False, False,
         7, False, None, None), #test not enough cp
        ([(0, 80000000, 3, "INTERNAL")], False, False,
         2, False, None, "30000"), #test failed commit       
        ([(0, 20000000, 3, "INTERNAL")], False, False,
         2, True, None, None), #test unauthed response
        ([(0, 5000000000, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw")], False, True,
         2, False, None, None), #test too much coins
        ([(0, 0, 5, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw")], False, False,
         2, False, ["J559UPUSLLjHJpaB", "J55z23xdjxJjC7er"], None), #test inadequate for sweep
    ])
def test_taker_init(createcmtdata, schedule, highfee, toomuchcoins, minmakers,
                    notauthed, ignored, nocommit):
    #these tests do not trigger utxo_retries
    oldtakerutxoretries = jm_single().config.get("POLICY", "taker_utxo_retries")
    oldtakerutxoamtpercent = jm_single().config.get("POLICY", "taker_utxo_amtpercent")
    jm_single().config.set("POLICY", "taker_utxo_retries", "20")
    def clean_up():
        jm_single().config.set("POLICY", "minimum_makers", oldminmakers)
        jm_single().config.set("POLICY", "taker_utxo_retries", oldtakerutxoretries)
        jm_single().config.set("POLICY", "taker_utxo_amtpercent", oldtakerutxoamtpercent)
    oldminmakers = jm_single().config.get("POLICY", "minimum_makers")
    jm_single().config.set("POLICY", "minimum_makers", str(minmakers))
    taker = get_taker(schedule)
    orderbook = copy.deepcopy(t_orderbook) 
    if highfee:
        for o in orderbook:
            #trigger high-fee warning; but reset in next step
            o['cjfee'] = '1.0'
    if ignored:
        taker.ignored_makers = ignored
    if nocommit:
        jm_single().config.set("POLICY", "taker_utxo_amtpercent", nocommit)
    res = taker.initialize(orderbook)
    if toomuchcoins or ignored:
        assert not res[0]
        return clean_up()
    if nocommit:
        print(str(res))
        assert not res[0]
        return clean_up()
    taker.orderbook = copy.deepcopy(t_chosen_orders) #total_cjfee unaffected, all same
    maker_response = copy.deepcopy(t_maker_response)
    if notauthed:
        #Doctor one of the maker response data fields
        maker_response["J559UPUSLLjHJpaB"][1] = "xx" #the auth pub
    if schedule[0][1] == 199850000:
        #triggers negative change
        #makers offer 3000 txfee; we estimate ~ 147*10 + 2*34 + 10=1548 bytes
        #times 30k = 46440, so we pay 43440, plus maker fees = 3*0.0002*200000000
        #roughly, gives required selected = amt + 163k, hence the above =
        #2btc - 150k sats = 199850000 (tweaked because of aggressive coin selection)
        #simulate the effect of a maker giving us a lot more utxos
        taker.utxos["dummy_for_negative_change"] = ["a", "b", "c", "d", "e"]
        with pytest.raises(ValueError) as e_info:
            res = taker.receive_utxos(maker_response)
        return clean_up()
    if schedule[0][1] == 199850001:
        #our own change is greater than zero but less than dust
        #use the same edge case as for negative change, don't add dummy inputs
        #(because we need tx creation to complete), but trigger case by
        #bumping dust threshold
        jm_single().BITCOIN_DUST_THRESHOLD = 10000
        res = taker.receive_utxos(maker_response)
        #should have succeeded to build tx
        assert res[0]
        #change should be none
        assert not taker.my_change_addr
        return clean_up()        
    if schedule[0][1] == 199599800:
        #need to force negative fees to make this feasible
        for k, v in taker.orderbook.iteritems():
            v['cjfee'] = '-0.002'
        #            change_amount = (total_input - self.cjamount -
        #                     self.orderbook[nick]['txfee'] + real_cjfee)
        #suppose change amount is 1000 (sub dust), then solve for x;
        #given that real_cjfee = -0.002*x
        #change = 200000000 - x - 1000 - 0.002*x
        #x*1.002 = 1999999000; x = 199599800
        res = taker.receive_utxos(maker_response)
        assert not res[0]
        assert res[1] == "Not enough counterparties responded to fill, giving up"
        return clean_up()
    if schedule[0][3] == "mxeLuX8PP7qLkcM8uarHmdZyvP1b5e1Ynf":
        #to trigger rounding error for sweep (change non-zero),
        #modify the total_input via the values in self.input_utxos;
        #the amount to trigger a 2 satoshi change is found by trial-error.
        #TODO note this test is not adequate, because the code is not;
        #the code does not *DO* anything if a condition is unexpected.
        taker.input_utxos = copy.deepcopy(t_utxos_by_mixdepth)[0]
        for k,v in taker.input_utxos.iteritems():
            v["value"] = int(0.999805228 * v["value"])
        res = taker.receive_utxos(maker_response)
        assert res[0]
        return clean_up()

    res = taker.receive_utxos(maker_response)
    if minmakers != 2:
        assert not res[0]
        assert res[1] == "Not enough counterparties responded to fill, giving up"
        return clean_up()
        
    assert res[0]
    #re-calling will trigger "finished" code, since schedule is "complete".
    res = taker.initialize(orderbook)
    assert not res[0]

    #some exception cases: no coinjoin address, no change address:
    #donations not yet implemented:
    taker.my_cj_addr = None
    with pytest.raises(NotImplementedError) as e_info:
        taker.prepare_my_bitcoin_data()
    with pytest.raises(NotImplementedError) as e_info:
        taker.sign_tx("a", "b", "c")
    with pytest.raises(NotImplementedError) as e_info:
        a = taker.coinjoin_address()
    taker.wallet.inject_addr_get_failure = True
    taker.my_cj_addr = "dummy"
    assert not taker.prepare_my_bitcoin_data()
    #clean up
    return clean_up()

@pytest.mark.parametrize(
    "schedule_len",
    [
        (7),
    ])
def test_unconfirm_confirm(schedule_len):
    """These functions are: do-nothing by default (unconfirm, for Taker),
    and merely update schedule index for confirm (useful for schedules/tumbles).
    This tests that the on_finished callback correctly reports the fromtx
    variable as "False" once the schedule is complete.
    """
    test_unconfirm_confirm.txflag = True
    def finished_for_confirms(res, fromtx=False):
        assert res #confirmed should always send true
        test_unconfirm_confirm.txflag = fromtx

    taker = get_taker(schedule_len=schedule_len, on_finished=finished_for_confirms)
    taker.unconfirm_callback("a", "b")
    for i in range(schedule_len-1):
        taker.schedule_index += 1
        fromtx = taker.confirm_callback("a", "b", 1)
        assert test_unconfirm_confirm.txflag
    taker.schedule_index += 1
    fromtx = taker.confirm_callback("a", "b", 1)
    assert not test_unconfirm_confirm.txflag
    
@pytest.mark.parametrize(
    "dummyaddr, signmethod, schedule",
    [
        ("mrcNu71ztWjAQA6ww9kHiW3zBWSQidHXTQ", None,
         [(0, 20000000, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw")]),
        ("mrcNu71ztWjAQA6ww9kHiW3zBWSQidHXTQ", "wallet",
         [(0, 20000000, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw")]),        
    ])
def test_on_sig(createcmtdata, dummyaddr, signmethod, schedule):
    #plan: create a new transaction with known inputs and dummy outputs;
    #then, create a signature with various inputs, pass in in b64 to on_sig.
    #in order for it to verify, the DummyBlockchainInterface will have to 
    #return the right values in query_utxo_set
    
    #create 2 privkey + utxos that are to be ours
    privs = [x*32 + "\x01" for x in [chr(y) for y in range(1,6)]]
    utxos = [str(x)*64+":1" for x in range(5)]
    fake_query_results = [{'value': 200000000,
                           'utxo': utxos[x],
                        'address': bitcoin.privkey_to_address(privs[x], False, magicbyte=0x6f),
                        'script': bitcoin.mk_pubkey_script(
                            bitcoin.privkey_to_address(privs[x], False, magicbyte=0x6f)),
                        'confirms': 20} for x in range(5)]

    dbci = DummyBlockchainInterface()
    dbci.insert_fake_query_results(fake_query_results)
    jm_single().bc_interface = dbci
    #make a transaction with all the fake results above, and some outputs
    outs = [{'value': 100000000, 'address': dummyaddr},
            {'value': 899990000, 'address': dummyaddr}]
    tx = bitcoin.mktx(utxos, outs)
    
    de_tx = bitcoin.deserialize(tx)
    #prepare the Taker with the right intermediate data
    taker = get_taker(schedule=schedule, sign_method=signmethod)
    taker.nonrespondants=["cp1", "cp2", "cp3"]
    taker.latest_tx = de_tx
    #my inputs are the first 2 utxos
    taker.input_utxos = {utxos[0]:
                        {'address': bitcoin.privkey_to_address(privs[0], False, magicbyte=0x6f),
                         'value': 200000000},
                        utxos[1]:
                        {'address': bitcoin.privkey_to_address(privs[1], False, magicbyte=0x6f),
                         'value': 200000000}}    
    taker.utxos = {None: utxos[:2], "cp1": [utxos[2]], "cp2": [utxos[3]], "cp3":[utxos[4]]}
    for i in range(2):
        # placeholders required for my inputs
        taker.latest_tx['ins'][i]['script'] = 'deadbeef' 
    #to prepare for my signing, need to mark cjaddr:
    taker.my_cj_addr = dummyaddr
    #make signatures for the last 3 fake utxos, considered as "not ours":
    tx3 = bitcoin.sign(tx, 2, privs[2])
    sig3 = b64encode(bitcoin.deserialize(tx3)['ins'][2]['script'].decode('hex'))
    taker.on_sig("cp1", sig3)
    tx4 = bitcoin.sign(tx, 3, privs[3])
    sig4 = b64encode(bitcoin.deserialize(tx4)['ins'][3]['script'].decode('hex'))
    taker.on_sig("cp2", sig4)
    tx5 = bitcoin.sign(tx, 4, privs[4])
    #Before completing with the final signature, which will trigger our own
    #signing, try with an injected failure of query utxo set, which should
    #prevent this signature being accepted.
    dbci.setQUSFail(True)
    sig5 = b64encode(bitcoin.deserialize(tx5)['ins'][4]['script'].decode('hex'))
    taker.on_sig("cp3", sig5)
    #allow it to succeed, and try again
    dbci.setQUSFail(False)
    #this should succeed and trigger the we-sign code
    taker.on_sig("cp3", sig5)

@pytest.mark.parametrize(
    "schedule",
    [
        ([(0, 20000000, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw")]),
    ])
def test_auth_counterparty(schedule):
    taker = get_taker(schedule=schedule)
    first_maker_response = t_maker_response["J559UPUSLLjHJpaB"]
    utxo, auth_pub, cjaddr, changeaddr, sig, maker_pub = first_maker_response
    auth_pub_tweaked = auth_pub[:8] + auth_pub[6:8] + auth_pub[10:]
    sig_tweaked = sig[:8] + sig[6:8] + sig[10:]
    assert taker.auth_counterparty(sig, auth_pub, maker_pub)
    assert not taker.auth_counterparty(sig, auth_pub_tweaked, maker_pub)
    assert not taker.auth_counterparty(sig_tweaked, auth_pub, maker_pub)

@pytest.fixture(scope="module")
def createcmtdata(request):
    def cmtdatateardown():
        shutil.rmtree("cmtdata")
    request.addfinalizer(cmtdatateardown)
    if not os.path.exists("cmtdata"):
            os.makedirs("cmtdata")
    load_program_config()
    jm_single().bc_interface = DummyBlockchainInterface()
    jm_single().config.set("BLOCKCHAIN", "network", "testnet")

            
        
    