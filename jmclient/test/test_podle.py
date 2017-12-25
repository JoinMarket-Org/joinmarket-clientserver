#! /usr/bin/env python
from __future__ import print_function
'''Tests of Proof of discrete log equivalence commitments.'''
import os
import jmbitcoin as bitcoin
import binascii
import json
import pytest
import copy
from jmclient import (load_program_config, get_log, jm_single, generate_podle,
                      generate_podle_error_string, set_commitment_file,
                      get_commitment_file, PoDLE, get_podle_commitments,
                      add_external_commitments, update_commitments)
from jmclient.podle import verify_all_NUMS, verify_podle, PoDLEError
log = get_log()

def test_commitments_empty(setup_podle):
    """Ensure that empty commitments file
    results in {}
    """
    assert get_podle_commitments() == ([], {})

def test_commitment_retries(setup_podle):
    """Assumes no external commitments available.
    Generate pretend priv/utxo pairs and check that they can be used
    taker_utxo_retries times.
    """
    allowed = jm_single().config.getint("POLICY", "taker_utxo_retries")
    #make some pretend commitments
    dummy_priv_utxo_pairs = [(bitcoin.sha256(os.urandom(10)),
           bitcoin.sha256(os.urandom(10))+":0") for _ in range(10)]
    #test a single commitment request of all 10
    for x in dummy_priv_utxo_pairs:
        p = generate_podle([x], allowed)
        assert p
    #At this point slot 0 has been taken by all 10.
    for i in range(allowed-1):
        p = generate_podle(dummy_priv_utxo_pairs[:1], allowed)
        assert p
    p = generate_podle(dummy_priv_utxo_pairs[:1], allowed)
    assert p is None

def generate_single_podle_sig(priv, i):
    """Make a podle entry for key priv at index i, using a dummy utxo value.
    This calls the underlying 'raw' code based on the class PoDLE, not the
    library 'generate_podle' which intelligently searches and updates commitments.
    """
    dummy_utxo = bitcoin.sha256(priv) + ":3"
    podle = PoDLE(dummy_utxo, binascii.hexlify(priv))
    r = podle.generate_podle(i)
    return (r['P'], r['P2'], r['sig'],
            r['e'], r['commit'])

def test_rand_commitments(setup_podle):
    for i in range(20):
        priv = os.urandom(32)
        Pser, P2ser, s, e, commitment = generate_single_podle_sig(priv, 1 + i%5)
        assert verify_podle(Pser, P2ser, s, e, commitment)
        #tweak commitments to verify failure
        tweaked = [x[::-1] for x in [Pser, P2ser, s, e, commitment]]
        for i in range(5):
            #Check failure on garbling of each parameter
            y = [Pser, P2ser, s, e, commitment]
            y[i] = tweaked[i]
            fail = False
            try: 
                fail = verify_podle(*y)
            except:
                pass
            finally:
                assert not fail

def test_nums_verify(setup_podle):
    """Check that the NUMS precomputed values are
    valid according to the code; assertion check
    implicit.
    """
    verify_all_NUMS(True)

def test_external_commitments(setup_podle):
    """Add this generated commitment to the external list
    {txid:N:{'P':pubkey, 'reveal':{1:{'P2':P2,'s':s,'e':e}, 2:{..},..}}}
    Note we do this *after* the sendpayment test so that the external
    commitments will not erroneously used (they are fake).
    """
    #ensure the file exists even if empty
    update_commitments()
    ecs = {}
    tries = jm_single().config.getint("POLICY","taker_utxo_retries")
    for i in range(10):
        priv = os.urandom(32)
        dummy_utxo = bitcoin.sha256(priv)+":2"
        ecs[dummy_utxo] = {}
        ecs[dummy_utxo]['reveal']={}
        for j in range(tries):
            P, P2, s, e, commit = generate_single_podle_sig(priv, j)
            if 'P' not in ecs[dummy_utxo]:
                ecs[dummy_utxo]['P']=P
            ecs[dummy_utxo]['reveal'][j] = {'P2':P2, 's':s, 'e':e}
    add_external_commitments(ecs)
    used, external = get_podle_commitments()
    for  u in external:
        assert external[u]['P'] == ecs[u]['P']
        for i in range(tries):
            for x in ['P2', 's', 'e']:
                assert external[u]['reveal'][str(i)][x] == ecs[u]['reveal'][i][x]
    
    #add a dummy used commitment, then try again
    update_commitments(commitment="ab"*32)
    ecs = {}
    known_commits = []
    known_utxos = []
    tries = 3
    for i in range(1, 6):
        u = binascii.hexlify(chr(i)*32)
        known_utxos.append(u)
        priv = chr(i)*32+"\x01"
        ecs[u] = {}
        ecs[u]['reveal']={}
        for j in range(tries):
            P, P2, s, e, commit = generate_single_podle_sig(priv, j)
            known_commits.append(commit)
            if 'P' not in ecs[u]:
                ecs[u]['P'] = P
            ecs[u]['reveal'][j] = {'P2':P2, 's':s, 'e':e}
    add_external_commitments(ecs)
    #simulate most of those external being already used
    for c in known_commits[:-1]:
        update_commitments(commitment=c)
    #this should find the remaining one utxo and return from it
    assert generate_podle([], max_tries=tries, allow_external=known_utxos)
    #test commitment removal
    to_remove = ecs[binascii.hexlify(chr(3)*32)]
    update_commitments(external_to_remove={binascii.hexlify(chr(3)*32):to_remove})
    #test that an incorrectly formatted file raises
    with open(get_commitment_file(), "rb") as f:
        validjson = json.loads(f.read())
    corruptjson = copy.deepcopy(validjson)
    del corruptjson['used']
    with open(get_commitment_file(), "wb") as f:
        f.write(json.dumps(corruptjson, indent=4))
    with pytest.raises(PoDLEError) as e_info:
        get_podle_commitments()
    #clean up
    with open(get_commitment_file(), "wb") as f:
        f.write(json.dumps(validjson, indent=4))



def test_podle_constructor(setup_podle):
    """Tests rules about construction of PoDLE object
    are conformed to.
    """
    priv  = "aa"*32
    #pub and priv together not allowed
    with pytest.raises(PoDLEError) as e_info:
        p = PoDLE(priv=priv, P="dummypub")
    #no pub or priv is allowed, i forget if this is useful for something
    p = PoDLE()
    #create from priv
    p = PoDLE(priv=priv+"01", u="dummyutxo")
    pdict = p.generate_podle(2)
    assert all([k in pdict for k in ['used', 'utxo', 'P', 'P2', 'commit', 'sig', 'e']])
    #using the valid data, serialize/deserialize test
    deser = p.deserialize_revelation(p.serialize_revelation())
    assert all([deser[x] == pdict[x] for x in ['utxo', 'P', 'P2', 'sig', 'e']])
    #deserialization must fail for wrong number of items
    with pytest.raises(PoDLEError) as e_info:
        p.deserialize_revelation(':'.join([str(x) for x in range(4)]), separator=':')
    #reveal() must work without pre-generated commitment
    p.commitment = None
    pdict2 = p.reveal()
    assert pdict2 == pdict
    #corrupt P2, cannot commit:
    p.P2 = "blah"
    with pytest.raises(PoDLEError) as e_info:
        p.get_commitment()
    #generation fails without a utxo
    p = PoDLE(priv=priv)
    with pytest.raises(PoDLEError) as e_info:
        p.generate_podle(0)
    #Test construction from pubkey
    pub = bitcoin.privkey_to_pubkey(priv+"01")
    p = PoDLE(P=pub)
    with pytest.raises(PoDLEError) as e_info:
        p.get_commitment()
    with pytest.raises(PoDLEError) as e_info:
        p.verify("dummycommitment", range(3))

def test_podle_error_string(setup_podle):
    priv_utxo_pairs = [('fakepriv1', 'fakeutxo1'),
                             ('fakepriv2', 'fakeutxo2')]
    to = ['tooold1', 'tooold2']
    ts = ['toosmall1', 'toosmall2']
    unspent = "dummyunspent"
    cjamt = 100
    tua = "3"
    tuamtper = "20"
    errmgsheader, errmsg = generate_podle_error_string(priv_utxo_pairs,
                                                       to,
                                                       ts,
                                                       unspent,
                                                       cjamt,
                                                       tua,
                                                       tuamtper)
    assert errmgsheader == ("Failed to source a commitment; this debugging information"
                            " may help:\n\n")
    y = [x[1] for x in priv_utxo_pairs]
    assert all([errmsg.find(x) != -1 for x in to + ts + y])
    #ensure OK with nothing
    errmgsheader, errmsg = generate_podle_error_string([], [], [], unspent,
                                                       cjamt, tua, tuamtper)

@pytest.fixture(scope="module")
def setup_podle(request):
    load_program_config()
    if not os.path.exists("cmtdata"):
        os.mkdir("cmtdata")
    prev_commits = False
    #back up any existing commitments
    pcf = get_commitment_file()
    log.debug("Podle file: " + pcf)
    if os.path.exists(pcf):
        os.rename(pcf, pcf + ".bak")
        prev_commits = True
    def teardown():
        if prev_commits:
            os.rename(pcf + ".bak", pcf)
        else:
            if os.path.exists(pcf):
                os.remove(pcf)
    request.addfinalizer(teardown)
