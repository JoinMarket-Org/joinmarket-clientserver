from commontest import DummyBlockchainInterface
import pytest

from jmbase import utxostr_to_utxo
from jmclient import (load_test_config, jm_single)
from jmclient.commitment_utils import get_utxo_info, validate_utxo_data
from jmbitcoin import select_chain_params

def test_get_utxo_info():
    load_test_config()
    # this test tests mainnet keys, so temporarily switch network
    select_chain_params("bitcoin")
    jm_single().config.set("BLOCKCHAIN", "network", "mainnet")

    dbci = DummyBlockchainInterface()
    privkey = "L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi"
    #to verify use from_wif_privkey and privkey_to_address
    iaddr = "bc1q6tvmnmetj8vfz98vuetpvtuplqtj4uvvwjgxxc"
    fakeutxo = "aa"*32+":08"
    success, fakeutxo_bin = utxostr_to_utxo(fakeutxo)
    assert success
    fake_query_results = [{'value': 200000000,
                                'address': iaddr,
                                'utxo': fakeutxo_bin,
                                'confirms': 20}]    
    dbci.insert_fake_query_results(fake_query_results)
    jm_single().bc_interface = dbci
    u, priv = get_utxo_info(fakeutxo + "," + privkey)
    assert u == fakeutxo
    assert priv == privkey
    #invalid format
    with pytest.raises(Exception) as e_info:
        u, priv = get_utxo_info(fakeutxo + privkey)
    #invalid index
    fu2 = "ab"*32 + ":-1"
    with pytest.raises(Exception) as e_info:
        u, priv = get_utxo_info(fu2 + "," + privkey)
    #invalid privkey
    p2 = privkey[:-1] + 'j'
    with pytest.raises(Exception) as e_info:
        u, priv = get_utxo_info(fakeutxo + "," + p2)

    utxodatas = [(fakeutxo_bin, privkey)]
    retval = validate_utxo_data(utxodatas, False)
    assert retval
    #try to retrieve
    retval = validate_utxo_data(utxodatas, True)
    assert retval[0] == (fakeutxo_bin, 200000000)
    fake_query_results[0]['address'] = "fakeaddress"
    dbci.insert_fake_query_results(fake_query_results)
    #validate should fail for wrong address
    retval = validate_utxo_data(utxodatas, False)
    assert not retval
    #remove fake query result and trigger not found
    dbci.fake_query_results = None
    dbci.setQUSFail(True)
    retval = validate_utxo_data(utxodatas, False)
    assert not retval
    dbci.setQUSFail(False)
    select_chain_params("bitcoin/regtest")
    jm_single().config.set("BLOCKCHAIN", "network", "mainnet")
