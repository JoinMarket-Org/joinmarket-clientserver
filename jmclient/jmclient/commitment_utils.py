from __future__ import print_function

import sys, os
import jmclient.btc as btc
from jmclient import jm_single, get_p2pk_vbyte

def quit(parser, errmsg): #pragma: no cover
    parser.error(errmsg)
    sys.exit(0)

def get_utxo_info(upriv):
    """Verify that the input string parses correctly as (utxo, priv)
    and return that.
    """
    try:
        u, priv = upriv.split(',')
        u = u.strip()
        priv = priv.strip()
        txid, n = u.split(':')
        assert len(txid)==64
        assert len(n) in range(1, 4)
        n = int(n)
        assert n in range(256)
    except:
        #not sending data to stdout in case privkey info
        print("Failed to parse utxo information for utxo")
        raise
    try:
        hexpriv = btc.from_wif_privkey(priv, vbyte=get_p2pk_vbyte())
    except:
        print("failed to parse privkey, make sure it's WIF compressed format.")
        raise
    return u, priv
    
def validate_utxo_data(utxo_datas, retrieve=False):
    """For each txid: N, privkey, first
    convert the privkey and convert to address,
    then use the blockchain instance to look up
    the utxo and check that its address field matches.
    If retrieve is True, return the set of utxos and their values.
    """
    results = []
    for u, priv in utxo_datas:
        print('validating this utxo: ' + str(u))
        hexpriv = btc.from_wif_privkey(priv, vbyte=get_p2pk_vbyte())
        addr = btc.privkey_to_address(hexpriv, magicbyte=get_p2pk_vbyte())
        print('claimed address: ' + addr)
        res = jm_single().bc_interface.query_utxo_set([u])
        print('blockchain shows this data: ' + str(res))
        if len(res) != 1 or None in res:
            print("utxo not found on blockchain: " + str(u))
            return False
        if res[0]['address'] != addr:
            print("privkey corresponds to the wrong address for utxo: " + str(u))
            print("blockchain returned address: " + res[0]['address'])
            print("your privkey gave this address: " + addr)
            return False
        if retrieve:
            results.append((u, res[0]['value']))
    print('all utxos validated OK')
    if retrieve:
        return results
    return True