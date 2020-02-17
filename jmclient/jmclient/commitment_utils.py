
import sys
import jmbitcoin as btc
from jmbase import jmprint
from jmclient import (jm_single, get_p2pk_vbyte, get_p2sh_vbyte,
                      BTCEngine, TYPE_P2PKH, TYPE_P2SH_P2WPKH,
                      BTC_P2PKH, BTC_P2SH_P2WPKH)
from jmbase.support import EXIT_FAILURE, utxostr_to_utxo


def quit(parser, errmsg): #pragma: no cover
    parser.error(errmsg)
    sys.exit(EXIT_FAILURE)

def get_utxo_info(upriv):
    """Verify that the input string parses correctly as (utxo, priv)
    and return that.
    """
    try:
        u, priv = upriv.split(',')
        u = u.strip()
        priv = priv.strip()
        success, utxo = utxostr_to_utxo(u)
        assert success, utxo
    except:
        #not sending data to stdout in case privkey info
        jmprint("Failed to parse utxo information for utxo", "error")
        raise
    try:
        # see note below for why keytype is ignored, and note that
        # this calls read_privkey to validate.
        raw, _ = BTCEngine.wif_to_privkey(priv)
    except:
        jmprint("failed to parse privkey, make sure it's WIF compressed format.", "error")
        raise
    return u, priv
    
def validate_utxo_data(utxo_datas, retrieve=False, segwit=False):
    """For each txid: N, privkey, first
    convert the privkey and convert to address,
    then use the blockchain instance to look up
    the utxo and check that its address field matches.
    If retrieve is True, return the set of utxos and their values.
    If segwit is true, assumes a p2sh wrapped p2wpkh, i.e.
    native segwit is NOT currently supported here. If segwit
    is false, p2pkh is assumed.
    """
    results = []
    for u, priv in utxo_datas:
        jmprint('validating this utxo: ' + str(u), "info")
        # as noted in `ImportWalletMixin` code comments, there is not
        # yet a functional auto-detection of key type from WIF, so the
        # second argument is ignored; we assume p2sh-p2wpkh if segwit,
        # else we assume p2pkh.
        engine = BTC_P2SH_P2WPKH if segwit else BTC_P2PKH
        rawpriv, _ = BTCEngine.wif_to_privkey(priv)
        addr = engine.privkey_to_address(rawpriv)
        jmprint('claimed address: ' + addr, "info")
        res = jm_single().bc_interface.query_utxo_set([u])
        if len(res) != 1 or None in res:
            jmprint("utxo not found on blockchain: " + str(u), "error")
            return False
        if res[0]['address'] != addr:
            jmprint("privkey corresponds to the wrong address for utxo: " + str(u), "error")
            jmprint("blockchain returned address: {}".format(res[0]['address']), "error")
            jmprint("your privkey gave this address: " + addr, "error")
            return False
        if retrieve:
            results.append((u, res[0]['value']))
    jmprint('all utxos validated OK', "success")
    if retrieve:
        return results
    return True
