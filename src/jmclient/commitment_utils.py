import sys
from jmbase import jmprint, utxostr_to_utxo, utxo_to_utxostr, EXIT_FAILURE
from jmclient import (
    jm_single,
    BTCEngine,
    BTC_P2PKH,
    BTC_P2SH_P2WPKH,
    BTC_P2WPKH,
)


def quit(parser, errmsg):  # pragma: no cover
    parser.error(errmsg)
    sys.exit(EXIT_FAILURE)


def get_utxo_info(upriv, utxo_binary=False):
    """Verify that the input string parses correctly as (utxo, priv)
    and return that. If `utxo_binary` is true, the first element of
    that return tuple is the standard internal form
    (txid-in-binary, index-as-int).
    """
    try:
        u, priv = upriv.split(',')
        u = u.strip()
        priv = priv.strip()
        success, utxo_bin = utxostr_to_utxo(u)
        assert success, u
    except:
        # not sending data to stdout in case privkey info
        jmprint("Failed to parse utxo information for utxo", "error")
        raise
    try:
        # see note below for why keytype is ignored, and note that
        # this calls read_privkey to validate.
        raw, _ = BTCEngine.wif_to_privkey(priv)
    except:
        jmprint(
            "failed to parse privkey, make sure it's WIF compressed format.",
            "error",
        )
        raise
    utxo_to_return = utxo_bin if utxo_binary else u
    return utxo_to_return, priv


def print_failed_addr_match(utxostr, addr1, addr2):
    jmprint(
        "privkey corresponds to the wrong address for utxo: " + utxostr,
        "error",
    )
    jmprint("blockchain returned address: {}".format(addr2), "error")
    jmprint("your privkey gave this address: " + addr1, "error")
    return False


def validate_utxo_data(utxo_datas, retrieve=False, utxo_address_type="p2wpkh"):
    """For each (utxo, privkey), first
    convert the privkey and convert to address,
    then use the blockchain instance to look up
    the utxo and check that its address field matches.
    If retrieve is True, return the set of utxos and their values.
    """
    results = []
    for u, priv in utxo_datas:
        success, utxostr = utxo_to_utxostr(u)
        if not success:
            jmprint("Invalid utxo format: " + str(u), "error")
            sys.exit(EXIT_FAILURE)
        jmprint('validating this utxo: ' + utxostr, "info")
        # as noted in `ImportWalletMixin` code comments, there is not
        # yet a functional auto-detection of key type from WIF, hence
        # the need for this additional switch:
        if utxo_address_type == "p2wpkh":
            engine = BTC_P2WPKH
        elif utxo_address_type == "p2sh-p2wpkh":
            engine = BTC_P2SH_P2WPKH
        elif utxo_address_type == "p2pkh":
            engine = BTC_P2PKH
        else:
            raise Exception("Invalid argument: " + str(utxo_address_type))
        rawpriv, _ = BTCEngine.wif_to_privkey(priv)
        addr = engine.privkey_to_address(rawpriv)
        jmprint('claimed address: ' + addr, "info")
        res = jm_single().bc_interface.query_utxo_set([u])
        if len(res) != 1 or None in res:
            jmprint("utxo not found on blockchain: " + utxostr, "error")
            return False
        returned_addr = engine.script_to_address(res[0]['script'])
        if returned_addr != addr:
            return print_failed_addr_match(utxostr, addr, returned_addr)
        if retrieve:
            results.append((u, res[0]['value']))
    jmprint('all utxos validated OK', "success")
    if retrieve:
        return results
    return True
