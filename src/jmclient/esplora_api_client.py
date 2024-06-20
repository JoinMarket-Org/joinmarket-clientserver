import collections
import json
import requests
from math import ceil
from typing import Optional

from jmbase import bintohex, get_log
from jmclient.configure import jm_single


jlog = get_log()


class EsploraApiClient():

    _API_URL_BASE_MAINNET = "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/api/"
    _API_URL_BASE_TESTNET = "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/testnet/api/"

    def __init__(self, api_base_url: Optional[str] = None) -> None:
        jcg = jm_single().config.get
        if api_base_url:
            self.api_base_url = api_base_url
        else:
            self.api_base_url = None
            network = jcg("BLOCKCHAIN", "network")
            if network == "mainnet":
                self.api_base_url = self._API_URL_BASE_MAINNET
            elif network == "testnet":
                if jcg("BLOCKCHAIN", "blockchain_source") != "regtest":
                    self.api_base_url = self._API_URL_BASE_TESTNET
                else:
                    return
            else:
                jlog.debug(f"Esplora API not available for {network}.")
                return
        jlog.debug("Esplora API will use {} backend.".format(self.api_base_url))
        onion_socks5_host = jcg("PAYJOIN", "onion_socks5_host")
        onion_socks5_port = jcg("PAYJOIN", "onion_socks5_port")
        self.session = requests.session()
        self.proxies = {
            "http": "socks5h://" +
                onion_socks5_host + ":" + onion_socks5_port,
            "https": "socks5h://" +
                onion_socks5_host + ":" + onion_socks5_port
        }

    def _do_request(self, uri: str, body: Optional[str] = None) -> bytes:
        url = self.api_base_url + uri
        jlog.debug("Doing request to " + url)
        if body:
            response = self.session.post(url, data=body, proxies=self.proxies)
        else:
            response = self.session.get(url, proxies=self.proxies)
        jlog.debug(str(response.content))
        return response.content

    def pushtx(self, txbin: bytes) -> bool:
        if not self.api_base_url:
            return False
        txhex = bintohex(txbin)
        txid = self._do_request("tx", txhex)
        return True if len(txid) == 64 else False

    def estimate_fee_basic(self, conf_target: int) -> Optional[int]:
        if not self.api_base_url:
            return None
        try:
            estimates = json.loads(self._do_request("fee-estimates"))
            estimates = { int(k):v for k,v in estimates.items() }
        except Exception as e:
            jlog.debug(e)
            return None
        sorted_estimates = collections.OrderedDict(sorted(estimates.items()))
        prev = None
        for k, v in sorted_estimates.items():
            if k > conf_target:
                break
            prev = v
        return ceil(prev * 1000) if prev else None

if __name__ == "__main__":
    from jmclient import load_program_config
    load_program_config()
    ec = EsploraApiClient()
    est = ec.estimate_fee_basic(3)
    print(est)
    est = ec.estimate_fee_basic(999)
    print(est)

