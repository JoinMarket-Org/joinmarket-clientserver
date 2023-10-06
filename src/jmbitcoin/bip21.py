# https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki
# bitcoin:<address>[?amount=<amount>][?label=<label>][?message=<message>]
# We don't check validity of Bitcoin address here, as all the tools using
# this are expected to do address validation independently anyway.

from jmbitcoin import amount_to_sat
from typing import Dict, List, Tuple, Union
from urllib.parse import parse_qsl, quote, unquote_plus, urlencode, urlparse
import re


def is_bip21_uri(uri: str) -> bool:
    parsed = urlparse(uri)
    return parsed.scheme.lower() == 'bitcoin' and parsed.path != ''


def _is_bip21_amount_str(amount: str) -> bool:
    return re.compile(r"^[0-9]{1,8}(\.[0-9]{1,8})?$").match(str(amount)) != None


def _validate_bip21_amount(amount: str) -> None:
    if not _is_bip21_amount_str(amount):
        raise ValueError("Invalid BTC amount " + str(amount))


def decode_bip21_uri(uri: str) -> Dict[str, Union[str, int]]:
    if not is_bip21_uri(uri):
        raise ValueError("Not a valid BIP21 URI: " + uri)
    result = {}
    parsed = urlparse(uri)
    result['address'] = parsed.path
    params = parse_qsl(parsed.query)
    for key, value in params:
        if key.startswith('req-'):
            raise ValueError("Unknown required parameter " + key +
                " in BIP21 URI.")
        if key == 'amount':
            _validate_bip21_amount(value)
            # Convert amount to sats, as used internally by JM
            result['amount'] = amount_to_sat(value + "btc")
        else:
            result[key] = unquote_plus(value)
    return result


def encode_bip21_uri(address: str,
                     params: Union[dict, List[Tuple[str, Union[float, int, str]]]],
                     safe: str = "") -> str:
    uri = 'bitcoin:' + address
    if len(params) > 0:
        if 'amount' in params:
            _validate_bip21_amount(params['amount'])
        uri += '?' + urlencode(params, safe=safe, quote_via=quote)
    return uri
