# https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki
# bitcoin:<address>[?amount=<amount>][?label=<label>][?message=<message>]
# We don't check validity of Bitcoin address here, as all the tools using
# this are expected to do address validation independently anyway.

from jmbitcoin import amount_to_sat
from urllib.parse import parse_qs, urlparse
from url_decode import urldecode
import re


def is_bip21_uri(uri):
    parsed = urlparse(uri)
    return parsed.scheme == 'bitcoin' and parsed.path != ''


def is_bip21_amount_str(amount):
    return re.compile("^[0-9]{1,8}(\.[0-9]{1,8})?$").match(amount) != None


def decode_bip21_uri(uri):
    if not is_bip21_uri(uri):
        raise ValueError("Not a valid BIP21 URI: " + uri)
    result = {}
    parsed = urlparse(uri)
    result['address'] = parsed.path
    params = parse_qs(parsed.query)
    for key in params:
        if key.startswith('req-'):
            raise ValueError("Unknown required parameter " + key +
                " in BIP21 URI.")
        if key == 'amount':
            amount_str = params['amount'][0]
            if not is_bip21_amount_str(amount_str):
                raise ValueError("Invalid BTC amount " + amount_str +
                    " vs. " + str(amount_to_sat(amount_str)) + " sat")
            # Convert amount to sats, as used internally by JM
            result['amount'] = amount_to_sat(amount_str + "btc")
        else:
            result[key] = urldecode(params[key][0])
    return result
