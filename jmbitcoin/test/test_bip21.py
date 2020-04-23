import jmbitcoin as btc
import pytest


def test_bip21():

    # These should raise exception because of not being valid BIP21 URI's
    with pytest.raises(ValueError):
        btc.decode_bip21_uri('')
        btc.decode_bip21_uri('nfdjksnfjkdsnfjkds')
        btc.decode_bip21_uri('175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W')
        btc.decode_bip21_uri(
            '175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=20.3')
        btc.decode_bip21_uri('bitcoin:')
        btc.decode_bip21_uri('bitcoin:?amount=20.3')
        btc.decode_bip21_uri(
            'bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=')
        btc.decode_bip21_uri(
            'bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=XYZ')
        btc.decode_bip21_uri(
            'bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=100\'000')
        btc.decode_bip21_uri(
            'bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=100,000')
        btc.decode_bip21_uri(
            'bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=100000000')

    assert(btc.decode_bip21_uri('bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W'
        )['address'] == '175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W')

    parsed = btc.decode_bip21_uri(
        'bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?label=Luke-Jr')
    assert(parsed['address'] == '175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W')
    assert(parsed['label'] == 'Luke-Jr')

    parsed = btc.decode_bip21_uri(
        'bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=20.3&label=Luke-Jr')
    assert(parsed['address'] == '175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W')
    assert(parsed['amount'] == 2030000000)
    assert(parsed['label'] == 'Luke-Jr')

    parsed = btc.decode_bip21_uri(
        'bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz')
    assert(parsed['address'] == '175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W')
    assert(parsed['amount'] == 5000000000)
    assert(parsed['label'] == 'Luke-Jr')
    assert(parsed['message'] == 'Donation for project xyz')

    # This should raise exception because of unknown req-* parameters
    with pytest.raises(ValueError):
        btc.decode_bip21_uri(
            'bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?req-somethingyoudontunderstand=50&req-somethingelseyoudontget=999')

    parsed = btc.decode_bip21_uri(
        'bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?somethingyoudontunderstand=50&somethingelseyoudontget=999')
    assert(parsed['address'] == '175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W')
    assert(parsed['somethingyoudontunderstand'] == '50')
    assert(parsed['somethingelseyoudontget'] == '999')

