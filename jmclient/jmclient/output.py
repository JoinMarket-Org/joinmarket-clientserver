from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401
from binascii import hexlify


def fmt_utxos(utxos, wallet, prefix=''):
    output = []
    for u in utxos:
        utxo_str = '{}{} - {}'.format(
            prefix, fmt_utxo(u), fmt_tx_data(utxos[u], wallet))
        output.append(utxo_str)
    return '\n'.join(output)


def fmt_utxo(utxo):
    return '{}:{}'.format(hexlify(utxo[0]).decode('ascii'), utxo[1])


def fmt_tx_data(tx_data, wallet):
    return 'path: {}, address: {}, value: {}'.format(
        wallet.get_path_repr(wallet.script_to_path(tx_data['script'])),
        wallet.script_to_addr(tx_data['script']), tx_data['value'])


def generate_podle_error_string(priv_utxo_pairs, to, ts, wallet, cjamount,
                                taker_utxo_age, taker_utxo_amtpercent):
    """Gives detailed error information on why commitment sourcing failed.
    """
    errmsg = ""
    errmsgheader = ("Failed to source a commitment; this debugging information"
                    " may help:\n\n")
    errmsg += ("1: Utxos that passed age and size limits, but have "
                "been used too many times (see taker_utxo_retries "
                "in the config):\n")
    if len(priv_utxo_pairs) == 0:
        errmsg += ("None\n")
    else:
        for p, u in priv_utxo_pairs:
            errmsg += (str(u) + "\n")
    errmsg += "2: Utxos that have less than " + taker_utxo_age + " confirmations:\n"
    if len(to) == 0:
        errmsg += ("None\n")
    else:
        for t in to:
            errmsg += (str(t) + "\n")
    errmsg += ("3: Utxos that were not at least " + taker_utxo_amtpercent + \
               "% of the size of the coinjoin amount " + str(cjamount) + "\n")
    if len(ts) == 0:
        errmsg += ("None\n")
    else:
        for t in ts:
            errmsg += (str(t) + "\n")
    errmsg += ('***\n')
    errmsg += ("Utxos that appeared in item 1 cannot be used again.\n")
    errmsg += ("Utxos only in item 2 can be used by waiting for more "
               "confirmations, (set by the value of taker_utxo_age).\n")
    errmsg += ("Utxos only in item 3 are not big enough for this "
               "coinjoin transaction, set by the value "
               "of taker_utxo_amtpercent.\n")
    errmsg += ("If you cannot source a utxo from your wallet according "
               "to these rules, use the tool add-utxo.py to source a "
               "utxo external to your joinmarket wallet. Read the help "
               "with 'python add-utxo.py --help'\n\n")
    errmsg += ("***\nFor reference, here are the utxos in your wallet:\n")

    for md, utxos in wallet.get_utxos_by_mixdepth_().items():
        if not utxos:
            continue
        errmsg += ("\nmixdepth {}:\n{}".format(
            md, fmt_utxos(utxos, wallet, prefix='    ')))
    return (errmsgheader, errmsg)
