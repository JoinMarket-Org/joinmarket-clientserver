from jmbase import utxo_to_utxostr


def fmt_utxos(utxos, wallet_service, prefix=''):
    output = []
    for u in utxos:
        utxo_str = '{}{} - {}'.format(
            prefix, fmt_utxo(u), fmt_tx_data(utxos[u], wallet_service))
        output.append(utxo_str)
    return '\n'.join(output)

def fmt_utxo(utxo):
    success, utxostr = utxo_to_utxostr(utxo)
    assert success
    return utxostr

def fmt_tx_data(tx_data, wallet_service):
    return 'path: {}, address: {}, value: {}'.format(
        wallet_service.get_path_repr(wallet_service.script_to_path(tx_data['script'])),
        wallet_service.script_to_addr(tx_data['script']), tx_data['value'])


def generate_podle_error_string(priv_utxo_pairs, to, ts, wallet_service, cjamount,
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
            errmsg += (fmt_utxo(u) + "\n")
    errmsg += "2: Utxos that have less than " + taker_utxo_age + " confirmations:\n"
    if len(to) == 0:
        errmsg += ("None\n")
    else:
        for t in to:
            errmsg += (fmt_utxo(t) + "\n")
    errmsg += ("3: Utxos that were not at least " + taker_utxo_amtpercent + \
               "% of the size of the coinjoin amount " + str(cjamount) + "\n")
    if len(ts) == 0:
        errmsg += ("None\n")
    else:
        for t in ts:
            errmsg += (fmt_utxo(t) + "\n")
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

    for md, utxos in wallet_service.get_utxos_by_mixdepth().items():
        if not utxos:
            continue
        errmsg += ("\nmixdepth {}:\n{}".format(
            md, fmt_utxos(utxos, wallet_service, prefix='    ')))
    return (errmsgheader, errmsg)
