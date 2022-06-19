#!/usr/bin/env python3
import sys
from datetime import datetime
from decimal import Decimal
from json import loads
from optparse import OptionParser

from jmbase import EXIT_ARGERROR, jmprint, get_log, utxostr_to_utxo, EXIT_FAILURE
from jmbitcoin import amount_to_sat, sat_to_btc
from jmclient import add_base_options, load_program_config, jm_single, get_bond_values

DESCRIPTION = """Given either a Bitcoin UTXO in the form TXID:n
(e.g., 0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098:0)
or an amount in either satoshi or bitcoin (e.g., 150000, 0.1, 10.123, 10btc),
calculate fidelity bond values for all possible locktimes in a one-year period
(12 months, you can change that with the `-m --months` option).
By default it uses the values from your joinmarket.cfg,
you can override these with the `-i --interest` and `-e --exponent` options.
Additionally, you can export the orderbook from ob-watcher.py and use the data here
with the `-o --orderbook` option, this will compare the results from this script
with the fidelity bonds in the orderbook.
"""

log = get_log()


def main() -> None:
    parser = OptionParser(
        usage="usage: %prog [options] UTXO or amount",
        description=DESCRIPTION,
    )
    add_base_options(parser)
    parser.add_option(
        "-i",
        "--interest",
        action="store",
        type="float",
        dest="interest",
        help="Interest rate to use for fidelity bond calculation (instead of interest_rate config)",
    )
    parser.add_option(
        "-e",
        "--exponent",
        action="store",
        type="float",
        dest="exponent",
        help="Exponent to use for fidelity bond calculation (instead of bond_value_exponent config)",
    )
    parser.add_option(
        "-m",
        "--months",
        action="store",
        type="int",
        dest="months",
        help="For how many months to calculate the fidelity bond values, each month has its own stats (default 12)",
        default=12,
    )
    parser.add_option(
        "-o",
        "--orderbook",
        action="store",
        type="str",
        dest="path_to_json",
        help="Path to the exported orderbook in JSON format",
    )

    options, args = parser.parse_args()
    load_program_config(config_path=options.datadir)
    if len(args) != 1:
        log.error("Invalid arguments, see --help")
        sys.exit(EXIT_ARGERROR)
    if options.path_to_json:
        try:
            with open(options.path_to_json, "r", encoding="UTF-8") as orderbook:
                orderbook = loads(orderbook.read())
        except FileNotFoundError as exc:
            log.error(exc)
            sys.exit(EXIT_ARGERROR)
    else:
        orderbook = None
    try:
        amount = amount_to_sat(args[0])
        confirm_time = None
    except ValueError:
        # If it's not a valid amount then it has to be a UTXO
        if jm_single().bc_interface is None:
            log.error("For calculation based on UTXO access to Bitcoin Core is required")
            sys.exit(EXIT_FAILURE)
        success, utxo = utxostr_to_utxo(args[0])
        if not success:
            # utxo contains the error message
            log.error(utxo)
            sys.exit(EXIT_ARGERROR)
        utxo_data = jm_single().bc_interface.query_utxo_set(utxo, includeconfs=True)[0]
        amount = utxo_data["value"]
        if utxo_data["confirms"] == 0:
            log.warning("Given UTXO is unconfirmed, current time will be used as confirmation time")
            confirm_time = None
        elif utxo_data["confirms"] < 0:
            log.error("Given UTXO is invalid, reason: conflicted")
            sys.exit(EXIT_ARGERROR)
        else:
            current_height = jm_single().bc_interface.get_current_block_height()
            block_hash = jm_single().bc_interface.get_block_hash(current_height - utxo_data["confirms"] + 1)
            confirm_time = jm_single().bc_interface.get_block_time(block_hash)

    parameters, results = get_bond_values(amount,
                                          options.months,
                                          confirm_time,
                                          options.interest,
                                          options.exponent,
                                          orderbook)
    jmprint(f"Amount locked: {amount} ({sat_to_btc(amount)} btc)")
    jmprint(f"Confirmation time: {datetime.fromtimestamp(parameters['confirm_time'])}")
    jmprint(f"Interest rate: {parameters['interest']} ({parameters['interest'] * 100}%)")
    jmprint(f"Exponent: {parameters['exponent']}")
    jmprint(f"\nFIDELITY BOND VALUES (BTC^{parameters['exponent']})")
    jmprint("\nSee /docs/fidelity-bonds.md for complete formula and more")

    for result in results:
        locktime = datetime.fromtimestamp(result["locktime"])
        # Mimic the locktime value the user would have to insert to create such fidelity bond
        jmprint(f"\nLocktime: {locktime.year}-{locktime.month}")
        # Mimic orderbook value
        jmprint(f"Bond value: {float(Decimal(result['value']) / Decimal(1e16)):.16f}")
        if options.path_to_json:
            jmprint(f"Weight: {result['weight']:.5f} ({result['weight'] * 100:.2f}% of all bonds)")
            jmprint(f"Top {result['percentile']}% of the orderbook by value")


if __name__ == "__main__":
    main()
