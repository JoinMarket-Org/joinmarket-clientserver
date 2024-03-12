#!/usr/bin/env python3

from decimal import Decimal
from jmbase import get_log, hextobin, bintohex
from jmbase.support import EXIT_SUCCESS, EXIT_FAILURE, EXIT_ARGERROR, jmprint, cli_prompt_user_yesno
from jmclient import jm_single, load_program_config, open_test_wallet_maybe, get_wallet_path, WalletService
from jmclient.cli_options import OptionParser, add_base_options
import jmbitcoin as btc
import sys

jlog = get_log()
parser = OptionParser(
    usage='usage: %prog [options] [wallet file] txid',
    description=
    'Bumps the fee on a wallet transaction')
parser.add_option('--psbt',
                  action='store_true',
                  dest='with_psbt',
                  default=False,
                  help='output as psbt instead of '
                  'broadcasting the transaction.')
parser.add_option('-o',
                  '--output',
                  action='store',
                  type='int',
                  dest='output',
                  default=-1,
                  help='optionally specify which output to deduct the fee from. Outputs '
                  'are 0-indexed meaning the first output has an index value of 0 and the '
                  'second, an index value of 1 and so on.')
parser.add_option('-f',
                  '--txfee',
                  action='store',
                  type='int',
                  dest='txfee',
                  default=-1,
                  help='Bitcoin miner tx_fee to use for transaction(s). A number higher '
                  'than 1000 is used as "satoshi per KB" tx fee. A number lower than that '
                  'uses the dynamic fee estimation of your blockchain provider as '
                  'confirmation target. This temporarily overrides the "tx_fees" setting '
                  'in your joinmarket.cfg. Works the same way as described in it. Check '
                  'it for examples.')
parser.add_option('-a',
                  '--amtmixdepths',
                  action='store',
                  type='int',
                  dest='amtmixdepths',
                  help='number of mixdepths in wallet, default 5',
                  default=5)
parser.add_option('-g',
                  '--gap-limit',
                  type="int",
                  action='store',
                  dest='gaplimit',
                  help='gap limit for wallet, default=6',
                  default=6)
parser.add_option('--yes',
                  action='store_true',
                  dest='answeryes',
                  default=False,
                  help='answer yes to everything')
add_base_options(parser)

def check_valid_candidate(orig_tx, wallet, output_index=-1):
    orig_tx_info = jm_single().bc_interface.get_transaction(orig_tx.GetTxid()[::-1])
    # check that the transaction is still unconfirmed
    if orig_tx_info['confirmations'] > 0:
        raise RuntimeWarning('Transaction already confirmed. Nothing to do.')

    # all transaction inputs must belong to the wallet
    own_inputs_n = len(wallet.inputs_consumed_by_tx(orig_tx))
    tx_inputs_n = len(orig_tx.vin)

    if own_inputs_n != tx_inputs_n:
        raise ValueError('Transaction inputs should belong to the wallet.')

    # either mempoolfullrbf must be enabled or at least one input must signal
    # opt-in rbf
    if not jm_single().bc_interface.mempoolfullrbf() and \
       not any([vin.nSequence <= 0xffffffff - 2 for vin in orig_tx.vin]):
        raise ValueError('Transaction not replaceable.')

    # 1. If output_index is specified, check that the output exist
    # 2. If not, check that we have only one output
    # 3. If not, wallet should own at least one output that we can deduct
    # fees from.
    if output_index >= 0 and len(orig_tx.vout) > output_index:
        return None
    elif len(orig_tx.vout) == 1:
        return None
    elif not any(
        [wallet.is_known_script(vout.scriptPubKey) for vout in orig_tx.vout]
    ):
        raise ValueError('Transaction has no obvious output we can deduct fees '
                         'from. Specify the output to pay from using the -o '
                         'option.')

def compute_bump_fee(tx, fee_per_kb):
    tx_info = jm_single().bc_interface.get_transaction(tx.GetTxid()[::-1])
    tx_size_n = btc.tx_vsize(tx)
    tx_fee = btc.amount_to_sat(abs(tx_info['fee']))
    proposed_fee_rate = fee_per_kb / Decimal(1000.0)
    proposed_fee = int(tx_size_n * proposed_fee_rate)
    min_proposed_fee = tx_fee + tx_size_n
    min_proposed_fee_rate = min_proposed_fee / Decimal(tx_size_n)

    if proposed_fee < (tx_fee + tx_size_n):
        raise ValueError('Proposed fee for transaction replacement: '
                         '%d sats (%.1f sat/vB) is below minimum required '
                         'for relay: %d sats (%.1f sat/vB). '
                         'Try using a higher fee setting.'
                         % (proposed_fee, proposed_fee_rate,
                            min_proposed_fee, min_proposed_fee_rate))

    return (proposed_fee - tx_fee)

def prepare_transaction(new_tx, old_tx, wallet):
    input_scripts = {}
    spent_outs = []
    for ix, vin in enumerate(new_tx.vin):
        script = wallet.pubkey_to_script(
            btc.extract_pubkey_from_witness(old_tx, ix)[0])
        tx_info = jm_single().bc_interface.get_transaction(
            hextobin(btc.b2lx(new_tx.vin[ix].prevout.hash)))
        prev_tx = btc.CTransaction.deserialize(hextobin(tx_info['hex']))
        amount = prev_tx.vout[new_tx.vin[ix].prevout.n].nValue

        input_scripts[ix] = (script, amount)
        spent_outs.append(btc.CMutableTxOut(amount, script))

    return (input_scripts, spent_outs)

def sign_transaction(new_tx, old_tx, wallet_service):
    input_scripts, _ = prepare_transaction(new_tx, old_tx, wallet_service.wallet)
    success, msg = wallet_service.sign_tx(new_tx, input_scripts)
    if not success:
        raise RuntimeError("Failed to sign transaction, quitting. Error msg: " + msg)

def sign_psbt(new_tx, old_tx, wallet_service):
    _, spent_outs = prepare_transaction(new_tx, old_tx, wallet_service.wallet)
    unsigned_psbt = wallet_service.create_psbt_from_tx(
        new_tx, spent_outs=spent_outs)
    signed_psbt, err = wallet_service.sign_psbt(unsigned_psbt.serialize())

    if err:
        raise RuntimeError("Failed to sign PSBT, quitting. Error message: " + err)

    return btc.PartiallySignedTransaction.deserialize(signed_psbt)

def create_bumped_tx(tx, fee_per_kb, wallet, output_index=-1):
    check_valid_candidate(tx, wallet, output_index)
    fee = compute_bump_fee(tx, fee_per_kb)

    if (
        len(tx.vout) == 1
        and tx.vout[0].nValue >= (fee + jm_single().BITCOIN_DUST_THRESHOLD)
    ):
        tx.vout[0].nValue -= fee
        fee = 0
    elif (
        output_index >= 0
        and len(tx.vout) > output_index
        and tx.vout[output_index].nValue >= (fee + jm_single().BITCOIN_DUST_THRESHOLD)
    ):
        tx.vout[output_index].nValue -= fee
        fee = 0
    else:
        for ix, vout in enumerate(tx.vout):
            if wallet.is_known_script(vout.scriptPubKey) and fee > 0:
                # check if the output is a change address
                if wallet.script_to_path(vout.scriptPubKey)[-2] != 1:
                    continue

                # deduct fee from the change
                tx.vout[ix].nValue -= fee
                fee = 0

                # if the output value is less than zero, remove it
                if tx.vout[ix].nValue < 0:
                    jlog.info("Dynamically calculated change lower than zero; dropping.")

                    # update fee to the additional amount needed to pay for the tx
                    # accounting for the removal of the output
                    fee = abs(tx.vout[ix].nValue) - len(tx.vout[ix].serialize())
                    tx.vout.remove(vout)
                    continue

                # if the output value is below the dust threshold, remove it
                if tx.vout[ix].nValue <= jm_single().BITCOIN_DUST_THRESHOLD:
                    jlog.info("Dynamically calculated change lower than dust: " +
                        btc.amount_to_str(tx.vout[ix].nValue) + "; dropping.")
                    tx.vout.remove(vout)
                break

    # create new transaction from the old
    # there's the possibility that it returns the same transaction as the old
    # if no outputs were available to deduct a fee from
    return btc.CMutableTransaction(
        tx.vin, tx.vout, nLockTime=tx.nLockTime,
        nVersion=tx.nVersion)

if __name__ == '__main__':
    (options, args) = parser.parse_args()
    load_program_config(config_path=options.datadir)
    if len(args) < 2:
        parser.error("JoinMarket bumpfee needs arguments:"
                     " wallet file and txid.")
        sys.exit(EXIT_ARGERROR)

    wallet_name = args[0]
    txid = args[1]

    # If tx_fees are set manually by CLI argument, override joinmarket.cfg:
    if int(options.txfee) > 0:
        jm_single().config.set("POLICY", "tx_fees", str(options.txfee))
    fee_per_kb = jm_single().bc_interface.estimate_fee_per_kb(
        jm_single().config.getint("POLICY", "tx_fees"))
    if fee_per_kb is None:
        raise RuntimeError("Cannot estimate fee per kB, possibly" +
                           " a failure of connection to the blockchain.")

    # open the wallet and synchronize it
    wallet_path = get_wallet_path(wallet_name, None)
    wallet = open_test_wallet_maybe(
        wallet_path, wallet_name, options.amtmixdepths - 1,
        wallet_password_stdin=options.wallet_password_stdin,
        gap_limit=options.gaplimit)
    wallet_service = WalletService(wallet)
    if wallet_service.rpc_error:
        sys.exit(EXIT_FAILURE)
    while not wallet_service.synced:
        wallet_service.sync_wallet(fast=not options.recoversync)
    wallet_service.startService()

    orig_tx = wallet_service.get_transaction(hextobin(txid))

    if not orig_tx:
        jlog.error("Could not retrieve the transaction! Maybe it doesn't belong to this wallet?")
        sys.exit(EXIT_FAILURE)

    try:
        bumped_tx = create_bumped_tx(orig_tx, fee_per_kb, wallet, options.output)
    except ValueError as e:
        jmprint(str(e), 'error')
        sys.exit(EXIT_FAILURE)
    except RuntimeWarning as w:
        jmprint(str(w))
        sys.exit(EXIT_SUCCESS)

    # sign the transaction
    if options.with_psbt:
        try:
            psbt = sign_psbt(bumped_tx, orig_tx, wallet_service)

            print("Completed PSBT created: ")
            print(wallet_service.human_readable_psbt(psbt))
            jlog.info("This PSBT is fully signed and can be sent externally for "
                      "broadcasting:")
            jlog.info(psbt.to_base64())
            sys.exit(EXIT_SUCCESS)
        except RuntimeError as e:
            jlog.error(str(e))
            sys.exit(EXIT_FAILURE)
    else:
        try:
            sign_transaction(bumped_tx, orig_tx, wallet_service)
        except RuntimeError as e:
            jlog.error(str(e))
            sys.exit(EXIT_FAILURE)

        jlog.info("Got signed transaction:")
        jlog.info(btc.human_readable_transaction(bumped_tx))

        if not options.answeryes:
            if not cli_prompt_user_yesno(
                    'Would you like to push to the network?'):
                jlog.info("You chose not to broadcast the transaction, quitting.")
                sys.exit(EXIT_SUCCESS)

        if jm_single().bc_interface.pushtx(bumped_tx.serialize()):
            txid = bintohex(bumped_tx.GetTxid()[::-1])
            jlog.info("Transaction sent: " + txid)
        else:
            jlog.error("Transaction broadcast failed!")
            sys.exit(EXIT_FAILURE)

