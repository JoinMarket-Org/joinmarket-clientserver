import logging
import pprint
import os
import sys
import time
import numbers
from typing import Callable, List, Optional, Tuple, Union

from jmbase import get_log, jmprint, bintohex, hextobin, \
    cli_prompt_user_yesno
from .configure import jm_single, validate_address, is_burn_destination
from .schedule import human_readable_schedule_entry, tweak_tumble_schedule,\
    schedule_to_text
from .wallet import BaseWallet, estimate_tx_fee, compute_tx_locktime, \
    FidelityBondMixin, UnknownAddressForLabel
from .wallet_service import WalletService
from jmbitcoin import make_shuffled_tx, amount_to_str, \
                       PartiallySignedTransaction, CMutableTxOut,\
                       human_readable_transaction
from jmbase.support import EXIT_SUCCESS
log = get_log()

"""
Utility functions for tumbler-style takers;
Currently re-used by CLI script tumbler.py and joinmarket-qt
"""

def get_utxo_scripts(wallet: BaseWallet, utxos: dict) -> list:
    # given a Joinmarket wallet and a set of utxos
    # as passed from `get_utxos_by_mixdepth` at one mixdepth,
    # return the list of script types for each utxo
    script_types = []
    for utxo in utxos.values():
        script_types.append(wallet.get_outtype(utxo["address"]))
    return script_types

def direct_send(wallet_service: WalletService,
                mixdepth: int,
                selected_utxos: List[str],
                dest_and_amounts: List[Tuple[str, int]],
                answeryes: bool = False,
                accept_callback: Optional[Callable[[str, str, int, int, Optional[str]], bool]] = None,
                info_callback: Optional[Callable[[str], None]] = None,
                error_callback: Optional[Callable[[str], None]] = None,
                return_transaction: bool = False,
                with_final_psbt: bool = False,
                optin_rbf: bool = True,
                custom_change_addr: Optional[str] = None,
                change_label: Optional[str] = None) -> Union[bool, str]:
    """Send coins directly from one mixdepth to one or more destination addresses using specific UTXOs;
    does not need IRC. Sweep as for normal sendpayment (set amount=0).
    If answeryes is True, callback/command line query is not performed.
    If optin_rbf is True, the nSequence values are changed as appropriate.
    If accept_callback is None, command line input for acceptance is assumed,
    else this callback is called:
    accept_callback:
    ====
    args:
    deserialized tx, destination address, amount in satoshis,
    fee in satoshis, custom change address, selected UTXOs

    returns:
    True if accepted, False if not
    ====
    info_callback and error_callback take one parameter, the information
    message (when tx is pushed or error occurred), and return nothing.

    This function returns:
    1. False if there is any failure.
    2. The txid if transaction is pushed, and return_transaction is False,
       and with_final_psbt is False.
    3. The full CMutableTransaction if return_transaction is True and
       with_final_psbt is False.
    4. The PSBT object if with_final_psbt is True, and in
       this case the transaction is *NOT* broadcast.
    """
    is_sweep = False
    outtypes = []
    total_outputs_val = 0

    # Sanity checks
    assert isinstance(dest_and_amounts, list)
    assert len(dest_and_amounts) > 0
    assert custom_change_addr is None or validate_address(custom_change_addr)[0]
    assert isinstance(mixdepth, numbers.Integral)
    assert mixdepth >= 0
    assert isinstance(wallet_service.wallet, BaseWallet)

    for target in dest_and_amounts:
        destination = target[0]
        amount = target[1]
        assert validate_address(destination)[0] or \
            is_burn_destination(destination)
        if amount == 0:
            assert custom_change_addr is None and \
                len(dest_and_amounts) == 1
            is_sweep = True
        assert isinstance(amount, numbers.Integral)
        assert amount >= 0
        if is_burn_destination(destination):
            #Additional checks
            if not isinstance(wallet_service.wallet, FidelityBondMixin):
                log.error("Only fidelity bond wallets can burn coins")
                return
            if answeryes:
                log.error("Burning coins not allowed without asking for confirmation")
                return
            if mixdepth != FidelityBondMixin.FIDELITY_BOND_MIXDEPTH:
                log.error("Burning coins only allowed from mixdepth " + str(
                    FidelityBondMixin.FIDELITY_BOND_MIXDEPTH))
                return
            if amount != 0:
                log.error("Only sweeping allowed when burning coins, to keep "
                    "the tx small. Tip: use the coin control feature to "
                    "freeze utxos")
                return
        # if the output is of a script type not currently
        # handled by our wallet code, we can't use information
        # to help us calculate fees, but fall back to default.
        # This is represented by a return value `None`.
        # Note that this does *not* imply we accept any nonstandard
        # output script, because we already called `validate_address`.
        outtypes.append(wallet_service.get_outtype(destination))
        total_outputs_val += amount

    txtype = wallet_service.get_txtype()

    if is_sweep:
        #doing a sweep
        destination = dest_and_amounts[0][0]
        amount = dest_and_amounts[0][1]
        selected_utxo_dict = wallet_service.get_utxos_by_mixdepth()[mixdepth]
        if selected_utxo_dict == {}:
            log.error(
                f"There are no available utxos in mixdepth {mixdepth}, "
                 "quitting.")
            return
        total_inputs_val = sum([va['value'] for u, va in selected_utxo_dict.items()])
        script_types = get_utxo_scripts(wallet_service.wallet, selected_utxo_dict)
        fee_est = estimate_tx_fee(len(selected_utxo_dict), 1, txtype=script_types,
            outtype=outtypes[0])
        outs = [{"address": destination,
                 "value": total_inputs_val - fee_est}]
    else:
        utxos = wallet_service.get_utxos_by_mixdepth().get(mixdepth, {})
        if not utxos:
            log.error(f"There are no available utxos in mixdepth {mixdepth}.")
            return False
        
        # Filter UTXOs based on selected_utxos
        selected_utxo_dict = {}
        for u, va in utxos.items():
            txid = u[0].hex()
            index = u[1]
            utxo_str = f"{txid}:{index}"
            if utxo_str in selected_utxos:
                selected_utxo_dict[(u[0], u[1])] = va
        
        if not selected_utxo_dict:
            log.error("None of the selected UTXOs are available in the specified mixdepth.")
            return False
        
        total_inputs_val = sum([va['value'] for u, va in selected_utxo_dict.items()])
        if total_inputs_val < total_outputs_val:
            log.error("Selected UTXOs do not cover the total output value.")
            return False
        
        if custom_change_addr:
            change_type = wallet_service.get_outtype(custom_change_addr)
            if change_type is None:
                change_type = txtype
        else:
            change_type = txtype
        
        if outtypes[0] is None:
            outtypes[0] = change_type
        outtypes.append(change_type)
        
        fee_est = estimate_tx_fee(len(selected_utxo_dict), len(dest_and_amounts) + 1, txtype=txtype, outtype=outtypes)
        changeval = total_inputs_val - fee_est - total_outputs_val
        
        outs = []
        for out in dest_and_amounts:
            outs.append({"value": out[1], "address": out[0]})
        
        change_addr = wallet_service.get_internal_addr(mixdepth) if custom_change_addr is None else custom_change_addr
        outs.append({"value": changeval, "address": change_addr})
    
    #compute transaction locktime, has special case for spending timelocked coins
    tx_locktime = compute_tx_locktime()
    if mixdepth == FidelityBondMixin.FIDELITY_BOND_MIXDEPTH and isinstance(wallet_service.wallet, FidelityBondMixin):
        for outpoint, utxo in selected_utxo_dict.items():
            path = wallet_service.script_to_path(utxo["script"])
            if not FidelityBondMixin.is_timelocked_path(path):
                continue
            path_locktime = path[-1]
            tx_locktime = max(tx_locktime, path_locktime + 1)
            #compute_tx_locktime() gives a locktime in terms of block height
            #timelocked addresses use unix time instead
            #OP_CHECKLOCKTIMEVERIFY can only compare like with like, so we
            #must use unix time as the transaction locktime

    #Now ready to construct transaction
    log.info("Using a fee of: " + amount_to_str(fee_est) + ".")
    if not is_sweep:
        log.info("Using a change value of: " + amount_to_str(changeval) + ".")
    
    tx = make_shuffled_tx(list(selected_utxo_dict.keys()), outs, version=2, locktime=tx_locktime)

    if optin_rbf:
        for inp in tx.vin:
            inp.nSequence = 0xffffffff - 2

    inscripts = {}
    spent_outs = []
    for i, txinp in enumerate(tx.vin):
        u = (txinp.prevout.hash[::-1], txinp.prevout.n)
        inscripts[i] = (selected_utxo_dict[u]["script"], selected_utxo_dict[u]["value"])
        spent_outs.append(CMutableTxOut(selected_utxo_dict[u]["value"], selected_utxo_dict[u]["script"]))
    
    if with_final_psbt:
        # here we have the PSBTWalletMixin do the signing stage
        # for us:
        new_psbt = wallet_service.create_psbt_from_tx(tx, spent_outs=spent_outs)
        serialized_psbt, err = wallet_service.sign_psbt(new_psbt.serialize())
        if err:
            log.error("Failed to sign PSBT, quitting. Error message: " + err)
            return False
        new_psbt_signed = PartiallySignedTransaction.deserialize(serialized_psbt)
        print("Completed PSBT created: ")
        print(wallet_service.human_readable_psbt(new_psbt_signed))
        return new_psbt_signed
    else:
        success, msg = wallet_service.sign_tx(tx, inscripts)
        if not success:
            log.error("Failed to sign transaction, quitting. Error msg: " + msg)
            return False
        log.info("Got signed transaction:\n")
        log.info(human_readable_transaction(tx))
        actual_amount = sum([out[1] for out in dest_and_amounts])
        sending_info = "Sends: " + amount_to_str(actual_amount) + " to destination: " + ", ".join([out[0] for out in dest_and_amounts])
        if custom_change_addr:
            sending_info += ", custom change to: " + custom_change_addr
        log.info(sending_info)
        if not answeryes:
            if not accept_callback:
                if not cli_prompt_user_yesno('Would you like to push to the network?'):
                    log.info("You chose not to broadcast the transaction, quitting.")
                    return False
            else:
                accepted = accept_callback(human_readable_transaction(tx), dest_and_amounts[0][0], actual_amount, fee_est, custom_change_addr)
                if not accepted:
                    return False
        if change_label:
            try:
                wallet_service.set_address_label(change_addr, change_label)
            except UnknownAddressForLabel:
                pass
        if jm_single().bc_interface.pushtx(tx.serialize()):
            txid = bintohex(tx.GetTxid()[::-1])
            successmsg = "Transaction sent: " + txid
            cb = log.info if not info_callback else info_callback
            cb(successmsg)
            txinfo = txid if not return_transaction else tx
            return txinfo
        else:
            errormsg = "Transaction broadcast failed!"
            cb = log.error if not error_callback else error_callback
            cb(errormsg)
            return False

def get_tumble_log(logsdir):
    tumble_log = logging.getLogger('tumbler')
    tumble_log.setLevel(logging.DEBUG)
    logFormatter = logging.Formatter(
        ('%(asctime)s %(message)s'))
    fileHandler = logging.FileHandler(os.path.join(logsdir, 'TUMBLE.log'))
    fileHandler.setFormatter(logFormatter)
    tumble_log.addHandler(fileHandler)
    return tumble_log

def get_total_tumble_amount(mixdepth_balance_dict, schedule):
    # calculating total coins that will be included in a tumble;
    # in almost all cases all coins (unfrozen) in wallet will be tumbled,
    # though it's technically possible with a very small mixdepthcount, to start
    # at say m0, and only go through to 2 or 3, such that coins in 4 are untouched
    # in phase 2 (after having been swept in phase 1).
    used_mixdepths = set()
    [used_mixdepths.add(x[0]) for x in schedule]
    total_tumble_amount = int(0)
    for i in used_mixdepths:
        total_tumble_amount += mixdepth_balance_dict[i]
    # Note; we assert since callers will have called `get_tumble_schedule`,
    # which will already have thrown if no funds, so this would be a logic error.
    assert total_tumble_amount > 0, "no coins to tumble."
    return total_tumble_amount

def restart_wait(txid):
    """ Returns true only if the transaction txid is seen in the wallet,
    and confirmed (it must be an in-wallet transaction since it always
    spends coins from the wallet).
    """
    res = jm_single().bc_interface.get_transaction(hextobin(txid))
    if not res:
        return False
    if res["confirmations"] == 0:
        return False
    if res["confirmations"] < 0:
        log.warn("Tx: " + txid + " has a conflict, abandoning.")
        sys.exit(EXIT_SUCCESS)
    else:
        log.debug("Tx: " + str(txid) + " has " + str(
                res["confirmations"]) + " confirmations.")
        return True

def restart_waiter(txid):
    """Given a txid, wait for confirmation by polling the blockchain
    interface instance. Note that this is currently blocking, so only used
    by the CLI version; the Qt/GUI uses the underlying restart_wait() fn.
    """
    ctr = 0
    log.info("Waiting for confirmation of last transaction: " + str(txid))
    while True:
        time.sleep(10)
        ctr += 1
        if not (ctr % 12):
            log.debug("Still waiting for confirmation of last transaction ...")
        if restart_wait(txid):
            break
    log.info("The previous transaction is now in a block; continuing.")

def unconf_update(taker, schedulefile, tumble_log, addtolog=False):
    """Provide a Taker object, a schedulefile path for the current
    schedule, a logging instance for TUMBLE.log, and a parameter
    for whether to update TUMBLE.log.
    Makes the necessary state updates explained below, including to
    the wallet.
    Note that this is re-used for confirmation with addtolog=False,
    to avoid a repeated entry in the log.
    """
    #on taker side, cache index update is only required after tx
    #push, to avoid potential of address reuse in case of a crash,
    #because addresses are not public until broadcast (whereas for makers,
    #they are public *during* negotiation). So updating the cache here
    #is sufficient
    taker.wallet_service.save_wallet()

    #If honest-only was set, and we are going to continue (e.g. Tumbler),
    #we switch off the honest-only filter. We also wipe the honest maker
    #list, because the intention is to isolate the source of liquidity
    #to exactly those that participated, in 1 transaction (i.e. it's a 1
    #transaction feature). This code is here because it *must* be called
    #before any continuation, even if confirm_callback happens before
    #unconfirm_callback
    taker.set_honest_only(False)
    taker.honest_makers = []

    #We persist the fact that the transaction is complete to the
    #schedule file. Note that if a tweak to the schedule occurred,
    #it only affects future (non-complete) transactions, so the final
    #full record should always be accurate; but TUMBLE.log should be
    #used for checking what actually happened.
    completion_flag = 1 if not addtolog else taker.txid
    taker.schedule[taker.schedule_index][-1] = completion_flag
    with open(schedulefile, "wb") as f:
        f.write(schedule_to_text(taker.schedule))

    if addtolog:
        tumble_log.info("Completed successfully this entry:")
        #the log output depends on if it's to INTERNAL
        hrdestn = None
        if taker.schedule[taker.schedule_index][3] in ["INTERNAL", "addrask"]:
            hrdestn = taker.my_cj_addr
        #Whether sweep or not, the amt is not in satoshis; use taker data
        hramt = taker.cjamount
        tumble_log.info(human_readable_schedule_entry(
            taker.schedule[taker.schedule_index], hramt, hrdestn))
        tumble_log.info("Txid was: " + taker.txid)

def tumbler_taker_finished_update(taker, schedulefile, tumble_log, options,
                   res, fromtx=False, waittime=0.0, txdetails=None):
    """on_finished_callback processing for tumbler.
    Note that this is *not* the full callback, but provides common
    processing across command line and other GUI versions.
    """

    if fromtx == "unconfirmed":
        #unconfirmed event means transaction has been propagated,
        #we update state to prevent accidentally re-creating it in
        #any crash/restart condition
        unconf_update(taker, schedulefile, tumble_log, True)
        return

    if fromtx:
        if res:
            #this has no effect except in the rare case that confirmation
            #is immediate; also it does not repeat the log entry.
            unconf_update(taker, schedulefile, tumble_log, False)
            #note that Qt does not yet support 'addrask', so this is only
            #for command line script TODO
            if taker.schedule[taker.schedule_index+1][3] == 'addrask':
                jm_single().debug_silence[0] = True
                jmprint('\n'.join(['=' * 60] * 3))
                jmprint('Tumbler requires more addresses to stop amount correlation')
                jmprint('Obtain a new destination address from your bitcoin recipient')
                jmprint(' for example click the button that gives a new deposit address')
                jmprint('\n'.join(['=' * 60] * 1))
                while True:
                    destaddr = input('insert new address: ')
                    addr_valid, errormsg = validate_address(destaddr)
                    if addr_valid:
                        break
                    jmprint(
                    'Address ' + destaddr + ' invalid. ' + errormsg + ' try again',
                    "warning")
                jm_single().debug_silence[0] = False
                taker.schedule[taker.schedule_index+1][3] = destaddr
                taker.tdestaddrs.append(destaddr)

            waiting_message = "Waiting for: " + str(waittime) + " minutes."
            tumble_log.info(waiting_message)
            log.info(waiting_message)
        else:
            # a transaction failed, either because insufficient makers
            # (acording to minimum_makers) responded in Phase 1, or not all
            # makers responded in Phase 2, or the tx was a mempool conflict.
            # If the tx was a mempool conflict, we should restart with random
            # maker choice as usual. If someone didn't respond, we'll try to
            # repeat without the troublemakers.
            log.info("Schedule entry: " + str(
                taker.schedule[taker.schedule_index]) + \
                     " failed after timeout, trying again")
            taker.add_ignored_makers(taker.nonrespondants)
            #Is the failure in Phase 2?
            if not taker.latest_tx is None:
                if len(taker.nonrespondants) == 0:
                    # transaction was created validly but conflicted in the
                    # mempool; just try again without honest settings;
                    # i.e. fallback to same as Phase 1 failure.
                    log.info("Invalid transaction; possible mempool conflict.")
                else:
                    #Now we have to set the specific group we want to use, and hopefully
                    #they will respond again as they showed honesty last time.
                    #Note that we must wipe the list first; other honest makers needn't
                    #have the right settings (e.g. max cjamount), so can't be carried
                    #over from earlier transactions.
                    taker.honest_makers = []
                    taker.add_honest_makers(list(set(
                        taker.maker_utxo_data.keys()).symmetric_difference(
                            set(taker.nonrespondants))))
                    #If insufficient makers were honest, we can only tweak the schedule.
                    #If enough were, we prefer to restart with them only:
                    log.info("Inside a Phase 2 failure; number of honest "
                             "respondants was: " + str(len(taker.honest_makers)))
                    log.info("They were: " + str(taker.honest_makers))
                    if len(taker.honest_makers) >= jm_single().config.getint(
                        "POLICY", "minimum_makers"):
                        tumble_log.info("Transaction attempt failed, attempting to "
                                        "restart with subset.")
                        tumble_log.info("The paramaters of the failed attempt: ")
                        tumble_log.info(str(taker.schedule[taker.schedule_index]))
                        #we must reset the number of counterparties, as well as fix who they
                        #are; this is because the number is used to e.g. calculate fees.
                        #cleanest way is to reset the number in the schedule before restart.
                        taker.schedule[taker.schedule_index][2] = len(taker.honest_makers)
                        retry_str = "Retrying with: " + str(taker.schedule[
                            taker.schedule_index][2]) + " counterparties."
                        tumble_log.info(retry_str)
                        log.info(retry_str)
                        taker.set_honest_only(True)
                        taker.schedule_index -= 1
                        return

            #There were not enough honest counterparties.
            #Tumbler is aggressive in trying to complete; we tweak the schedule
            #from this point in the mixdepth, then try again.
            tumble_log.info("Transaction attempt failed, tweaking schedule"
                            " and trying again.")
            tumble_log.info("The paramaters of the failed attempt: ")
            tumble_log.info(str(taker.schedule[taker.schedule_index]))
            taker.schedule_index -= 1
            taker.schedule = tweak_tumble_schedule(options, taker.schedule,
                                                   taker.schedule_index,
                                                   taker.tdestaddrs)
            tumble_log.info("We tweaked the schedule, the new schedule is:")
            tumble_log.info(pprint.pformat(taker.schedule))
    else:
        if not res:
            failure_msg = "Did not complete successfully, shutting down"
            tumble_log.info(failure_msg)
            log.info(failure_msg)
        else:
            log.info("All transactions completed correctly")
            tumble_log.info("Completed successfully the last entry:")
            #Whether sweep or not, the amt is not in satoshis; use taker data
            hramt = taker.cjamount
            tumble_log.info(human_readable_schedule_entry(
                taker.schedule[taker.schedule_index], hramt))
            #copy of above, TODO refactor out
            taker.schedule[taker.schedule_index][5] = 1
            with open(schedulefile, "wb") as f:
                f.write(schedule_to_text(taker.schedule))


def tumbler_filter_orders_callback(orders_fees, cjamount, taker):
    """Since the tumbler does not use interactive fee checking,
    we use the -x values from the command line instead.
    """
    orders, total_cj_fee = orders_fees
    abs_cj_fee = 1.0 * total_cj_fee / taker.n_counterparties
    rel_cj_fee = abs_cj_fee / cjamount
    log.info('rel/abs average fee = ' + str(rel_cj_fee) + ' / ' + str(
            abs_cj_fee))

    if rel_cj_fee > taker.max_cj_fee[0] and abs_cj_fee > taker.max_cj_fee[1]:
        log.info("Rejected fees as too high according to options, will "
                 "retry.")
        return "retry"
    return True
