from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401
from future.utils import iteritems
import logging
import pprint
import os
import time
import numbers
from jmbase import get_log, jmprint
from .configure import jm_single, validate_address
from .schedule import human_readable_schedule_entry, tweak_tumble_schedule,\
    schedule_to_text
from .wallet import BaseWallet, estimate_tx_fee
from jmbitcoin import deserialize, mktx, serialize, txhash, amount_to_str
from jmbase.support import EXIT_SUCCESS
log = get_log()

"""
Utility functions for tumbler-style takers;
Currently re-used by CLI script tumbler.py and joinmarket-qt
"""

def direct_send(wallet_service, amount, mixdepth, destaddr, answeryes=False,
                accept_callback=None, info_callback=None):
    """Send coins directly from one mixdepth to one destination address;
    does not need IRC. Sweep as for normal sendpayment (set amount=0).
    If answeryes is True, callback/command line query is not performed.
    If accept_callback is None, command line input for acceptance is assumed,
    else this callback is called:
    accept_callback:
    ====
    args:
    deserialized tx, destination address, amount in satoshis, fee in satoshis
    returns:
    True if accepted, False if not
    ====
    The info_callback takes one parameter, the information message (when tx is
    pushed), and returns nothing.

    This function returns:
    The txid if transaction is pushed, False otherwise
    """
    #Sanity checks
    assert validate_address(destaddr)[0]
    assert isinstance(mixdepth, numbers.Integral)
    assert mixdepth >= 0
    assert isinstance(amount, numbers.Integral)
    assert amount >=0
    assert isinstance(wallet_service.wallet, BaseWallet)

    from pprint import pformat
    txtype = wallet_service.get_txtype()
    if amount == 0:
        utxos = wallet_service.get_utxos_by_mixdepth()[mixdepth]
        if utxos == {}:
            log.error(
                "There are no utxos in mixdepth: " + str(mixdepth) + ", quitting.")
            return
        total_inputs_val = sum([va['value'] for u, va in iteritems(utxos)])
        fee_est = estimate_tx_fee(len(utxos), 1, txtype=txtype)
        outs = [{"address": destaddr, "value": total_inputs_val - fee_est}]
    else:
        #8 inputs to be conservative
        initial_fee_est = estimate_tx_fee(8,2, txtype=txtype)
        utxos = wallet_service.select_utxos(mixdepth, amount + initial_fee_est)
        if len(utxos) < 8:
            fee_est = estimate_tx_fee(len(utxos), 2, txtype=txtype)
        else:
            fee_est = initial_fee_est
        total_inputs_val = sum([va['value'] for u, va in iteritems(utxos)])
        changeval = total_inputs_val - fee_est - amount
        outs = [{"value": amount, "address": destaddr}]
        change_addr = wallet_service.get_internal_addr(mixdepth)
        outs.append({"value": changeval, "address": change_addr})

    #Now ready to construct transaction
    log.info("Using a fee of : " + amount_to_str(fee_est) + ".")
    if amount != 0:
        log.info("Using a change value of: " + amount_to_str(changeval) + ".")
    txsigned = sign_tx(wallet_service, mktx(list(utxos.keys()), outs), utxos)
    log.info("Got signed transaction:\n")
    log.info(pformat(txsigned))
    tx = serialize(txsigned)
    log.info("In serialized form (for copy-paste):")
    log.info(tx)
    actual_amount = amount if amount != 0 else total_inputs_val - fee_est
    log.info("Sends: " + amount_to_str(actual_amount) + " to address: " + destaddr)
    if not answeryes:
        if not accept_callback:
            if input('Would you like to push to the network? (y/n):')[0] != 'y':
                log.info("You chose not to broadcast the transaction, quitting.")
                return False
        else:
            accepted = accept_callback(pformat(txsigned), destaddr, actual_amount,
                                       fee_est)
            if not accepted:
                return False
    jm_single().bc_interface.pushtx(tx)
    txid = txhash(tx)
    successmsg = "Transaction sent: " + txid
    cb = log.info if not info_callback else info_callback
    cb(successmsg)
    return txid


def sign_tx(wallet_service, tx, utxos):
    stx = deserialize(tx)
    our_inputs = {}
    for index, ins in enumerate(stx['ins']):
        utxo = ins['outpoint']['hash'] + ':' + str(ins['outpoint']['index'])
        script = wallet_service.addr_to_script(utxos[utxo]['address'])
        amount = utxos[utxo]['value']
        our_inputs[index] = (script, amount)
    return wallet_service.sign_tx(stx, our_inputs)

def get_tumble_log(logsdir):
    tumble_log = logging.getLogger('tumbler')
    tumble_log.setLevel(logging.DEBUG)
    logFormatter = logging.Formatter(
        ('%(asctime)s %(message)s'))
    fileHandler = logging.FileHandler(os.path.join(logsdir, 'TUMBLE.log'))
    fileHandler.setFormatter(logFormatter)
    tumble_log.addHandler(fileHandler)
    return tumble_log

def restart_wait(txid):
    """ Returns true only if the transaction txid is seen in the wallet,
    and confirmed (it must be an in-wallet transaction since it always
    spends coins from the wallet).
    """
    try:
        res = jm_single().bc_interface.rpc('gettransaction', [txid, True])
    except JsonRpcError as e:
        return False
    if not res:
        return False
    if "confirmations" not in res:
        log.debug("Malformed gettx result: " + str(res))
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
            #a transaction failed, either because insufficient makers
            #(acording to minimum_makers) responded in Phase 1, or not all
            #makers responded in Phase 2. We'll first try to repeat without the
            #troublemakers.
            log.info("Schedule entry: " + str(
                taker.schedule[taker.schedule_index]) + \
                     " failed after timeout, trying again")
            taker.add_ignored_makers(taker.nonrespondants)
            #Is the failure in Phase 2?
            if not taker.latest_tx is None:
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
                #If enough were, we prefer the restart with them only:
                log.info("Inside a Phase 2 failure; number of honest respondants was: " + str(len(taker.honest_makers)))
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
