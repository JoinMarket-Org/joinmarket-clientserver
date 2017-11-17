from __future__ import absolute_import, print_function
from jmclient import schedule_to_text, human_readable_schedule_entry
import logging
import pprint
import os
import time
import numbers
from .configure import get_log, jm_single, validate_address
from .schedule import human_readable_schedule_entry, tweak_tumble_schedule
from .wallet import Wallet, SegwitWallet, estimate_tx_fee
from jmclient import mktx, deserialize, sign, txhash
log = get_log()

"""
Utility functions for tumbler-style takers;
Currently re-used by CLI script tumbler.py and joinmarket-qt
"""

def direct_send(wallet, amount, mixdepth, destaddr, answeryes=False,
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
    assert isinstance(mixdepth, int)
    assert mixdepth >= 0
    assert isinstance(amount, numbers.Integral)
    assert amount >=0
    assert isinstance(wallet, Wallet) or isinstance(wallet, SegwitWallet)

    from pprint import pformat
    txtype = 'p2sh-p2wpkh' if isinstance(wallet, SegwitWallet) else 'p2pkh'
    if amount == 0:
        utxos = wallet.get_utxos_by_mixdepth()[mixdepth]
        if utxos == {}:
            log.error(
                "There are no utxos in mixdepth: " + str(mixdepth) + ", quitting.")
            return
        total_inputs_val = sum([va['value'] for u, va in utxos.iteritems()])
        fee_est = estimate_tx_fee(len(utxos), 1, txtype=txtype)
        outs = [{"address": destaddr, "value": total_inputs_val - fee_est}]
    else:
        #8 inputs to be conservative
        initial_fee_est = estimate_tx_fee(8,2, txtype=txtype)
        utxos = wallet.select_utxos(mixdepth, amount + initial_fee_est)
        if len(utxos) < 8:
            fee_est = estimate_tx_fee(len(utxos), 2, txtype=txtype)
        else:
            fee_est = initial_fee_est
        total_inputs_val = sum([va['value'] for u, va in utxos.iteritems()])
        changeval = total_inputs_val - fee_est - amount
        outs = [{"value": amount, "address": destaddr}]
        change_addr = wallet.get_internal_addr(mixdepth)
        outs.append({"value": changeval, "address": change_addr})

    #Now ready to construct transaction
    log.info("Using a fee of : " + str(fee_est) + " satoshis.")
    if amount != 0:
        log.info("Using a change value of: " + str(changeval) + " satoshis.")
    tx = mktx(utxos.keys(), outs)
    stx = deserialize(tx)
    for index, ins in enumerate(stx['ins']):
        utxo = ins['outpoint']['hash'] + ':' + str(
                ins['outpoint']['index'])
        addr = utxos[utxo]['address']
        signing_amount = utxos[utxo]['value']
        amt = signing_amount if isinstance(wallet, SegwitWallet) else None
        tx = sign(tx, index, wallet.get_key_from_addr(addr), amount=amt)
    txsigned = deserialize(tx)
    log.info("Got signed transaction:\n")
    log.info(tx + "\n")
    log.info(pformat(txsigned))
    actual_amount = amount if amount != 0 else total_inputs_val - fee_est
    log.info("Sends: " + str(actual_amount) + " satoshis to address: " + destaddr)
    if not answeryes:
        if not accept_callback:
            if raw_input('Would you like to push to the network? (y/n):')[0] != 'y':
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
    """Here txid is of form txid:N for direct utxo query.
    Returns true only if the utxo is reported to have at least 1
    confirm by the blockchain interface.
    """
    res = jm_single().bc_interface.query_utxo_set(txid, includeconf=True)
    if not res[0]:
        return False
    if res[0]['confirms'] > 0:
        return True
    return False

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
    taker.wallet.update_cache_index()

    #We persist the fact that the transaction is complete to the
    #schedule file. Note that if a tweak to the schedule occurred,
    #it only affects future (non-complete) transactions, so the final
    #full record should always be accurate; but TUMBLE.log should be
    #used for checking what actually happened.
    completion_flag = 1 if not addtolog else taker.txid
    taker.schedule[taker.schedule_index][5] = completion_flag
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
                print('\n'.join(['=' * 60] * 3))
                print('Tumbler requires more addresses to stop amount correlation')
                print('Obtain a new destination address from your bitcoin recipient')
                print(' for example click the button that gives a new deposit address')
                print('\n'.join(['=' * 60] * 1))
                while True:
                    destaddr = raw_input('insert new address: ')
                    addr_valid, errormsg = validate_address(destaddr)
                    if addr_valid:
                        break
                    print(
                    'Address ' + destaddr + ' invalid. ' + errormsg + ' try again')
                jm_single().debug_silence[0] = False
                taker.schedule[taker.schedule_index+1][3] = destaddr
                taker.tdestaddrs.append(destaddr)

            waiting_message = "Waiting for: " + str(waittime) + " minutes."
            tumble_log.info(waiting_message)
            log.info(waiting_message)
            txd, txid = txdetails
            taker.wallet.remove_old_utxos(txd)
            taker.wallet.add_new_utxos(txd, txid)
        else:
            #a transaction failed; tumbler is aggressive in trying to
            #complete; we tweak the schedule from this point in the mixdepth,
            #then try again:
            tumble_log.info("Transaction attempt failed, tweaking schedule"
                            " and trying again.")
            tumble_log.info("The paramaters of the failed attempt: ")
            tumble_log.info(str(taker.schedule[taker.schedule_index]))
            log.info("Schedule entry: " + str(
                taker.schedule[taker.schedule_index]) + \
                     " failed after timeout, trying again")
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

def tumbler_filter_orders_callback(orders_fees, cjamount, taker, options):
    """Since the tumbler does not use interactive fee checking,
    we use the -x values from the command line instead.
    """
    orders, total_cj_fee = orders_fees
    abs_cj_fee = 1.0 * total_cj_fee / taker.n_counterparties
    rel_cj_fee = abs_cj_fee / cjamount
    log.info('rel/abs average fee = ' + str(rel_cj_fee) + ' / ' + str(
            abs_cj_fee))

    if rel_cj_fee > options['maxcjfee'][
        0] and abs_cj_fee > options['maxcjfee'][1]:
        log.info("Rejected fees as too high according to options, will retry.")
        return "retry"
    return True
