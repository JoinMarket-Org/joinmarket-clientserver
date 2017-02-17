from __future__ import absolute_import, print_function
from jmclient import schedule_to_text, human_readable_schedule_entry
import logging
import pprint
import os
import time
from .configure import get_log, jm_single, validate_address
from .schedule import human_readable_schedule_entry, tweak_tumble_schedule

log = get_log()

"""
Utility functions for tumbler-style takers;
Currently re-used by CLI script tumbler.py and joinmarket-qt
"""

def get_tumble_log(logsdir):
    tumble_log = logging.getLogger('tumbler')
    tumble_log.setLevel(logging.DEBUG)
    logFormatter = logging.Formatter(
        ('%(asctime)s %(message)s'))
    fileHandler = logging.FileHandler(os.path.join(logsdir, 'TUMBLE.log'))
    fileHandler.setFormatter(logFormatter)
    tumble_log.addHandler(fileHandler)
    return tumble_log

def restart_waiter(txid):
    """Given a txid, wait for confirmation by polling the blockchain
    interface instance. Note that this is currently blocking, which is
    fine for the CLI for now, but should be re-done using twisted/thread TODO.
    """
    ctr = 0
    log.info("Waiting for confirmation of last transaction: " + str(txid))
    while True:
        time.sleep(10)
        ctr += 1
        if not (ctr % 12):
            log.debug("Still waiting for confirmation of last transaction ...")
        res = jm_single().bc_interface.query_utxo_set(txid, includeconf=True)
        if not res[0]:
            continue
        if res[0]['confirms'] > 0:
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
                                                   taker.schedule_index)
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
