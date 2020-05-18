## Running the tumbler

Assuming installation has been done correctly, running the `tumbler.py` script in the `scripts/` directory is almost the same as that in the [original codebase](https://github.com/Joinmarket-Org/joinmarket).

As a reminder, the explanation of the principal details of how to do this are in [the wiki](https://github.com/JoinMarket-Org/joinmarket/wiki/Step-by-step-running-the-tumbler).

This document explains the delta to the operation of that script, which is almost entirely additions, and gives some tips on how to monitor and make use of the extra features, which are *mostly* aimed at making the tumbler more reliable/robust.

#### Schedules

In this implementation, each coinjoin has an associated "schedule" of format like this:

```
[mixdepth, amount-fraction, N-counterparties (requested), destination address, wait time in minutes, rounding, flag indicating incomplete/broadcast/completed (0/txid/1)]
```

`[]` here represents a Python list. It's recorded in files in a csv format (because in some cases users may edit). See [this](https://github.com/AdamISZ/joinmarket-clientserver/blob/master/scripts/sample-schedule-for-testnet) testnet sample given in the repo. A couple of extra notes on the format:

* the 4th entry, the destination address, can have special values "INTERNAL" and "addrask"; the former indicates that the coins are to be sent to the "next" mixdepth, modulo the maximum mixdepth. The latter is the same function as in the original implementation, i.e. it takes a destination from those provided by the user, either in the initial command line or on a prompt during the run.

* the 2nd entry, amount fraction, is a decimal between 0 and 1; *this is specific to the tumbler*; for sendpayment, this amount is an integer in satoshis.

* 0 amounts for the second entry indicate, as for command line flags, a sweep; decimals indicate mixdepth fractions (for tumbler)

* the 6th entry, `rounding`, is how many significant figures to round the coinjoin amount to. For example a rounding of `2` means that `0.12498733` will be rounded to `0.1200000`. A rounding value of `16` means no rounding. Sweep coinjoin amounts are never rounded.

For the `sendpayment.py` script, this schedule can indeed be simply written in a file and passed as a parameter (for this reason it's likely the tumbler and sendpayment scripts can merge in future).

As you can imagine, the idea for the `tumbler.py` script is simply that a tumbler *schedule* is generated, according to the same algorithm that was used in the original implementation ([code](https://github.com/AdamISZ/joinmarket-clientserver/blob/master/jmclient/jmclient/schedule.py#L61-L133)), however here it is persisted - see the next section.

#### Tumbler schedule and logging

Two new log files are introduced in this implementation, to help tracking the progress of the tumble, and to allow restarts. The first is by default `logs/TUMBLE.schedule` but its name can be changed with the new `--schedulefile` option. In this, the schedule that is generated on startup, according to the user command line options (such as -N for counterparties, -M for mixdepths etc.) is recorded, and updated as each transaction is seen on the network - in particular what is updated is the above-mentioned 'completed' flag, as well as the destination addresses for the user destinations (replacing 'addrask'). So by opening it at any time you can see a condensed view of the current state (note in particular '1' or '0' for the final entry; '1' means the transaction is done). The *main* purpose of this file is to allow restarts, see the section on "Restarts" below. Thus, **don't edit or delete this file until the tumble run is fully completed**.

However, another file is more specifically intended to help tracking: currently hardcoded as `logs/TUMBLE.log`, it will show: transaction times, txids, destination addresses, and also any instances of failures and re-attempts. This is not used for restarting, so can be deleted at any time (it's a standard log file and operates in append by default for multiple runs).


#### Interpreting key console output

At regular intervals you'll see one of these messages:

```
timestamp [MainThread  ] [INFO ]  STALL MONITOR:
timestamp [MainThread  ] [INFO ]  No stall detected, continuing
```

```
timestamp [MainThread  ] [INFO ]  STALL MONITOR:
timestamp [MainThread  ] [INFO ]  Tx was already pushed; ignoring
```

Both of these represent the program recognizing that nothing has gone wrong with a previous transaction (not necessarily the one in process), and can occur at any time; these mean the transaction was processed OK, and can be ignored. If you see this:

```
timestamp [MainThread  ] [INFO ]  STALL MONITOR:
timestamp [MainThread  ] [INFO ]  Stall detected. Regenerating transactions and retrying.
```

it means the current transaction has failed for some reason, and you will a little further on see a message indicating the parameters of the failed schedule entry, which will then be tweaked and retried. See below on "tweaking".

Another important output you'll sometimes see in the console is the same information that is printed to `commitments_debug.txt` in the case of commitment sourcing failure, like:

```
1: Utxos that passed age and size limits, but have been used too many times (see taker_utxo_retries in the config):
None
2: Utxos that have less than 5 confirmations:
3a001fa0272df5c43c2c38d91d1f784b4ba18c18043355b88c7c713dd3ecc78c:5
...
```

If the tumbler continues to run after this (re: if it doesn't, see the section on failure/crash vectors below), you need do nothing; usually, you will see the "regenerating transactions" message after a while, and it will try again until (a) the utxos have got old enough (5 confirms), or (b) in rare cases, you will have to wait until the amount is right (20% rule), which depends on "tweaking", see the next section.

```
Makers didn't respond
```
This will happen when aberrant makers don't complete the protocol (or strictly, when not enough of them do). As above, simply wait for regenerate-after-tweak occurs.

#### Tweaking the schedule

In case of a single transaction failing, the tumbler is going to aggressively try to continue. This is similar but also a bit different from what happened in the original implementation. After a "Stall detected" message like the one above, the *current schedule entry* will be tweaked, in one of two ways:

* For non-sweeps, the amount fraction (recorded in the schedule as the second entry, a decimal) will be altered, as well as all the succeeding amount fractions in that mixdepth, done in such a way as to preserve the overall distribution of the original schedule. However, the N (number of counterparties) is *not* changed, remembering that we leverage a fallback to `minimum_makers` in case of non-response, so a higher N is always better for reliability. Tweaking the amount fraction can help by changing what liquidity your tumbler perceives, but also sometimes by changing what PoDLE commitments are valid (remembering the 20% rule).

* For sweeps, the amount cannot change, but on the other hand we can bump the success rate by reducing N (for sweeps fallback is not possible).

This tweaking process is repeated as many times as necessary until the transaction goes through. One case in which repetition several times is likely: if you set a low value of `-l` (the time wait parameter), you may quite often not have any PoDLE commitments of sufficient age, and so will have to wait for 5 confirmations; in this case it will just keep retrying until that's true. (Note! Utxo commitments which are too young do not get used up; your own bot recognizes this and doesn't broadcast them until they're valid).

##### How often do retries occur?

This is hardcoded currently to `20 * maker_timeout_sec`, the figure 20 being hardcoded is due to me not wanting yet another config variable, although that could be done of course. This is the rate at which the stall monitor wakes up in the client protocol, the setting is in the code [here](https://github.com/AdamISZ/joinmarket-clientserver/blob/master/jmclient/jmclient/client_protocol.py#L87). Note that by default this is fairly slow, 10 minutes.

#### Restarts

In case of shutdown or crash, the `TUMBLE.schedule` file mentioned above will have an up-to-date record of which transactions in the schedule completed successfully; and you can find the txids, for convenience, in `TUMBLE.log` to sanity check (of course you may want to run `wallet-tool.py` also, which is fine). By restarting the tumbler script with the same parameters, but appending an additional parameter `--restart`, the script will continue the tumble from the first not-successfully-completed transaction and continue (it will wait for confirmations on the last transaction, if it's not yet in a block). If you used a custom name for `TUMBLE.schedule`, or renamed it afterwards, don't forget to also pass the parameter `--schedulefile` so it can be found; note that these files are always assumed to be in the `logs/` subdirectory of where you're running (so `scripts/logs` here). (A small technical note: on restart, the `TUMBLE.schedule` is truncated in that the txs that already completed will be removed, something that should probably change, but all the info is logged in `TUMBLE.log`, which you should use as your primary record of what happened and when).

Minor note, you could conceivably edit `TUMBLE.schedule` before restarting, but this would have to be considered "advanced" usage!

This can of course be implemented in, say, a shell script (just add --restart to all re-runs except the first), although I haven't tried that out.

#### Possible failure vectors - crash or shutdown

* **Failure to source commitment** - if there is no *unused* PoDLE commitment available, the script terminates as even with tweaks this condition will not change. This *could* be changed to allow dynamic update of the `commitments.json` file (adding external utxos), but I didn't judge that to be the right choice for now. On the other hand, as was noted above, if the commitments are simply too young, the script will keep tweaking and retrying. I recommend using the `add-utxo.py` script to prepare external commitments in advance of the run for more robustness, although it shouldn't be necessary for success.
* **Network errors** - this is the biggest unknown for now; since this has not been tested in a sufficiently wide variety of network conditions, it's possible that the IRC reconnection fails in case of drop, or perhaps even crashes.
* **Insufficient liquidity**. This is a tricky one - particulary for sweeps, if the number of potential counterparties is low, and if some of them are deliberately non-responsive, you may run out of counterparties. Currently the script will simply keep retrying indefinitely. **Use a reasonably high -N value** - I think going much below 5 is starting to introduce risk, so values like `-N 6 1` should be OK, but `-N 3 1` is dubious. Force-quitting after a very long timeout is conceivable, but obviously a slightly tricky/impractical proposition.

Note that various other failure vectors will not actually cause a problem, such as the infamous "txn-mempool-conflict"; tweaking handles these cases.

