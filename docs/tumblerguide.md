## Running the tumbler.

Note that the tumbler can be run as a script:

```
(jmvenv)a@~/joinmarket-clientserver/scripts$ python tumbler.py --help
```

or from the JoinmarketQt app in the "Multiple Joins" tab (see [the guide](JOINMARKET-QT-GUIDE.md)),

or using the RPC-API via a webapp like [JAM](https://github.com/joinmarket-webui/joinmarket-webui).

# Contents

1. [Introduction to the tumbler](#introduction)

   a. [A note on fees](#a-note-on-fees)

2. [How it works - the algorithm](#algo)

   a. [Example 1](#example1)

   b. [Example 2](#example2)

4. [Schedules (transaction lists)](#schedules)

5. [Tumbler schedule and logging](#logging)

6. [Interpreting key console output](#interpreting)

7. [Tweaking the schedule](#tweaking)


8. [Possible failure vectors](#failure-vectors)

<a name="introduction" />

## Introduction to the tumbler

Tumbler is a JoinMarket bot which attempts to completely break the link between addresses. It is used to restore privacy where it has been damaged. It creates many many coinjoins to bounce coins around in different amounts and times. The purpose of this is to help human beings preserve their security and dignity; the reason for doing this is the same as the reason for not broadcasting live camera feeds of every room inside your house.

Having said that, there is a lot of subtlety around *how* to use tools like this to upgrade privacy - neither Joinmarket generally, nor the "tumbler algorithm" presented here are a panacea. Think about how you're using it.

<a name="a-note-on-fees" />

### A note on fees

Because coinjoin transactions are larger than "normal" Bitcoin transactions, mining fees can get as high (or higher) as 0.002-0.004 BTC in times of high fees (estimate based on 4kB transaction, 50-100 sats/vbyte). Hence for 10 transactions, which is a realistic number when using default parameters and three destination addresses, you could end up paying tens or even hundreds(!) of dollars just in Bitcoin transaction fees. Coinjoin fees are most likely negligible compared to this.

That $50 total mining fee (example figure) is independent of the amount of bitcoin you are tumbling, so you have to consider whether it will be worth it for amounts much smaller than, say, $500 (10% fee!). Note that you can pay smaller bitcoin mining fees by setting the field `tx_fees` in the `joinmarket.cfg` (see both the [usage guide](USAGE.md#fee-settings) and the comments in `joinmarket.cfg`). This can of course slow things down - which may not be a bad thing.

For much larger amounts (~$1000+ in value) on the other hand, the balance shifts significantly and the coinjoin fees will tend to become more important. However, there are enough bots with fixed-size fees and ultra-low percentage fees and you will probably find that the fee won't be an issue. Paying less than 1% fee for the whole run would be normal in this case.

Of course, the above doesn't really apply in very low fee regimes, but the principle that "tumbler represents of the order of 100 one-in-one-out transactions", still applies.

**TLDR: Pay attention to fees, especially if fees on the network are high, it may be worth avoiding using the tumbler in this case.**

<a name="algo" />

## How it works - the algorithm

The basic concepts:

First, we need multiple destination addresses; the default is 3, but you can go higher. Why? Because there's no point trying to "mix" 3.754 BTC through a bunch of transactions, if the entire amount ends up in the same place (minus fees; these are usually nontrivial but that's not good enough to break the link).

Second, we need to add randomized delays to spread these transactions out over a *significant* time. This is not really optional; even if Joinmarket had 10 times the volume it has today, it'd still be the case that if you do all these transactions over a period of 5-10 blocks, it would be very obvious and stand out like a sore thumb. You want these transactions to be *some* of the Joinmarket transactions over the period, not all of them! (If Joinmarket had 1000x the volume per unit time, then perhaps you could do this quickly, but Bitcoin cannot even support that!).

So now, in outline, how the tumbler works. The basic idea is to move the coins from one mixdepth to another, in sequence, but (usually) in multiple transactions, and always emptying fully each mixdepth, at the end (i.e. using "sweeps", coinjoins with no leftover change outputs). The best way to understand the process, is by example.

<a name="example1" />

### Example 1. Three utxos in mixdepth 0 (each 1BTC), 4 mixdepths, 9 counterparties, 3 transactions per mixdepth, 3 destination addresses A, B, C.

This is the simplest setup, pretty much default according to recommendations. Notice here we specifically mean that mixdepths 1,2,3,4 all start out empty.

Phase 1: The coins in mixdepth 0 will be moved in a sweep, to mixdepth 1. No change is behind; the full amount *after* fees (let's say, 2.99 BTC) will arrive in an "internal" address in mixdepth 1. Of course the point is that there will be 9 exactly identical 2.99 BTC utxos in the transaction output; only one is yours.

Phase 2:
* There will now be 3 transactions from mixdepth 1 to mixdepth 2. The last will be a sweep (also to mixdepth 2).
* Then, 3 transactions from mixdepth 2. The first two will go to mixdepth 3, the last (a sweep) will be to destination address A
* Then, 3 transactions from mixdepth 3. The first two will go to mixdepth 4, the last (a sweep) will be to destination address B.
* Then, *one* transaction from mixdepth 4, to the final destination address C.

Here is what an example of that looks like, as a schedule, generated by Joinmarket's code (the addresses are testnet):

```
0,0,9,INTERNAL,0.02,16,0
1,0.07158886670804065,9,INTERNAL,0.15,16,0
1,0.3104360747679161,9,INTERNAL,0.25,16,0
1,0,9,INTERNAL,0.41,16,0
2,0.28860335923421476,9,INTERNAL,0.31,16,0
2,0.17728531788154556,9,INTERNAL,0.04,16,0
2,0,9,mzzAYbtPpANxpNVGCVBAhZYzrxyZtoix7i,0.05,16,0
3,0.1593149311659825,9,INTERNAL,0.05,16,0
3,0.5469121480293317,9,INTERNAL,0.08,16,0
3,0,9,mifCWfmygxKhsP3qM3HZi3ZjBEJu7m39h8,0.04,16,0
4,0,9,mnTn9KVQQT9zy9R4E2ZGzWPK4EfcEcV9Y5,0.07,16,0
```

To understand the term 'schedule' here and the meaning of the above list, see [Schedules](#schedules) below.

Note a point of confusion re: counting "number of mixdepths 4" here means 4 mixdepths are used in Phase 2, so we start from 1 and end in 4. Also notice, the last mixdepth is always different in that there is only one sweep to one of the final destination addresses.

Number of counterparties: controlled with `-N` on the command line, this defaults to `9 1` which means 9 with a standard deviation of 1 (so usually 8-10); this is probably best left at defaults, though you can go a little lower, or experiment with significantly higher (especially with the new message channels as of 2022), if the fees as discussed above don't cause a problem.

Amounts and times: these are both randomized. You can't control how much goes to which of the different destination addresses, using the algorithm, and also the time delays between each transaction are randomized. See the options on CLI or the tumbler 'wizard' in the Qt app for how to control the *average* time. Note that for privacy, longer time waits are almost always better. Expect this process to take up hours or days, that is how it is intended to be used.

<a name="example2" />

### Example 2. Two utxos in mixdepth 2 (each 1BTC), one utxo in mixdepth 4, 8 mixdepths, 9 counterparties, 4 transactions per mixdepth, 4 destination addresses A, B, C, D.
<a name="basic" />

First, note you can use more than 3 destination addresses (and it's good to do so), if you're mixing through more than the default 4 mixdepths.
Second, note that the tumbler algorithm as of [this commit](ADD_LINK_HERE), now **cycles** through the default 5 mixdepths, instead of creating extra ones. This means that the mixdepth path goes as follows:

Phase 1:
* Sweep from mixdepth 2 to mixdepth 3
* Sweep from mixdepth 4 to mixdepth 0

Phase 2:
Starting mixdepth is 0 because that is the lowest non-empty *after* Phase 1. Then, the sequence is (0->1, 1->2, 2->3, 3->4, 4->0, 0->1, 1->2). The final transaction will sweep from mixdepth 2 to the final destination address.

The multiple uses of the same mixdepth do not "step on each other's toes", for two reasons: one, Joinmarket never reuses an address, and two, we always sweep (and therefore entirely clean out) each mixdepth as we go through it.

Doing things this way is cleaner: we keep to a fixed number of mixdepths/accounts in the wallet, even if we want to do a very large run of the tumbler algo.

Here is a test example schedule with those parameters:

```
4,0,9,INTERNAL,0.22,16,0
2,0,9,INTERNAL,1.25,16,0
0,0.1287547602736554,9,INTERNAL,0.34,16,0
0,0.33777065308789445,9,INTERNAL,0.12,16,0
0,0.2416658618765749,9,INTERNAL,0.05,16,0
0,0,9,INTERNAL,0.23,16,0
1,0.4248409290648639,9,INTERNAL,0.01,16,0
1,0.33866158339454555,9,INTERNAL,0.02,4,0
1,0.010807366510609207,9,INTERNAL,0.13,16,0
1,0,9,INTERNAL,0.11,16,0
2,0.04086022411519208,9,INTERNAL,0.82,16,0
2,0.20924362829352816,9,INTERNAL,0.03,16,0
2,0.03518603894933314,9,INTERNAL,0.05,16,0
2,0,9,INTERNAL,0.16,16,0
3,0.13973910506875786,9,INTERNAL,0.38,4,0
3,0.21418596171826687,9,INTERNAL,0.24,16,0
3,0.3792667736100306,9,INTERNAL,0.08,16,0
3,0,9,INTERNAL,0.07,16,0
4,0.23084503924196553,9,INTERNAL,0.02,16,0
4,0.3566850751084202,9,INTERNAL,0.07,16,0
4,0.06412832650536227,9,INTERNAL,0.09,16,0
4,0,9,mzzAYbtPpANxpNVGCVBAhZYzrxyZtoix7i,0.04,16,0
0,0.3794032390530363,9,INTERNAL,0.02,16,0
0,0.10756327418131051,9,INTERNAL,0.93,16,0
0,0.40107055434802497,9,INTERNAL,0.07,16,0
0,0,9,mifCWfmygxKhsP3qM3HZi3ZjBEJu7m39h8,0.11,16,0
1,0.05776628660005234,9,INTERNAL,0.93,16,0
1,0.1936955942281181,9,INTERNAL,0.66,16,0
1,0.13956928336353558,9,INTERNAL,0.14,16,0
1,0,9,bcrt1qcnv26w889eum5sekz5h8we45rxnr4sj5k08phv,0.58,16,0
2,0,9,mnTn9KVQQT9zy9R4E2ZGzWPK4EfcEcV9Y5,0.52,16,0
```

### Restarting

Even before discussing practical code-level actions, we can see: this approach allows us to have coins in *any* mixdepth when we start; so we no longer have a special option `--restart` if you manually ended the run halfway, or if a transaction repeatedly failed and you had to give up. You can judge for yourself; if you started a tumbler run of 8 mixdepths and it stopped after 3, you can do another run with 5 mixdepths later, if you like. W.r.t the destination addresses, you were never able to control the ratio that arrives at different destinations anyway (it's technically possible but not recommended, you'd need to create schedules manually and think carefully about it), so this really doesn't change that aspect.

Delaying the whole process by stopping and restarting it is quite sensible anyway; as explained above, we *want* this process to be slow, not fast.

### Reminder about commitments.

Follow the [usage guide](USAGE.md) on how to fund your wallet. Don't neglect to read [this](https://github.com/JoinMarket-Org/joinmarket/wiki/Sourcing-commitments-for-joins) page, otherwise you could encounter problems.

This is actually a really important area with the tumbler, because we use sweeps often. It's not really crucial to use 3 utxos to fund at the start, but try to fund with 2, anyway. And:

It's **strongly** recommended to use counterparty counts (as discussed above; `-N` on the command line) of 8 or higher, **and** `--minmakercount` of 4 (the default) or 5, to give maximum possibility to achieve a successful join every time you make a request (if makers are flaky in the first phase of negotiation, you can still complete as long as up to `--minmakercount` respond correctly).

<a name="schedules" />

## Schedules (transaction lists)

In this implementation, each coinjoin has an associated "schedule" of format like this:

```
[mixdepth, amount-fraction, N-counterparties (requested), destination address, wait time in minutes, rounding, flag indicating incomplete/broadcast/completed (0/txid/1)]
```

`[]` here represents a Python list. It's recorded in files in a csv format (because in some cases users may edit). See [this](https://github.com/Joinmarket-Org/joinmarket-clientserver/blob/master/scripts/sample-schedule-for-testnet) testnet sample given in the repo. A couple of extra notes on the format:

* the 4th entry, the destination address, can have special values "INTERNAL" and "addrask"; the former indicates that the coins are to be sent to the "next" mixdepth, modulo the maximum mixdepth. The latter takes a destination from those provided by the user, either in the initial command line or on a prompt during the run.

* the 2nd entry, amount fraction, is a decimal between 0 and 1; *this is specific to the tumbler*; if a schedule has a (nonzero) integer, that is used (in `sendpayment`) for non-tumbler coinjoin sends..

* 0 amounts for the second entry indicate, as for command line flags, a sweep; decimals indicate mixdepth fractions (for tumbler), e.g. if your mixdepth's total balance is 10.0 BTC and this value is 0.22 then 2.2 BTC will be sent.

* the 6th entry, `rounding`, is how many significant figures to round the coinjoin amount to. For example a rounding of `2` means that `0.12498733` will be rounded to `0.1200000`. A rounding value of `16` means no rounding. Sweep coinjoin amounts are never rounded.

For the `sendpayment.py` script, this schedule can indeed be simply written in a file and passed as a parameter (for this reason it's likely the tumbler and sendpayment scripts can merge in future).

As you can imagine, the idea for the `tumbler.py` script, and the MultiJoin wizard in [JoinmarketQt](JOINMARKET-QT-GUIDE.md#tumbler) is simply that a tumbler *schedule* is generated, according to the algorithm introduced in [this PR](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/387) ([code](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/77422231207c7c3e984a88e944b6c715cece46b5/jmclient/jmclient/schedule.py#L87)), however here it is persisted - see the next section.

<a name="logging" />

## Tumbler schedule and logging

There are two log files to help tracking the progress of the tumble. The first is by default `<datadir>/logs/TUMBLE.schedule` but its name can be changed with the new `--schedulefile` option. In this, the schedule that is generated on startup, according to the user command line options (such as -N for counterparties, -M for mixdepths etc.) is recorded, and updated as each transaction is seen on the network - in particular what is updated is the above-mentioned 'completed' flag, as well as the destination addresses for the user destinations (replacing 'addrask'). So by opening it at any time you can see a condensed view of the current state (note in particular '1' or '0' for the final entry; '1' means the transaction is done).

However, another file is more specifically intended to help tracking: currently hardcoded as `<datadir>/logs/TUMBLE.log`, it will show: transaction times, txids, destination addresses, and also any instances of failures and re-attempts. It's a standard log file and operates in append by default for multiple runs).

<a name="interpreting" />

## Interpreting key console output

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

it means the current transaction has failed for some reason, and you will a little further on see a message indicating the parameters of the failed schedule entry, which will then be tweaked and retried. See [below](#tweaking) on "tweaking".

Another important output you'll sometimes see in the console is the same information that is printed to `commitments_debug.txt` in the case of commitment sourcing failure, like:

```
1: Utxos that passed age and size limits, but have been used too many times (see taker_utxo_retries in the config):
None
2: Utxos that have less than 5 confirmations:
3a001fa0272df5c43c2c38d91d1f784b4ba18c18043355b88c7c713dd3ecc78c:5
...
```

If the tumbler continues to run after this (re: if it doesn't, see the section on failure/crash vectors [below](#failure-vectors)), you need do nothing; usually, you will see the "regenerating transactions" message after a while, and it will try again until (a) the utxos have got old enough (5 confirms), or (b) in rare cases, you will have to wait until the amount is right (20% rule), which depends on "tweaking", see the next section.

```
Makers didn't respond
```
This will happen when too many aberrant makers don't complete the protocol. As above, simply wait for regenerate-after-tweak occurs.

<a name="tweaking" />

## Tweaking the schedule

In case of a single transaction failing, the tumbler is going to aggressively try to continue. This is similar but also a bit different from what happened in the original implementation. After a "Stall detected" message like the one above, the *current schedule entry* will be tweaked, in one of two ways:

* For non-sweeps, the amount fraction (recorded in the schedule as the second entry, a decimal) will be altered, as well as all the succeeding amount fractions in that mixdepth, done in such a way as to preserve the overall distribution of the original schedule. However, the N (number of counterparties) is *not* changed, remembering that we leverage a fallback to `minimum_makers` in case of non-response, so a higher N is always better for reliability. Tweaking the amount fraction can help by changing what liquidity your tumbler perceives, but also sometimes by changing what PoDLE commitments are valid (remembering the 20% rule).

* For sweeps, the amount cannot change, but on the other hand we can bump the success rate by reducing N (for sweeps fallback is not possible).

This tweaking process is repeated as many times as necessary until the transaction goes through. One case in which repetition several times is likely: if you set a low value of `-l` (the time wait parameter), you may quite often not have any PoDLE commitments of sufficient age, and so will have to wait for 5 confirmations; in this case it will just keep retrying until that's true. (Note! Utxo commitments which are too young do not get used up; your own bot recognizes this and doesn't broadcast them until they're valid).

<a name="how-often-do-retries-occur" />

## How often do retries occur?

This is hardcoded currently to `20 * maker_timeout_sec`, the figure 20 being hardcoded is due to me not wanting yet another config variable, although that could be done of course. This is the rate at which the stall monitor wakes up in the client protocol, the setting is in the code [here](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/acc00fc6f5a1cd1f21052c5af06cd06e78c6edda/jmclient/jmclient/client_protocol.py#L359-L363). Note that by default this is fairly slow, 10 minutes.

<a name="failure-vectors" />

## Possible failure vectors - crash or shutdown

* **Failure to source commitment** - if there is no *unused* PoDLE commitment available, the script terminates as even with tweaks this condition will not change. This *could* be changed to allow dynamic update of the `commitments.json` file (adding external utxos), but I didn't judge that to be the right choice for now. On the other hand, as was noted above, if the commitments are simply too young, the script will keep tweaking and retrying. I recommend using the `add-utxo.py` script to prepare external commitments in advance of the run for more robustness, although it shouldn't be necessary for success.
* **Network errors** - this should not cause a problem. Joinmarket handles network interruptions to its onion services and/or IRC servers quite robustly.
* **Insufficient liquidity**. This is a tricky one - particulary for sweeps, if the number of potential counterparties is low, and if some of them are deliberately non-responsive, you may run out of counterparties. Currently the script will simply keep retrying indefinitely.

Note that various other failure vectors will not actually cause a problem, such as the infamous "txn-mempool-conflict"; tweaking handles these cases.

