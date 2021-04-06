# Sourcing commitments for joins

**To keep reading time short, what to do and what not to do is in bold, so you can focus on that.**

## Commitments for initiating coinjoins

To reduce the potential for spying, we now require that every request for a coinjoin comes along with a "commitment" which is a hash value based on the idea of [proof of discrete log equivalence, PoDLE](https://joinmarket.me/blog/blog/poodle/).

The gory crypto details don't matter of course, what matters is that for each utxo you own that is (a) at least 5 blocks old, and (b) contains an amount of at least 20% of the transaction size ("20%" is controlled by `taker_utxo_amtpercent` in `joinmarket.cfg` - **don't change this**), you are allowed 3 tries ("3" is controlled by `taker_utxo_retries` in `joinmarket.cfg` - **don't change this**) to do a transaction. Once you've tried 3 times, you have to use a different utxo (some Makers may choose to be more lax, but this will be the usual requirement).

## Source of commitment utxos

Usually they will be sourced from your spending mixdepth, and this will require no intervention. The main purpose of this page is (a) to make that happen as much as possible and (b) to tell you what to do if it goes wrong.

### Wait for at least 5 confirmations

Commitments will not be accepted if the age is less than the default 5 confirmations, so **for a fresh wallet, wait for at least 5 blocks before starting as a user/taker**.

### Fund your wallet with multiple utxos.

To help, **when you fund your Joinmarket wallet** (as a Taker, i.e. a transaction originator using `sendpayment` or `tumbler`; for Makers it doesn't matter), it's recommended to **send the coins to multiple (e.g. 3) addresses**. In wallets like Bitcoin Core or Electrum (or I presume many others) this can be done in the GUI using the `sendtomany` or `paytomany` feature; you just enter multiple addresses (and probably pay the same amount to each one). If you're using Joinmarket sendpayment, you'll want to choose several receiving addresses in one external branch for one mixdepth. **Don't do a `sendtomany` to *different* mixdepths**, as that will link those mixdepths together, a central thing that Joinmarket avoids. Also, **don't send multiple outputs to the same address** - use different addresses.

As an example, if you send to 3 addresses instead of 1, you will then have 9 commiments available - effectively 9 tries at doing the first transaction, instead of only 3 tries if you send the coins to one address.

However, **don't split an amount to be spent into more than 5** - because a utxo has to be at least 20% of the total payment amount, so you could find yourself unable to source a commitment in that case. 3 equal sized amounts ought to be fine.

In most cases this will be enough.

### Sourcing external commitments

In cases where you don't have enough utxos with valid commitments left, or you're not prepared to wait 5 blocks, there are alternatives made available. If you go into the `scripts` directory you'll find a tool `add-utxo.py`. Run `python add-utxo.py --help` to see an explanation. In short, you can:

* Add external utxos from a non-JM wallet, like Electrum or Core, one at a time, or from a prepared file (-r).
* Add external utxos from a Joinmarket wallet (-w).
* Delete existing external utxos (-d)
* Validate utxos (-v, -o)

Note that whatever utxo you add has to have a scriptPubKey of the **same** type as those of your current wallet (currently either nested or native segwit). This also corresponds to the type of orderbook you interact with.

Also note that "adding a utxo" does **not** mean spending it! It only means adding a hash-value commitment and the pubkey, basically. Any Bitcoin utxo can be used as an effective 3-time usage token, without spending it.

Be aware that Makers will see this utxo *only if* your usage is successful (they accept it and return their utxos in response), which is a reason not to use this "sourcing external" approach if you have any concerns about them getting that knowledge. Also, if you source a utxo from another non-JM wallet you will have to pass its private key in WIF compressed format to the script (it cannot be signed inside the wallet as this is not a standard Bitcoin ECDSA signature), in order to create the commitment - the usual strong warnings about handling private keys apply here, so use this approach only *very* carefully.

### Commitment storage, and what if things go wrong.

The commitments you've already used (just hash values) are stored in the `used` section of the file `~/.joinmarket/cmtdata/commitments.json` - **don't delete this file**. Although you won't need to read this file, it represents your memory of which commitments you've already used, so if you lose that record, your Taker scripts will find themselves spending a lot of time retrying commitments that the rest of the Joinmarket "network" knows are already used, and so will be rejected. This is only an inconvenience, but it could be pretty annoying. Any external commitments you sourced according to the previous section are also added here, and deleted automatically once they're used up. You can add/delete the contents of that `external` section using the previously mentioned `scripts/add-utxo.py` script (see previous section for a brief overview of options).

If in a run of `sendpayment.py` no commitment can be sourced (in tumbler it just waits), either within the spending mixdepth, or external as described above, a file `commitments_debug.txt` is created that will show exactly which utxos have been tried and why they failed - and gives brief instructions on what to do depending on the state of each of those. A sample file is shown at the end of this page.

### Minor additional tools

An extra method for `wallet-tool.py` is added: `showutxos` - this will pretty print all the available utxos in any Joinmarket wallet. This is only potentially useful for people who run both as Maker and Taker and want to consider transferring utxos for commitments from one mixdepth/wallet to another (using the `-w` option to `scripts/add-utxo.py`).

Similarly a `sendtomany` function is available in `cd scripts; python sendtomany.py --help`; read the help for details but it's as simple as it sounds, specifically creating equal sized outputs for each of the destination addresses you specify; it requires one utxo and its private key as inputs. You're prompted before broadcast, so you can check its validity.


Sample commitments_debug.txt:

```
THIS IS A TEMPORARY FILE FOR DEBUGGING; IT CAN BE SAFELY DELETED ANY TIME.
***
1: Utxos that passed age and size limits, but have been used too many times (see taker_utxo_retries in the config):
dba822a36ad524b775af63db4e25b3558c75ac90d8566a74b2d08b9f63adff97:1
cde0608bf5426c7ed705d87553718e8c74fa75b9428f14e0759f9e95b03d25f2:1
2: Utxos that have less than 5 confirmations:
None
3: Utxos that were not at least 20% of the size of the coinjoin amount 499948833
8ddaee775825a6f89f48e17b47177d3858044cdc633ced09c7c84cc75f609522:0
***
Utxos that appeared in item 1 cannot be used again.
Utxos only in item 2 can be used by waiting for more confirmations, (set by the value of taker_utxo_age).
Utxos only in item 3 are not big enough for this coinjoin transaction, set by the value of taker_utxo_amtpercent.
If you cannot source a utxo from your spending mixdepth according to these rules, use the tool add-utxo.py to source a utxo from another mixdepth or a utxo external to your joinmarket wallet. Read the help with 'python add-utxo.py --help'

***
For reference, here are the utxos in your wallet:

mixdepth 1:
    dba822a36ad524b775af63db4e25b3558c75ac90d8566a74b2d08b9f63adff97:1 - path: m/84'/1'/1'/1/1, address: bcrt1qwdf43llnn8t7h38vxsqswadyelh4trz3ne6syu, value: 200000000
    cde0608bf5426c7ed705d87553718e8c74fa75b9428f14e0759f9e95b03d25f2:1 - path: m/84'/1'/1'/1/0, address: bcrt1ql6akvae73rf433d7ga0muqcrh4y0nuxer5zczd, value: 200000000
    8ddaee775825a6f89f48e17b47177d3858044cdc633ced09c7c84cc75f609522:0 - path: m/84'/1'/1'/1/3, address: bcrt1ql0z4wcjapmrkehgtcjc8c0gvv59hls30h0qhwq, value: 99988990
mixdepth 0:
    57fcec6f770e3b2ac35e9cb17b1ee88ae5b0dc84b941f7418b04a4edecc46d7f:1 - path: m/84'/1'/0'/1/0, address: bcrt1qctllzvz5jcyfa08q0psfyx6p2luss8llldh06u, value: 200000000
    8ddaee775825a6f89f48e17b47177d3858044cdc633ced09c7c84cc75f609522:4 - path: m/84'/1'/0'/0/4, address: bcrt1qv5utq4crzwpq4gw3mvfmaw7q63ukpjf3098f6k, value: 100000000
```
