Joinmarket-clientserver 0.9.1:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.9.1>

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading
=========

To upgrade:

(If you are upgrading from a version pre-0.6.2 then please see the section "Move user data to home directory" in [the 0.6.2 release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.6.2.md), and follow the instructions there (except the `commitmentlist` file - that can actually be left alone, the previous release notes were wrong on this point).)

(If you are upgrading from a version pre-0.7.0 please read the "Upgrading" section in [the 0.7.0 release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.7.0.md).)

(If you are upgrading from a version pre-0.9.0 please read the [release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.9.1.md) to find out how about [fidelity bonds](../fidelity-bonds.md) are relevant to your use-case).

First run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.

Note that `./install.sh -?` will show the options for installation.

*Quick background: fidelity bond utxos are created as p2wsh i.e. segwit "scripthash" outputs, and the redeemscript has a timelock in it. They are not spendable before the date specified in the timelock. Once that time is past, they are "time-unlocked coins" and perhaps "ex-fidelity-bond utxos" (though they can still function as fidelity bond after the timelock, with less value). This is just to explain some of the language below.*

Notable changes
===============


### Taker side alterations for handling time-unlocked coins

If a taker-user does include a time-unlocked (i.e. previously fidelity bond) utxo, in their wallet (this is most likely someone who ran Joinmarket as a maker in the past; otherwise they probably wouldn't have such a coin), in a coinjoin they construct, then they cannot use this utxo to construct "PoDLE commitments" (at least, today, this is true: if future code is written to support this, it would not be backwards compatible with bots that don't have that code; it seems unlikely that this will be done).
Notice that this *nearly* precludes the ability to make a coinjoin using a single ex-fidelity-bond utxo as input (but only *nearly* : you could use external commitments).

Whether people actually want to create coinjoins using these utxos as input is a matter that can be debated, but it is possible after this fix:

`8f5998b` Prevent selection of non-standard utxo for podle


### Fix for bug of non-coinjoin "direct send" payment with a time-unlocked coin

Sweeps containing time-unlocked coins, sent as a direct payment (`-N 0`), were working in 0.9.0 but there was a bug in non-sweeps, fixed here:

`e1ec4b9` Fix bug in direct send of timelocked outputs

Additionally note that PSBT construction with these time-unlocked coins is **not** yet supported.


### Maker side alterations for handling time-unlocked coins

There is a technical reason why including time-unlocked coins in your coinjoins as a maker is, for now, not possible. The simple version: makers have to send their transaction signatures to takers, and the Joinmarket protocol expects those signatures in a fixed format, and that can't be done here (even if we got clever with sending the data in the expected format, the taker would reject it as it doesn't conform to the standard signature it's expecting). Note that this makes the discussion of "should we allow makers to include custom script utxos as input" moot, for now.

The simple approach taken for now is: just freeze any non-standard wallet utxo when the maker starts up, so it can't be selected for joins. When the script shuts down, the utxo is then unfrozen again. If there is a "hard crash" the user may have to unfreeze such a coin manually.

`ab5b45e` lock timelocked utxos on maker startup

A subsidiary point ended being superseded by that freezing fix: part of Joinmarket's protocol involves signing ownership of a utxo, by the maker, in the setup conversation, as a MitM defence. This utxo also cannot be of the time-unlocked type for the same reason. This commit is preserved however, as it applies the generic concept "don't use a non-standard utxo for the authorization step".

`8c3ae11` fix maker selection of ioauth input with expired timelocked addresses


#### Documentation updates to clarify aspects of fidelity bond usage

Questions and interactions with users post-the release of 0.9.0 made us realize that some details were not as clear as they should be. For example,
the fact that only one fidelity bond will be advertised at a time:

`f7180b8` Emphasize that ygen uses only single UTXO as fbond

`148f970` Add single UTXO fb warning to gettimelockaddress

Additionally, a couple of changes were needed to the doc to explain exactly how a user can/cannot spend fidelity bond utxos, after they've passed their timelock and are spendable on-chain (see above code commits for more detail).

`e7c3c4e` detailed conditions for spending timelocked coins

`13ae0c3` Remove doc saying timelock utxo can be spent in cj

Giving users additional advice on the non-obvious question of how time-unlocked (previous fidelity bond) utxos should be spent:

`cea80e2` Suggest use of coin control in fidelity-bond.md

A typo fix in the equation defining fidelity bond value:

`87f36c2` Fix error in simplified equation in fidelity-bond

As per commit comment:

`a090293` Emphasize the sybil protection gained by takers


### Fix overflow error on 32 bit ARM

See [this issue](https://github.com/JoinMarket-Org/joinmarket-clientserver/issues/953) for context. 32 bit systems hit a limit in datetime processing at year 2038 (see also next section). The fix here rewrites several datetime related calls to be compatible with those systems.

`f9ea973` fix overflow error on 32bit ARM


### Ob-watcher fixes

As per above:
`ce08a0c` Fix year 2038 problem in ob-watcher /fidelitybonds

Also, a separate bug was fixed in the code triggered by the json export of the orderbook:

`58d3e59` Fix Export Orders page on ob-watcher


### More minor improvements and fixes

Only in testing should a user be allowed to set a timelock in the past, for real usage it's an error:

`79a330e` Check that gettimelockaddress argument is in future

`53c7c7d` Better error message in case of invalid joinmarket.cfg format

`c20655c` Always cast pid read from wallet lockfile to int

`1bf9f85` Update link to irc logs to https

This last item in the list is a bit more significant, as it was a potential crash vector in running takers, but it was rare and trivial to fix: a logging statement was crashing due to trying to use a negative satoshi value:

`4586e34` Prevent crash if negative change in sweep


### Testing and dev related background refactoring

`c2312a4` clean up timestamp_to_time_number()

`dc13038` reuse index for timenumber in FidelityBonds wallet


Credits
=======

Thanks to everyone who directly contributed to this release -

- @openoms
- @kristapsk
- @chris-belcher
- @PulpCattel
- @undeath
- @AdamISZ

And thanks also to those who submitted bug reports, reviewed and otherwise helped out.
