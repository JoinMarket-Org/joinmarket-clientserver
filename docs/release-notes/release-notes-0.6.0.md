Joinmarket-clientserver 0.6.0:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.6.0>

This release has several significant improvements, although changes to the user
workflow are minor. It also contains an important bugfix for Qt users who **must**
upgrade (see first "Notable Change" below). Non-Qt users are also, however, strongly recommended to upgrade to take
advantage of functional improvements.

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading 
=========

To upgrade (but: read and follow instructions in 0.4.0 if from pre-0.4.0):

First run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.
To install using Python2, use `./install.sh -p python2` ; the default is now Python3 and is strongly recommended.

Note that `.install.sh -?` will show the options for installation.

If you are running JoinmarketQt, note that Python2 is incompatible.

Notable changes
===============

### Respect config settings for fee filters in Joinmarket-Qt

This fixes a bug whereby, although the fees could be checked in a dialog box (if using Single Join, and if checktx is set, which is the default),
the randomly chosen makers fees were not forced to be below the fee maximums (relative and absolute) in the config file (settings:
`max_cj_fee_abs`, `max_cj_fee_rel`).
This bug did not occur in the command line version.
This could result in higher fees being paid than intended, with some probability, by the Taker (if they were not using the checktx option).
For this reason update is essential for any user of the Qt version of the application (if they intend to do coinjoins rather than simple payments or payjoin).

c571613 Make Qt check config fee filters as well as checktx

### Tumbler privacy improvements

The tumbler algorithm has been improved with the aim to increase privacy. This affects the `tumbler.py` script and `joinmarket-qt.py` GUI.

* At the start of the run, tumbler will now fully spend all mixdepths with coinjoin with no change address (also known as a sweep transaction) back to its own internal wallet. After these initial sweeps are done tumbler will continue with the already-existing algorithm of sending coinjoins with randomly-generated amounts.

* Tumbler will now occasionally send a round number of bitcoins, for example `0.20000000` or `0.15000000` instead of `0.24159873`. The default probability of this happening is 25% per coinjoin.

* The default wait time between coinjoins is increased from 30 minutes to 60 minutes.

* The default number of coinjoin counterparties is increased from 6 to 9.

* The default number of coinjoins per mixdepth is decreased from 4 to 2.

For a full discription and reasoning behind the changes see: [Plan to improve the privacy of JoinMarket's tumbler script](https://gist.github.com/chris-belcher/7e92810f07328fdfdef2ce444aad0968)

b79d34a Remove amountpower and use uniform distn instead

f40ef2c Occasionally round amounts in tumbler schedule

35f23eb Add sweep coinjoins to start of tumbler schedule

32479ae Modify tumbler defaults to improve privacy

### Wallet refactoring for proper reactive behaviour

This is a large-ish "under the hood" change that allows the wallet to *react* to external events. Thus after this change a deposit
into the wallet is handled automatically, rather than requiring the user to manually resync or restart. This applies both to yield
generators and to the Qt wallet; the wallet tab now shows the live balances at addresses.

(At a more technical level, as well as
changing to a reactive architecture, there are other benefits: a wallet service architecture completely isolates the wallet and
blockchain access implementation from its client applications, allowing future changes/refactors to work much more easily, significantly
simpler transaction monitoring code, and also we now have only a single polling loop to the underlying Bitcoin Core RPC).

c654de0 Wallet and blockchain refactoring

eadbed2 Update receive-payjoin for walletservice arch

cf19df2 Restore account support in wallet_service, needed for pre-0.17 Bitcoin Core

### New custom yield generator(s)

The below commits act to slightly refactor and support the use of
separate/new custom yield generators. Makers are encouraged to take a look
at the new script [here](https://github.com/JoinMarket-Org/custom-scripts/tree/master/yield-generators)
called `yg-acyclic`, which has a specific idea about using a maker bot to siphon funds out via one
mixdepth; read the comments in the file for detail, and please do try it out.

35ebfd0 Fix yg-privacyenhanced.py for recent change.

8b1e24e Make yg algorithms easier to define.

fac2d88 generalize YieldGeneratorBasic.on_tx_unconfirmed

### Wallet password via stdin

This new option allows one to pass wallet passwords via stdin, so as to allow automated startup of the command line application,
without having the security concern that arises from implementing this as a command line argument (shell history/process list etc.).

b83e27c Add --wallet-password-stdin

### Amount formatting

It is now possible to specify amounts in bitcoins, as well as in sats (the default, which is still retained) on the command line, and also in Joinmarket-Qt. You can add `btc` after an amount to clarify.
See [here]() for more details. To emphasise, this is not a *change* - you can still do what you did before, but it adds the possibility of using the alternative unit.

b2e4308 Allow both BTC and sat amounts for single send / CJ

8fd0e75 Mention ability to use both BTC and sat amounts in docs

6926a31 Allow both BTC and sat amounts for payjoin receive

### Several minor improvements and bugfixes in Qt

A couple of things notable in this set: first, seed display was (for some reason?)
not implemented in Qt but only on command line; that has now been added. Also, minor
bugfixes to how mnemonic extension adding works and ensuring that comment lines are
preserved in the config file when using Qt (those comments are sometimes very useful,
so please read them if you haven't!).

1c01f76 Handle exceptions in direct_send()

e6c0575 Abort wallet generation if mnemonic extension choosen but not provided

c23c982 Rename "Exit" to "Quit" in main menu

9dee0d7 Add dialog for displaying seed phrase to JM-Qt

fdc6194 Rename single-letter main window variable from `w`

b3c54ca Rename variable that was previously missed

8ec948e Fix context menu for bech32 addresses in tx history tab

02c2b4b don't use native dialog for schedule open

5d4fc41 Preserve comments in config file when using Qt

bdc0ac5 Fixes #389 - wallet syncing in Qt

24e50cd Use restart_callback in all situations

8936cfc Fixes #445 The variable mnemonic_extension is already of type str and so the call to decode() in displayWords was a bug.

ed825d5 Handle already existing wallet file on recover

### Temporarily revert batch-import during run

An obscure error is encountered by some users running on slower disks: because pre-0.19 Bitcoin Core contains a bug with excessive use of database locks
during importing of watch-only addresses, an import of as few as 20-60 addresses can create a very long delay (on the order of 10s of seconds),
whereas it's hardly noticeable on SSD disks. As a result coinjoins can even fail, hence the below commit reverts a batch import which
was intended to make conditions of failure to sync the wallet far less likely.

df57099 Revert "Fix bug in detailed wallet sync relating to gap addrs."

### Rationalisation of txfee estimate values in code

This should not require any user action.
The `txfee_default` variable was a leftover from a much simpler first version of Joinmarket
with sometimes no access to fee estimates, we no longer need it so it's removed as its existence
is confusing. Similarly, the `--txfee` option was also misleading and is now repurposed as an
override, see the command line help for details.

5c0b9eb Remove txfee_default

0ab5b65 Redefine cli-option --txfee

### Exit code rationalisation

Make exit codes from application shutdown follow standard logic.

52108b6 Update exit codes


### Minor updates for installation

Of note: current libsodium version is old, but we use only the most
basic functionality; we will probably update shortly, all the same.
`libssl-dev` and `libltdl-dev` are a necessity for certain Debian distros.
The twisted version update was not strictly needed, as the security issue
in pre-v19 only applied to the `web` module, which Joinmarket doesn't use,
but the update is made here since it hurts nothing.

cb38ac9 Update url for libsodium

84a4ab2 libssl-dev added as dependency

09e6385 Added missing dependency libltdl-dev

fe66f2e Add option to install.sh to not build the Qt GUI

9066ad4 Bump twisted from 18.9.0 to 19.7.0 in /jmbase

### Minor changes

More minor bugfixes:

User created custom schedules were broken by fee check in #367, so restored:

d9bcca3 Allow custom schedules to work again after #367

Core supports fee block targets up to 1000 and not only 144:

cf54789 Set txfee threshold to 1000 instead of 144

Tumbler was only checking for valid addresses at time of transaction, not at startup:

ad65521 Validate addresses in CLI tumbler at start.

Two fixes for wallet history function:

54326e8 Fix wallet history's display of cj internal sweeps

90a449c Handle unconfirmed tx in wallet_fetch_history()

Several minor changes to the documentation, logs/error messages, or testing code.

documentation and logging

42991a4 Add note to docs about running yg in background

11304c6 fix formatting error in USAGE.md

c9bf1c6 Update documentation: Replace links to instructions in original Wiki ...

1509be0 Clarify that the quickstart install guide is only for Linux

d568040 Fix outdated link in Linux install instructions

e1ff07c add link to custom-scripts ygs in docs

testing

489aedc move maker_timeout_setting to regtest_joinmarket.cfg

6a0e742 Add basic unit tests for YieldGeneratorBasic.


Credits
=======

Thanks to everyone who directly contributed to this release -

- @chris-belcher
- @kristapsk
- @AlexCato
- @AdamISZ
- @zaiteki
- @CandleHater
- @undeath
- @domob1812

And thanks also to those who submitted bug reports, tested and otherwise helped out.
