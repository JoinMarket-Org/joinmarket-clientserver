Joinmarket-clientserver 0.8.3:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.8.3>

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading
=========

To upgrade:

(If you are upgrading from a version pre-0.6.2 then please see the section "Move user data to home directory" in [the 0.6.2 release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.6.2.md), and follow the instructions there (except the `commitmentlist` file - that can actually be left alone, the previous release notes were wrong on this point).)

(If you are upgrading from a version pre-0.7.0 please read the "Upgrading" section in [the 0.7.0 release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.7.0.md).)

First run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.

Note that `./install.sh -?` will show the options for installation.

Notable changes
===============

### Bugfix - avoid cases of unnecessary transaction signing failure

See [PR 910](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/910). In cases where makers sent data (in the `!ioauth` command, that transfers the information needed to construct the coinjoin) which was not valid in some way, such as the utxo not being valid (e.g. already spent), then sometimes (depending on exact conditions), those maker utxos were *left in* the transaction template that the Taker constructs. This led to a condition where a transaction would simply timeout as unsigned. While this doesn't stop the tumbler from continuing (it tries again after a timeout), it is a bad outcome, not least because PoDLE commitments get used up unnecessarily; the transaction could have completed normally, using the makers with correctly verified data.

After this commit, the code has been refactored to more cleanly organize the process of (a) verify that makers' data is correct and only then (b) add the makers' utxos to the transaction template.

Coinjoins should fail to complete less often after this fix.

`9b01d9a` minor refactor of Taker.receive_utxos()

### Darkscience Tor onion address update

The optional Tor onion address in the default config is updated from the old v2 onion to the new v3 onion address. See [here](https://www.darkscience.net/servers/). Users should take note and update this in their config files, since v2 onions are going to be deprecated [shortly](https://blog.torproject.org/v2-deprecation-timeline).

`1125120` darkscience tor address v3

### Bugfixes to Payjoin code

Three fixes/changes here. The first dealt with a bug in which, if the index of the change output were zero, the parameter `additionalfeeoutputindex` was being incorrectly ignored, preventing the possibility of subtracting the fee from the change. This happened about 50% of the time where this option was chosen and led to lower transaction fees than intended.
The second was more important; when more than 1 input was provided by the sender (probably not uncommon), the rule for the placement of new input(s) from the receiver according to BIP78 was not exactly correct, this is now fixed.
The third is not a bugfix, but a design choice: we feel it is better to insist that the receiver uses confirmed coins only, not unconfirmed.

`15089fc` Fix additionalfeeoutputindex check in BIP78

`60215e1` BIP78 input ordering correct for > 2 inputs

`0d21b92` Require confirmed coins to receive payjoin

### Set default tx broadcast to `random-peer`

After [PR 677](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/677) late last year, the code enabled the choice of "random-peer" or "not-self" for transaction broadcast, as well as the existing default "self" (broadcasting via your own Core node). Also note that this PR implemented a fallback to broadcast yourself, in case `random-peer` fails because the peer fails to broadcast (see `Taker.handle_unbroadcast_transaction`).
This commit updates the default to `random-peer`, being seen as superior for privacy, since there is no drawback given the above fallback mechanism in case of any failure.

`a1e9d8b` Set default tx_broadcast = random-peer

### New feature: enable custom change addresses

See [PR 859](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/859). This enables the option of adding a custom change address in place of the normally chosen in-wallet change address, if the user chooses. This is applied both for command line `sendpayment` and for JoinmarketQt, and it works for direct sends (i.e. no coinjoin), also. (It doesn't work for Payjoins, however).
Additionally, warning messages are given to the user, in particular for the case where they choose a custom change address that is of a different scriptPubKey type than the wallet; this can lead to undesirable scenarios for coinjoins.

`ad8cd74` Enable external/custom change addresses.

`b4ca42d` taker: Fix change validation logic

`b25d03c` Fixes bug introduced in ad8cd74

### 2e50d03 Fix signmessage to be Electrum-compatible

Verification of message signatures against segwit addresses is not currently functional/possible in Core, and additionally the signing function used for messages in jmbitcoin, derived from coincurve, was not compatible with Electrum either. This commit uses the functionality in python-bitcointx's signmessage module, and now the wallet method `signmessage` creates signatures on messages against segwit addresses that are verifiable in Electrum.
Note that a feature like this is useful, given compatibility with Electrum (tested as of 4.0.9), but it is somewhat of a stop-gap. See [BIP 322](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki) for how things may develop in future.

Also note that we still do not have a verify method implemented here, only a sign method.

For more details on the history of this feature, see [here](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/841#issuecomment-808329156).

### BIP78 via daemon

Although for most this is an under-the-hood change only, with no functionality altered, for a subclass of users it's important. After these changes, the Tor onion service used by the receiver, and the sender's request via the SOCKS5 proxy, happen only via the daemon package, which (for those users) can be run on a separate machine or otherwise isolated instance. This brings the BIP78 implementation in line with the standard Coinjoin implementation with respect to network connections being isolate-able.

`15468cb` Payjoin receiver via daemon.

`b6e2576` BIP78 sender protocol via daemon

`09b3fab` Remove Tor config defaults request in onion setup

`8b0d08d` Don't request privkey for ephemeral onion from Tor

### Change commitments logic to avoid using different mixdepths' utxos

See [PR 840](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/840). This represents a fix to a minor hole in the privacy of takers. Before this change, takers would occasionally use utxos for PoDLE commitments that were not in the same mixdepth as their inputs for the coinjoin (first, utxos in the transaction were preferred for PoDLE creation; then, if those were not eligible, any other utxo in the wallet was tried). Where this happened, the makers who received the opening of the PoDLE commitment, which includes the utxo, may be able to correlate these utxos with those in the final coinjoin transaction which they deduced to belong to the taker, and thus make a high-likelihood correlation of utxos between different mixdepths, something that Joinmarket tries hard to avoid.
To avoid this possible violation of Joinmarket's privacy model, after this change, Joinmarket will *ONLY* source commitments from the same mixdepth as the inputs to the Coinjoin. Takers should be aware that this may lead to more cases in which they run out of possible commitments.

`40768cf` Change taker's commitments logic

### Change to mixdepth selection algorithm in yg-privacyenhanced.py

See [PR 808](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/808). This represents a probably somewhat significant improvement in the quality of the choice of mixdepth made by the `yg-privacyenhanced` yieldgenerator (which should be considered default; the `yield-generator-basic.py` is essentially legacy at this point). In short, it makes it a priority to concentrate coins into one mixdepth (or a clump of mixdepths) where possible, and removes an inherent bias towards picking a lower mixdepth that previously existed (technically there is still a *very* small bias but it's not relevant).

A reminder that maker-users of the codebase can also take a look at [this](https://github.com/JoinMarket-Org/custom-scripts/blob/master/yield-generators/yg-acyclic.py).

`993003e` Change mixdepth selection of yg-privacyenhanced


### Logging changes

Some fixes/improvements in logging. We send log output to STDOUT instead of STDERR for those who find that useful; we disable colored output in case output is piped to a file (but see one point still unfinished [here](https://github.com/JoinMarket-Org/joinmarket-clientserver/issues/911)); we make sure invalid IRC messages show up in full in the log and also there is a slight improvement in the formatting of transaction feerates.

`96c03ed` Disable coloured output if stdout is not a terminal

`f2362dc` Log whole IRC message on "bad command"

`60622ff` Change log output to STDOUT from STDERR

`a982ea0` Better tx feerate formatting

### Bugfix to `max_sweep_fee_change` usage

For background, you may want to read [this](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.8.1.md#constraining-sweep-transaction-fees) from the 0.8.1 release notes. The above-mentioned config setting is currently at 0.8 by default, but there was a bug in the implementation such that the calculated ratio was the reciprocal of what was intended; this error is fixed here.

An additional note: users who are more concerned with successful sweep transactions than a change in fee might be advised to bump the default from 0.8 to a much higher value like 2.0.

`027e468` inverted feeratio so calculation of fee deviation works as intended

### Auto-load the bitcoind wallet on startup if possible.

See [PR 856](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/856). This is helpful now that the model of bitcoind RPC access to wallets has changed (note that there is no longer a "default wallet", and that wallets can be loaded dynamically). Read more about setting bitcoind RPC wallets [here](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/USAGE.md#setting-a-core-wallet-recommended) if this is new to you.

`7f85822` Try load RPC wallet on start-up if it's not loaded

### Cache RPC `gettransaction` results for better performance

See [PR 851](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/851). This should improve the performance of the `history` command by caching results from the RPC call.

`6f533aa` Reduce number of gettransaction RPC's by caching results

### More minor functional changes

`ae57657` ob-watcher.py: gracefully exit on old python versions

`7bfc758` Use mempoolminfee instead of minrelaytxfee as tx feerate floor

`bc2d604` Prevent absurdly low minsizes in yg-pe

`aab14f6` fix taker fee estimation on sweep after maker responses

`1d74222` Fix year 2038 problem in fidelity bond wallets

`8639a96` When selecting utxos in yg, count in that change should be above dust threshold already on the first try

`43cc960` taker: Account for off-by-one errors caused by rounding

`9ea0a73` Hide "Total balance" in wallet-tool when only single mixdepth is displayed

`f361c98` Better handling of non-standard tx'es, less extra output for csv and other small improvements

### Qt UI improvements

These are mostly fairly minor so grouped together:

`2bde2f9` jm-qt: Don't annoy the user for removing an address

`1c2b6cd` jm-qt: Clarify error message: "0" is a valid input to `numCPInput`

`4599bd7` Fix autofreeze warning on Qt

`7949374` Clear single send form after successful send

`25b2e8e` Don't create logs, wallets and cmtdata subdirectories under scripts


### Testing and dev related background fixes

These are almost entirely not related to user functionality, but a couple of notes:

Although `df83764` is minor, it relates to an important point: we cannot support importing keys of a different scriptPubKey type (e.g. native segwit BIP84) than the wallet being imported into. Key import is not something users should generally use, but if they do, it's very important to know this limitation.

`03ea5bb` adds options to the `run_tests.sh` script.

`41658aa` Remove socks.py, not used

`adbbb24` address complaints of flake8 in jmclient

`ab43961` Add flake8 linter script

`512fab7` Fix remaining flake8 errors

`fde23c3` Remove unused imports

`4e4b15b` add tests cases for commitment sourcing

`46281b5` Use python-bitcointx in fidelity bond wallet sync

`392f51b` Remove rand_pow_array(), it's not used anymore

`c30929a` Fix SNICKER client-daemon setup

`eedd6e0` Ensure clients connect to correct daemon port

`03ea5bb` Add command line option support and verbose output option

`60e2bea` Move wallet_utils tests to test suite

`df83764` Remove unused key-type param for importprivkey

`c70f253` add test case for low feerate

`79bb3ff` Allow to specify all conftest.py arguments to run_tests.sh

`e7027ab` Change IRC ports for local tests

`516e46a` Additional BIP32 test vector for hardened derivation with leading zeros

`fb1d6cf` Remove unused function argument

### Documentation updates

`3edd07c` Remove reused donation addresses

`16294bc` taker_utils: Fix typo in comment

`46fe744` update payjoin comment in readme

`f0cd0a9` Update SOURCING-COMMITMENTS.md

`aa49169` add the community Telegram channel

`b0ea821` small update to TODO list

`e0cfae5` move IRC network from freenode to libera.chat (merges #884)

`912b4d5` add missing whitespace to log


Credits
=======

Thanks to everyone who directly contributed to this release -

- @Lobbelt
- @kristapsk
- @undeath
- @chris-belcher
- @AdamISZ
- @bisqubutor
- @sangaman
- @csH7KmCC9
- @PulpCattel
- @Pantamis
- @openoms

And thanks also to those who submitted bug reports, reviewed and otherwise helped out.


