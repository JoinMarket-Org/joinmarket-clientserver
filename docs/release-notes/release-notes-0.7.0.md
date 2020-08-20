Joinmarket-clientserver 0.7.0:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.7.0>

**This release requires Python 3.6+** (do read upgrading section below).

This implementation includes support for **BIP78 (payjoin) for payments**, in Qt GUI or on command line, using either current P2SH segwit wallets ('3' addresses) or native bech32 wallets.

In support of this there is a major upgrade to the backend Bitcoin code, providing PSBT support, coming from the use of [python-bitcointx](https://github.com/Simplexum/python-bitcointx) (an actively maintained fork of the old python-bitcoinlib).
This will allow a lot of future improvements to Joinmarket to work more smoothly and with a cleaner architecture.

There are many other minor improvements, and a new JoinmarketQt one-click executable for Windows.

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading 
=========

To upgrade:

If you run a system that does not and cannot run python 3.6 or higher, you may have to change this: note that Python3.5 is reaching EOL [next month](https://devguide.python.org/#status-of-python-branches).
For now anyone in that position can simply stick with [Joinmarket 0.6.3.1](https://github.com/JoinMarket-Org/joinmarket-clientserver/releases/tag/v0.6.3.1). That version should continue to work as-is for some time.

Note that this release **requires** a re-run of `install.sh`, i.e. simply checking out the commit or tag on git will not work. The reason for this is that the new Bitcoin code depends on new dependencies (python package [`python-bitcointx`](https://github.com/Simplexum/python-bitcointx) and an independent build of [`libsecp256k1`](https://github.com/bitcoin-core/secp256k1), mainly).

Also: If you are upgrading from a version pre-0.6.2 then please see the section "Move user data to home directory" in  [the 0.6.2 release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.6.2.md), and follow the instructions there (except the `commitmentlist` file - that can actually be left alone, the previous release notes were wrong on this point).

First run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.

Note that `./install.sh -?` will show the options for installation.

Notable changes
===============

### Major bitcoin backend code refactoring, including some PSBT support.

Based on [python-bitcointx](https://github.com/Simplexum/python-bitcointx), see [PR 536](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/536). This replaces some old Bitcoin parsing code, adds support for PSBT in wallets, and also support for SNICKER in wallets. The PSBT is required for our implementation of BIP78 (see below).

Meanwhile the support for these features and the cleaner transaction signing and verifying code will allow other features to be implemented more effectively in future.


`070c5bf` `22ed0e0` `f060781` `de3ad53` `03a1359` `ad459d2` `4cf77ed` `53ef79b` `d34c53b` `6e6bf0a` python-bitcointx backend for jmbitcoin; PSBT support; SNICKER support; libsecp256k1 installation; human readable formatting of transactions.

### Payjoin (BIP78 type) on command line and GUI.

The new standard [BIP78](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki) for Payjoin style payments, in which users can pay a merchant or other wallet while at the same time doing a coinjoin is of course very much in line with the goals of Joinmarket as a project, so it is natural that we made it a priority to support this. The BIP78 receiver you are paying *can* be (and indeed, it is better) a Tor hidden service (so *.onion), which will be usable to pay other user wallets, e.g. Wasabi. Otherwise the server must be using TLS (as per the recommendation in the BIP, an unsecured connection is not supported).

To do such a Payjoin, simply provide the BIP21 style URI in the `Recipient/URI` field in the `Single Join` (should be 'payment') tab of Joinmarket-Qt or pass it in the command line.

Such URIs can be found e.g. from pasting from a btcpayserver instance displaying an invoice, or can be sent in the same way an address can.

Note that the pre-existing Joinmarket-Joinmarket payjoin function still exists, but we will deprecate and remove it (almost certainly) when we add BIP78 receiver support to this wallet.

`ca0de5c` `037a2c1` `55295e8` `41540ab` Add bip78 payjoin module and client-server test.

`1de8888` Add support for BIP78 payjoins to .onion receivers

`347cb7a` Add 60s timeout fallback to BIP78 payjoins

`2401c83` `39c4e24` `aeba4ca` Implement BIP78 payjoin in JoinMarketQt GUI


#### Qt improvements and bugfixes

`fd9d98f` Fixes #639. Allow export of private keys in Qt.

`51ce63b` Use ellipsis for non-immediate menu items


#### IRC bot mode

IRC server operators find it helpful, in some cases, for bots like those used by Joinmarket, to mark their status as such. Hence we add `+B` mode to our bots.

`aa21efc` Fixes #621. Adds +B to joinmarket IRC bots.

#### Change passphrase feature

Now both on command line and Qt, a user can change their passphrase used to lock the wallet.

`3316542` Qt: Add change wallet passphrase feature

`73a604f` Add feature: change encryption passphrase, per #552

`bd48c91` Qt: Add passphrase protection

##### Various improvements and bugfixes

Of note here is that the "frozenness" of utxos is now displayed by the `showutxos` method of `wallet-tool.py`,
mostly the remainder are minor bugfixes.

`ea855b3` Correct `import matplotlib` exception handling

`bbcf7e4` Add missing close parenthesis to RPC error message

`59747d8` bugfix: ob-watcher base58 encoding

`7d6caf1` Fix podle utxo error format

`e5ec172` Output frozen UTXO's on showutxos too, add "frozen" state to output

`1d592d9` Check for pushtx() success in direct_send()


##### Documentation

There has been a fair amount of work to strengthen the documentation in the `docs/` directory of the repo, removing cross-references to older documents that are now out of date and adding some detail on new functionality (for example, BIP78).

`9f9b27c` add direct Windows installation option and guide

`3ef18bc` update gui version in Qt guide

`b5e87ba` Update PAYJOIN.md document for new BIP78 function.

`b653f3f` `35460ff` Make tumblerguide self contained and update info

`7a54ad2` update testing docs

`35cee94` Docs: add commitments explainer

`5ca78c2` install.sh now works on macOS, no need to follow more complicated guide

`73b0edc` Update macOS installation instructions


##### Installation script improvements

`a219cf1` upgrade twisted to 20.3.0

`a39991a` Make scripts compatible with FreeBSD

`3ed4e88` Search for correct library extension on mac os

##### Testing and dev-related

`b289e39` Update version to 0.7.0dev

`4a0d5d4` Use list of tuples for multiple parameter BIP21 encoding tests

`04752e1` Correct flake8 errors

`dfb169a` Fix wallet test entropy extension input

`0bef681` Refactor: #566 use python3 super() syntax

`536bef5` [test] Parse getnewaddress response properly

`7eab576` [test] Update test/bitcoin.conf according to 0.20 release notes

`8de8381` Add jm-tx-history.txt to .gitignore

`9d0f56f` Tests: remove mixed maker addresses test

`42a5010` Replace fmt_utxo with call to jmbase.utxo_to_utxostr

`a9668fd` Drop key_type argument to import_private_key


Credits
=======

Thanks to everyone who directly contributed to this release -

- @jules23
- @kristapsk
- @AdamISZ
- @jameshilliard

And thanks also to those who submitted bug reports, tested, reviewed and otherwise helped out.
