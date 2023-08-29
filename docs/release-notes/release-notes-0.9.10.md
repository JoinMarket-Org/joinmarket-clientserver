Joinmarket-clientserver 0.9.10:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.9.10>

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading
=========

To upgrade:

*Reminder: always back up and recreate your joinmarket.cfg file when doing the upgrade; this is to make sure you have the new default settings.*

(If you are upgrading from a version pre-0.7.0 please read the "Upgrading" section in [the 0.7.0 release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.7.0.md).)

(If you are upgrading from a version pre-0.9.0 please read the [release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.9.0.md) to find out how about [fidelity bonds](../fidelity-bonds.md) are relevant to your use-case).

First run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.

Note that `./install.sh -?` will show the options for installation. See the section on Installation below for a new option for Tor.

Changes
===============

### Removal of Python 3.6 support, 3.7 or newer is required now

Python 3.6 has been end-of-life since end of 2021 and Python 3.7 is also minimum requirement for planned future packaging changes.

* `63890ee` Drop Python 3.6 support
* `9f4da21` Document requirement of Python 3.7 or newer

### Fee estimation changes and fee bumping

Command line script `bumpfee.py` is added which gives simple way to speed up unconfirmed transaction by replacing it with higher fee paying one if all inputs belong to Joinmarket wallet (so will not work with coinjoins) and original transaction has signalled BIP125 opt-in RBF flag. BIP125 signalling is also enabled by default, in previous versions that was only possible with `sendpayment.py` by adding manually command line flag.

Also transaction fee randomization (which we do for privacy reasons) code is now changed to randomize only upwards, but never below the manually specified or automatically estimated fee for block confirmation target.

* `eeb362b` added bumpfee.py script for bumping fees for rbf transactions
* `907f1b0` Signal BIP125 opt-in RBF for non-cj sends by default
* `67ff868` Randomize transaction fees only upwards
* `d5c240b` Refactor fee estimation code

### Wallet RPC API improvements

Two new API endpoints are added - `/getinfo`, which currently allows to get version of Joinmarket running in backend, and `/wallet/recover`, which allows recover wallet from seed phrase using API.

* `7f4eaa9` RPC-API: add ability to recover wallet
* `828398f` RPC-API: read gaplimit from config
* `c9f6ac8` RPC-API: add getinfo endpoint.

### BIP21 bitcoin: URI changes

Multiple duplicate arguments with the same key, like amount, now is parsed in guarateed order, where last one wins. That matches behaviour of Bitcoin Core.

* `88bd45b` Parse URI params in guaranteed order, for duplicates, last one wins

### Code quality improvements

* `373493f` Refactor: move output descriptor code out of blockchaininterface
* `f6795e4` Add typehints to jmbitcoin/jmbitcoin/amount.py
* `3805c7a` Remove ElectrumWalletInterface
* `e31e839` Add get_wallet_rescan_status() instead of getwalletinfo() for bci
* `2cc7f21` Refactor: alphabetical order of imports and `abc` changes
* `53a9af5` Add `**/build/` to .gitignore
* `8255c18` Alphabetical order of imports and add typehints
* `a85832a` Remove deprecated check for Python 3+
* `6b2a248` Add typehints to BIP21 code
* `e4f74b5` Deduplicate AES code
* `4e5d894` Remove imports from future and past

### Bugfixes and other minor changes

* `6a47dd2` Add missing space to error message
* `a94d871` ignore txs with invalid sPKs when scanning
* `34c0c45` Add -l/--label-change option to sendpayment.py to automatically label change address
* `abbffef` ignore matched txs with invalid sPKs when scanning
* `f68ae8b` Rename "sat/vkB" to "sat/kvB"
* `9ce4e98` JM requires Python 3.6+ currently
* `6cf2237` Add space between address and comma for added utxos msg for easier selection by double clicking
* `dd0176e` Check wallet lock file before asking for password
* `90fe9b2` Fix pyaes dependency, should be in jmbase, not jmbitcoin
* `dafc180` no lock check on readonly

### Documentation

* `9fe2174` Fix git command typos
* `f8af2bf` Fix libsecp256k1 commit ids in docs
* `cb2ad2b` docs: add restart config to directory node service

### Installation and dependencies

* `f57e9fd` Bump cryptography for 64-bit ARM and x86
* `4b2cbe9` Pin werkzeug dependency to 2.2.0
* `c7b59ae` Bump werkzeug from 2.2.0 to 2.2.3 in /jmclient
* `77bd017` Bump pyOpenSSL and hence cryptography

### Testing

* `dd1bde0` update ygrunner test for 1427
* `224de08` CI: Bump used GitHub Actions to newer versions
* `3641f1e` Disable venv caching
* `198117f` CI: Remove editable installs
* `3c0b508` Remove unnecessary commands from setup joinmarket + virtualenv step
* `9072e10` Don't alter LD_LIBRARY_PATH, PKG_CONFIG_PATH and C_INCLUDE_PATH in tests
* `c921206` GitHub workflow update (test multiple Bitcoin Core versions)
* `cd1f394` Add test coverage for is_bip21_uri()
* `e3681f7` Fixes websocket test in test_wallet_rpc.py

Credits
=======

Thanks to everyone who directly contributed to this release -

- @AdamISZ
- @akhavr
- @BitcoinWukong
- @kristapsk
- @openoms
- @PulpCattel
- @roshii
- @takinbo

And thanks also to those who submitted bug reports, tested, reviewed and otherwise helped out.
