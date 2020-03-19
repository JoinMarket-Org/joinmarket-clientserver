Joinmarket-clientserver 0.6.2:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.6.2>

This release includes many functional improvements.

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading 
=========

To upgrade (but: read and follow instructions in 0.4.0 if from pre-0.4.0):

First run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.
**Python 3 is now required; Python 2 is no longer supported as it reached EOL.**

Note that `./install.sh -?` will show the options for installation.

**Once you have upgraded, please take note of the change mentioned below under `Move user data to home directory`.**

Notable changes
===============

### Move user data to home directory

In line with standard practice, an overdue change: from this release, data is stored in `$HOME_DIR/.joinmarket`. So for Linux this
is `~/.joinmarket` and for MacOS, `$HOME/Library/Application support/joinmarket`. What is stored there is:

    `joinmarket.cfg` file
    `wallets/` directory
    `logs/` directory
    `cmtdata/` directory
    `commitmentlist` file

Most obviously this will impact any existing wallet you have; you should simply copy the `your-wallet-name.jmdat` file into `~/.joinmarket/wallets`.
You are also advised to copy the folder `cmtdata` to the new `~/.joinmarket/cmtdata` location (although this is not strictly needed, it's better).
The same is true of the file `commitmentlist`.

You may need to run the `wallet-tool.py` script once to create the directory.

In certain cases you may prefer to use a specific directory for your joinmarket data; for any script, you can override the `~/.joinmarket/`
default, by specifying `--datadir=yourdirectory`, as mentioned in the `--help` text.

`8c8e6e2` Move all user data to home directory

`6711a4e` fix location of yigen-statement.csv

`de255c3` Fix homedir lookup in MacOS

`252a869` add datadir option to Qt script

`6943ff2` Bugfix: tumbler datadir reference

### No-history wallet synchronization

The no-history synchronization method is enabled by setting `blockchain_source = bitcoin-rpc-no-history` in the `joinmarket.cfg` file.

The method can be used to import a seed phrase to see whether it has any money on it within just 5-10 minutes. No-history sync doesn't require a long blockchain rescan, although it needs a full node which can be pruned.

No-history sync works by scanning the full node's UTXO set. The downside is that it cannot find the history but only the current unspent balance, so it cannot avoid address reuse. Therefore when using no-history synchronization the wallet cannot generate new addresses. Any found money can only be spent by fully-sweeping the funds but not partially spending them which requires a change address. When using the method make sure to increase the gap limit to a large amount to cover all the possible bitcoin addresses where coins might be.

The mode does not work with the Joinmarket-Qt GUI application but might do in future.

`f5e27c3` Add test code for no-history sync

`cbf69c6` Implement no-history synchronization

### Auto-freeze of deposits to reused addresses.

See #471 . New deposits should always be to unused addresses, so to prevent [forced address reuse attacks](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse), (sometimes called dust attacks, but that's a poor name), we freeze any deposit to an already-used address by default.

The user can easily simple unfreeze these utxos both on CLI and in the Qt GUI (see the "Coins" tab; right click a utxo to unfreeze it). Also, the user can set a finite threshold above which such deposits will *not* be frozen by setting the value of `max_sats_freeze_reuse` in the `[POLICY]` section to a positive integer (`-1` means no limit).

Complementary: the command line interface for freezing/unfreezing utxos is made more convenient, with a loop.
 
`d719ff2` Auto-freezing of address reuse below a threshold.

`83c4d3d` Bugfix for `d719ff2` (was erroneously freezing all new utxos)

`f949ee9` add tooltips for freeze_reuse config to Qt

`66823aa` Add loop in the CLI for freezing UTXOs

### No-blockchain option

This is useful for testing (so principally for developers), but also for running the ob-watcher script that lets you observe the offers available in your browser.
Specify `no-blockchain` in the `blockchain_source` setting of the `[BLOCKCHAIN]` section of the `joinmarket.cfg`.

`931a5c8` Add 'no-blockchain' blockchain_source option.

`8ae41b1` noblockchain error message for Qt

### Direct send privacy improvement

This adds to direct send payments (i.e. ordinary wallet spends, no coinjoin) the same features that we have for PayJoin payments: random shuffle of inputs and outputs, and locktime setting for approximate sharing of anonymity set with Core, Electrum.

`c23808f` Privacy improvements for direct_send()

### Python2 deprecation.

See #499. Since Python2 has reached EOL as of start of 2020, we also no longer support it for Joinmarket. Anyone who for some reason cannot get access to Python3 can continue to run 0.6.1, at least for some time.

`4bf1f50` Remove Python 2 compatibility imports and disable Python 2 installation in setuptools.

`8c21b04` Sunsetting support for Python 2

### Change of default IRC messaging servers

Cyberguerilla's IRC (also known as "cgan") appears to be down permanently; we have added a new IRC server "hackint" to the default list, which now includes that one, and Darkscience.
The agora server has proved relatively unstable and remains inactive by default, but you can activate it by uncommenting the relevant lines in `joinmarket.cfg`.

`f8d1472` Disable Agora by default (again), as discussed on IRC

`ea71b56` Added hackint IRC

`589a23a` Remove Cyberguerilla (it's gone) and add Darkscience

`11acea3` Remove Cyberguerilla and re-enable Agora in default IRC config

### Simplification of installation process

Whilst this is a meaningful refactoring of the installation process to make it more
in line with python standards, so it's mostly only of interest to developers.

`18d8f96` simplified joinmarket dependencies installation

### Confirmations included in showutxos output on CLI

See #489. As a result of #359 which introduced tracking of confirmations within the wallet, this
change in UI could be added. It is not yet implemented in Qt.

`f891bcb` Display confirmations in wallet-tool showutxos

### New code maintainer's public key

@kristapsk is now a maintainer of this repository along with @chris-belcher and @AdamISZ.
His public key is added for verification of commits.

`a5c9d80` Add my public key

### Other changes

There are many commits less of interest to users, relating to: documentation, testing, logging and minor bugfixes:

##### Testing

`06f7358` fix flake errors after #504

`71a37c0` Remove nonstandard scripts from test suite

`7359792` Move Travis-specific install_bitcoind.sh out of root

`635bf32` Pin pytest to 5.3.5, and bitcoind download for travis

`0f13276` Use either wget or curl for downloading deps

`2fe861d` fix messagechannel test

`06a95ae` fix ygrunner test config load

##### Documentation

Includes a new URL for donations and update to the Qt guide

`3e9f0bb` Add explaining text to readme from old repository

`be36438` (pr_518) Windows details on generating joinmarket.cfg

`87fb67a` Update JOINMARKET-QT-GUIDE.md

`7ce6cdc` Add URL for donating without address reuse

`3bafced` Add links to various install guides to readme

`bb1b01e` update INSTALL.md for new libsodium

`0d31f31` (origin/update_todo) updates to TODO.md

`1158e24` update GUI version in JMQT guide

`9eba2dd` Update USAGE.md

`f7fb5b7` Add table of contents

`6433286` Add joinmarket logo

##### Logging

`16cf93a` Display INFO level log message on estimate_fee_per_kb() with result

`0cdd5ac` Add missing space to "matplotlib not found" error message

`a84dafb` Add INFO level log message on IRC disconnect and reconnect

##### Minor bugfixes, changes, refactoring

(The first is minor because it refers to an unused constant)

`42d8780` Made P2WSH_PRE be the correct value

`8bf95fd` Display both BTC and sat amounts in more places

`205ae85` Get rid of most of direct rpc() calls outside blockchaininterface

`5acb85f` [Refactor] Fix get_script_path and get_addr_path

`a0c8446` fixed location path for accessing wallets (in payjoin receiver)

`a51bd55` Fix sweep in GUI

`b3e9a6f` Fix sweep in scripts/sendpayment.py

`cfa032d` bugfix obwatcher options load

`6efbf33` Fix unwanted display of privkeys in GUI introduced in `cbf69c6`

`ce49ea3` Qt: Only show wallet sync in status bar at start

`e15963f` Retry in selectWallet() only on non-fatal errors

`5f85734` Make explicit args in wallet_generate_recover_bip39

`f519909` Check against dust threshold for single joins

Credits
=======

Thanks to everyone who directly contributed to this release -

- @kristapsk
- @takinbo
- @AdamISZ
- @chris-belcher
- @jameshilliard
- @joseortiz3
- @k3tan172

And thanks also to those who submitted bug reports, tested and otherwise helped out.
