Joinmarket-clientserver 0.5.1:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.5.1>

This release contains a number of minor improvements bugfixes. All users are
encouraged to upgrade as soon as possible.

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading 
=========

To upgrade (but: read and follow instructions in 0.4.0 if from pre-0.4.0):

First run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.
To install using Python2, use `./install.sh -p python2` ; the default is now Python3.

Note that `.install.sh -?` will show the options for installation.

If you are running JoinmarketQt, note that Python2 is incompatible.

Notable changes
===============

### Make Python3 the default and add a help message to installation script

The `install.sh` can be run with the argument `-?` to show the help message,
which explains the optional flags (`--with-qt`, `--python`, `--develop`).
Python3 is now made the default option, since it seems to be quite stable now and
is clearly preferable; Python2 can be run as an option.

`5ac3aae` Allow more specific --python targets for install.sh

`e1e93cd` Default to python3 install

`3ccd395` `4abe512` `c8ff323` add help menu to install.sh

### Add native segwit wallet to backend

Although not directly exposed in Joinmarket in 0.5.1, this commit represents an
important step of allowing the full wallet functionality using native segwit (p2wpkh)
and bech32 addresses in place of the current p2sh-wrapped segwit (p2sh-p2wpkh); this
is done, still using BIP39 for seedphrases, with [BIP 84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki)
in place of the existing
[BIP 49](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki). As well as new wallet classes this commit make some alterations to
the jmbitcoin library functions (new scripts, signing etc., as well as some updated
documentation in the code). Note that a switch to use of native segwit in Joinmarket
coinjoins is not a trivial decision, as we have to consider anonymity sets,
but it is likely to happen in the future; also there may be other applications
of native segwit wallets.

`2632df5` Native segwit support including basic BIP84 wallet.

### Minor bugfixes following up from the Python3 upgrade

These are mostly clean-up commits of some edge cases discovered
in running with Python3 (wallet history method had a bug; convert_old_wallet likewise;
the electruminterface (which is considered mostly unsupported, but people still like
to try it) had a couple of bugs too).

`5d6825b` Fix bug in convert_old_wallet after Py3 upgrade

`0d1981e` adapt install.sh to Qt with python3

`78d5f7e` python3 fixes for electruminterface

`ad77769` zip(*value_freq_list[1:]) needs to be a list 

### Add more informative labels to wallet display

This commit adds, both to the command line and Qt wallet display, a set of labels for
the utxos/addresses in an active wallet; there's "cj-out" (coinjoin output utxo),
"change-out" (change output utxo), "reused" for when an address has been used more than
once (which should not happen unless the user actively chooses it), "non-cj-change"
and "deposit" (which means coins arriving in the wallet from an external one).

The main commit is `596261a`; the other commits are bugfixes for unintended side effects.

`596261a` `481b688` `0a74b83` `c400b07` implement wallet-tools display[all] extended usage status

### Fix minor UI bugs in Qt

There were some error conditions in the dialogs when running the `generate` method to create
a new wallet, and entering passwords, which are fixed here.

`eaac4be` Fix bug in wallet generate in Qt

`5d66d94` Check for empty password and cancellation in JoinMarket-Qt wallet generation

`51a257f` Don't show password when loading wallet in JoinmarketQt

`cdde41e` Handle already existing wallet file on generate

### Lengthen timeout for transaction broadcast

It was observed that in the case of larger coinjoins, the final coinjoin transaction may
be broadcast after the previously-default 30 seconds, meaning that the Maker may fail to recognize
that the transaction had happened, which while not a security risk, meant that the maker had
a temporarily incorrect view of his own coins and thus made offers that used inaccurate sizes.
The reason for delays longer than 30s are various, but the principal one is that we heavily
throttle IRC communications to avoid hitting server limits; and there is a ~ quadratic scaling
in data transfer for number of participants; so if a Taker requests 10 counterparties, he must send
a very large transaction 10 times. For this reason the number has been bumped to 180s by default
(but it can always be edited by the user in `joinmarket.cfg`, see `unconfirm_timeout_sec`.

(Slightly more in the weeds: we run asynchronously and poll every few seconds for updates on
transactions that we have signed; obviously we can't do that forever for a transaction that is
never going to come; Takers will sometimes just decide not to broadcast, or fail; so we must time
out these polling loops; previously 30 seconds was considered to be ample, but see prev paragraph.
Additionally, note that we cannot lock utxos as soon as a transaction has been arranged, to avoid
the Maker being unclear about what to offer, because this would represent a DOS risk where a
malicious taker just locks up all the Maker's utxos by arranging but not broadcasting tons of
transactions. Hence only the broadcast event triggers the "locking/deleting" of utxos.).

`39d2b62` Increase timeout waiting for coinjoin TX broadcast 

### Add donation address to README

`9e88e86` Add signed donation addresses to README 

### Improve txfee docs

Users should note that "fixed" fees (specified as values of `tx_fees` larger than 144) are interpreted
as a number of satoshis per kB, but that they are *also* randomized by 20%, to avoid the trivial watermarking
of all of that user (taker)'s transactions. If you choose 1000, meaning 1 sat/byte, you are in danger of
creating a transaction that will not relay. This may soon be fixed up further; note for now, that using a
figure < 1200 is strongly disrecommended as the tx might not broadcast (and we do not yet allow rbf).

`d238172` Improve manually selected tx fee documentation

### Write process id to lockfile for checking conflicts

Previously the lockfile informed a user that another process was already operating on the wallet
(it's not supported to run Joinmarket twice against the same wallet simultaneously); with this update
the PID of the other process is displayed. (As before, this can happen on a crash as well as an actual
conflict, note).

`585d2f9` Write pid to wallet lockfile, display it when lock already in place


### Minor changes

Will not be of interest to non-developers (these are mostly changes to tests/very minor refactoring).

`83a1263` remove unused bci.py module

`8256b27` build minimal libsodium

`54618e6` Remove btc.py

`9799f2c` require minimum bencoder.pyx version

`c541b01` Remove unused regex based type detection

`e0f8715` pin coverage+pytest-cov versions, upgrade core to 0.17.1 on docker

`a6a8bcf` only download and extract miniircd if it doesn't exist


Credits
=======

Thanks to everyone who directly contributed to this release -

- @qubenix
- @jameshilliard
- @undeath
- @AdamISZ
- @AlexCato
- @fivepiece
- @chris-belcher
- @kristapsk

And thanks also to those who submitted bug reports, tested and otherwise helped out.


