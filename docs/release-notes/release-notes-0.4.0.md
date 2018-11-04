Joinmarket-clientserver 0.4.0:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.4.0>

This is a significant upgrade, but mostly to features `behind the scenes` that should improve both the
security and the performance (in terms of coinjoin success/quality). However it is not a security critical
release, nor includes any genuinely breaking changes. See the next section, Upgrade, for more details; there
are a couple of minor things you should do when upgrading, but it shouldn't cause any real hassle.

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading 
=========

To upgrade:

First run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.

Next: there is a small but not disruptive task to do: upgrade the wallet file format. Use the instructions
[here](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/wallet-upgrade.md) . Note this
does not require doing transactions, or rescanning Core or anything similarly disruptive; it's purely a file format change (see
"Notable Changes" (under "Upgrade of wallet ...") below for details on this wallet upgrade).
Obviously do keep a backup of the previous format, at least initially, but the new format has been quite widely tested now
and shouldn't cause issues in usage.

Thirdly: this can be skipped for now if you don't have time, but: see
[here](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/config-irc-update.md)
for how to change the format in the configuration
for IRC servers. It's a trivial change that just helps out in situations where one of the IRC servers is down (you can now
just comment it out, unlike before).

Fourthly: (this can also be skipped until later) When running `sendpayment.py` or `tumbler.py` you will be prompted to choose
a specific value for the maximum coinjoin fee(s) per participant, or accept a default random value. Details on the reason
for this below in "Notable changes", under "Order chooser improvement"


Notable changes
===============

### Upgrade of wallet code and wallet file format

The wallet file has changed from a partially encrypted JSON format to a
fully encrypted binary format (dubbed JMDAT). This hides some metadata
previously accessable to anyone having access to the file itself, like
the number and mixdepths of imported keys, how heavily a wallet has been
used, or if it is a testnet or mainnet wallet.

Additionally the password hashing algorithm has been upgraded from a
weak double-iterated SHA-256 hash to Argon2, an algorithm specifically
developed for hashing passwords. This change makes it much more costly
to attack a wallet file with an unknown password.

The encryption algorithm itself remains unchanged. It is still
AES-256-CBC.

Under the hood, the code for storing data on disk has been separated
from the code working on the data. This abstraction reduces the code
complexity and allows easier code review/verification.

Other than that, the wallet code has been completely rewitten, with the
intention of making it more robust, well-structured and universal. With
the new code it will be much easier to abstract the joinmarket codebase
away from specific bitcoin address versions (adding segwit support
required a vast amount of code changes all over the place, in some cases
causing problems with keeping it compatible with the previously used
P2PKH addresses) and possibly even from bitcoin itself (however, there
are no plans to support any other cryptocurrencies than bitcoin). This
will especially be relevant when eventually adding support for native
segwit coinjoins (bech32 addresses) in the future.

a0c1d5a add upgrade notes

8885e61 revert bad assert fix

a929cf3 make log output human-readable again

aa2c1d9 fix some bugs in wallet_utils

9dd1dc7 fix wallet sync in fast mode

98f41f7 make SimpleLruCache an actual LRU cache

703ae04 remove wallet.sign()

34f8600 fix wallet syncing

747c227 fix some max_mixdepth off-by-one errors

39e4276 change default wallet name

8b9abef add is_segwit_mode() utility function

8ca6cfc make sure new addresses always get imported

914a40e adopt wallet_utils for new wallet

cdbb345 remove uses of internal wallet data from electruminterface. NOTE: changes untested, probably breaks electruminterface somehow

1f30967 adopt blockchaininterface for new wallet

705d41d remove usages of wallet.unspent

89b5cd4 add new wallet classes to existing tests

3cf9926 remove references to old wallet classes

2a0757c remove BitcoinCoreWallet

6aaabb2 change yieldgenerator using new wallet implementation, start porting wallet_utils

995c123 replace old wallet implementation with new one

474a77d add setup.py dependencies

ca57a14 add new wallet implementation

455d092 minor bugfixes to Qt for new wallet code

fd0e5b2 Merge #181: new wallet follow-up

3a89ee4 move wallet upgrade docs and improve wallet opening error handling

310fac8 add test for wallet.mixdepth

3921882 change wallet mixdepth behaviour

d3a6dd0 fix old wallet conversion with mnemonic extension

6a26e48 Disallow less than 1 mixdepth in changemixdepth. Maxmixdepth error msg in tumbler: fix off-by-one

fdd0d11 Remove --rpcwallet CLI option

a65b822 fix help msg error for changemixdepth

8f434b5 open wallet in read-only mode if possible

697d8d7 bugfix: sendpayment invalid reference to userpcwallet

### Remove use of deprecated accounts feature in Core

As of Bitcoin Core 0.17.0, the accounts feature is deprecated, and can only still be
used with the flag `--deprecatedrpc=accounts` passed to `bitcoind`. As of 0.18 it will
be removed entirely. Hence Joinmarket has switched over to using the labels feature, instead
of the accounts feature, as of this 0.4.0 release, meaning you should notice no effect when
upgrading to 0.17.0. For more details see the [PR](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/186).

`b52bc06` Switch over to using labels instead of accounts

### Order chooser improvement

This is a small and probably near-invisible change, once configured, but may actually be *very*
important and so is worth understanding:

One weakness of Joinmarket's model is that Takers are very price sensitive (using an exponential
distribution of weighting by price, by default, with the order-choose method (1) `weighted_order_choose`).
The other two non-default options were: (2) pick orders manually (great, but very fiddly/annoying) and
(3) `cheapest-order-choose`, which obviously is maximally price sensitive.

The problem with this heavy price-sensitivity is that Sybils, i.e. attackers who want to participate
in a maximum number of joins to block them or to gain more probabilistic information, or other advantages,
can get a lot of leverage from simply offering ultra-low fees compared to the current market. But zero
fee sensitivity is also senseless, since the whole point is to have an actual market, i.e. prices must matter.

One sensible trade-off is to have the Taker choose a maximum price they're willing to pay, but to be randomly choosing
fees within that range. And that's what the new default order-choosing mechanism (4) `random_under_max_order_choose` is
doing. You choose a maximum absolute number of satoshis per coinjoin counterparty, and a maximum relative fraction
per counterparty, and orders which violate *both* of those limits are rejected. This can be set on the command line,
as a flag, or in the `joinmarket.cfg` file. You can also override the default and go back to any of the three previously
existing order-choose algorithms.

Note that the defaults offered to you are randomized; we don't want all Takers using the same default maximum value, since
that will lead to artificial crowding of fees near those levels; as implemented, this can't happen.

`a2c74ee` add random-under-max order chooser

### Various other minor fixes

Non-developers can safely ignore these changes. The last four are modifications
to the installation scripts, in case that is relevant to your interests.

55c51a9 Remove jmtainter script, not used or maintained currently

03ee77b fix issues highlighted by flake8

9d72573 add flake8 config and enable in travis

bdbf62b fix flake8 warning

59a998f fix int assertions

ebcb640 fix amount fraction comment in tumblerguide

316f866 use libsecp256 @d333521 for secp256k1-py

be1374c install script fixed

a057b87 add setupall.py --all mode

51eb77e update libsodium url and core to v0.16.3 in docker


Credits
=======

Thanks to everyone who directly contributed to this release -

- @undeath
- @fivepiece
- @AdamISZ
- @chris-belcher
- @kristapsk
- @mighty-merganser

And thanks also to those who submitted bug reports, tested and otherwise helped out.
