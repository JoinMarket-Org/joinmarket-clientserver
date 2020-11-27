Joinmarket-clientserver 0.8.0:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.8.0>

This is a major upgrade release, in one specific sense: the native segwit orderbook is now available, and wallets, by default, are created native segwit (bech32, i.e. addresses starting with bc1 on mainnet). Please read "Native segwit (bech32) order book" below for details.

There are also several minor bugfixes.

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

### Native segwit (bech32) order book

See the [native segwit upgrade guide](../NATIVE-SEGWIT-UPGRADE.md) for details. From this release, new wallets will be created as native segwit by default. This setting can be changed by setting `native=false` in the `[POLICY]` section of `joinmarket.cfg`.

*Note that native segwit wallets are not a new feature: we have had them since [version 0.5.1](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.5.1.md#add-native-segwit-wallet-to-backend) and they have been used for payjoin experimentation*, what is new is only the default, and the use in Joinmarket coinjoins.

If you create wallets, and run Takers and Makers with the default settings, you will be using only native segwit for your coinjoins and other transactions, and will only join with other participants using native segwit. Note that everything about pre-existing p2sh coinjoins and transactions still works as before, if you disable as per the above `native=false`.

`ab87db2` Create native segwit v0 order type

`2ae348b` Update signature exchange and verification for bech32

`3c96d41` Several tweaks for bech32 orderbook, plus docs

`ebd54d6` Bugfix: yg-privacyenhanced non-integer fees

`3537b70` Update transaction parameters

`9e66bc5` Update ob-watcher

`f69cb37` Choose maker offers based only on our wallet type

#### Bugfix: correct minsize calculation for yield generators with reloffers, and txfee contribution

A bug in the calculation of yield generator minsize, for reloffers, was previously not resetting it to a higher value to account for the txfee contribution; this is fixed. A consequence of this: default txfee contribution value is changed from 100 to 0, to avoid confusing yield generator users who might not understand the reason their number of coins is insufficient (it is a function of both the relative fee setting and the txfee contribution setting, to ensure that the profit is always at least 20% of the latter). The complexity of this should probably be removed in future updates to the protocol.

`dcfc610` Bugfix: allow minsize dynamic update

`d1ae07d` set default txfee contrib to zero, improve error message

#### Don't fail on whitespace in recovery seed entry

In entering recovery seed phrases on Qt and command line, we now ensure that white space is always stripped appropriately; prior to this fix, unexpected failures could occur due to whitespace being interpreted as a word in the seed phrase.

`29b274e` Strip whitespace from beginning and end of mnemonic on wallet recovery

`5f07872` allow multiple whitespace in mnemonic entry

#### Make libsecp256k1 tests optional in installation script

This option is enabled with the `--disable-secp-check` parameter of `install.sh`, and is useful for people on more constrained devices who want to speed up installation.

`aa3cec4` Make libsecp256k1 tests optional

#### Update commitments utilities scripts

These fairly minor scripts needed to be updated for the new bitcoin backend, and bech32 wallets.

`cc78dae` Update commitments utility scripts

##### Various improvements and bugfixes

`d5cf387` Get rid of remaining direct rpc() calls outside blockchaininterface.py

`f314333` Add commitmentlist from rootdir to gitignore

`6aa300a` (pr_728) Fix relunit selector

`6300eda` Re-introduce pillow dependency, seems to be need by qrcode itself.

`44c9dcd` (pr_726) Remove twisted logging on testnet

`394e672` Add link to orderbook.md

`29458f8` Remove dead code

`1b6beda` Remove /shutdown from ob-watcher


Credits
=======

Thanks to everyone who directly contributed to this release -

- @jules23
- @kristapsk
- @PulpCattel
- @nixbitcoin
- @AdamISZ


And thanks also to those who submitted bug reports, tested (especially bech32 testing!), reviewed and otherwise helped out.
