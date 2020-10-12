Joinmarket-clientserver 0.7.1:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.7.1>

This release requires Python 3.6+ - see "Upgrading" section in the 0.7.0 release notes for more information if needed.

This implementation includes support for **receiving BIP78 (payjoin) payments** (0.7.0 introduced sending them), in Qt GUI or on command line, using either current P2SH segwit wallets ('3' addresses) or native bech32 wallets ('bc1' addresses).
To support this, Joinmarket spawns a Tor onion service ("hidden service") temporarily for payment receipt, for maximum privacy.

There are a few other fixes and improvements as listed below.

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading 
=========

To upgrade:

(If you are upgrading from a version pre-0.6.2 then please see the section "Move user data to home directory" in [the 0.6.2 release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.6.2.md), and follow the instructions there (except the `commitmentlist` file - that can actually be left alone, the previous release notes were wrong on this point).)

(If you are upgrading from a version pre-0.7.0 please read the "Upgrading" section in [the 0.7.0 release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.6.2.md).)

First run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.

Note that `./install.sh -?` will show the options for installation.

Notable changes
===============

### BIP 78 (Payjoin) Receiver

Joinmarket should now be able to send *and* receive payjoins.

For help in usage, see the [documentation](../PAYJOIN.md). There is also a simple video demonstration [here](https://video.autizmo.xyz/videos/watch/7081ae10-dce0-491e-9717-389ccc3aad0d).
This completes Joinmarket's implementation of [BIP 78 Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki). The receiver uses a Tor onion service, so Tor must be running on the receiver's machine (see the docs for some details on this). There have been some limited compatibility tests with other wallets, but more testing in the field will be helpful (please report on this github repo if you find issues in using).
Note in particular that the wallet type (native segwit, or p2sh segwit) may be a relevant consideration, and also don't forget that BIP78 is designed to make sure the payment goes through, even if the coinjoin element fails.

Note, the PSBT and python-bitcointx bump commits are a result of testing with [Wasabi](https://github.com/zkSNACKs/WalletWasabi/) that revealed a new (last few months) addition to BIP174 (PSBT) that allows NONWITNESS_UTXO fields to be included along with WITNESS_UTXO fields to aid hardware wallet security. These commits allow Joinmarket to correctly process PSBTs that choose this option.

`23d0b8f` BIP78 receiver over a Tor hidden service.

`2b898be` Fix finalization check of PSBT Inputs

`2da073b` Bump python-bitcointx to v1.1.1.post0

`9886553` Adds close button to BIP78 receiver dialog

### Transaction broadcast via peers

A long standing issue since Joinmarket-clientserver was created as an alternative implementation: the original version of Joinmarket allowed participants to request transaction broadcast over the message channel, instead of broadcasting it themselves, for further obfuscation. But part of the code required for this was not implemented. This update corrects that, and now both `random-peer` and `not-self` broadcast options (set in `[POLICY]` `tx_broadcast` config option), as documented in the config file, are allowed again.
Note, however, that while many bots are not updated to this version, very often your bot *will* fall back to broadcasting the transaction itself, because the bot you requested this action from simply ignores the request in the old code. This is noted in the config comments.

This patch was prompted because a recent update actually resulted in choosing this option was causing a crash rather than a broadcast failure.

`d209d4d` Fixes #368. random-peer and not-self tx broadcast.

`4440ffb` Taker broadcasts tx after unconfirm_timeout_sec.

#### Add wallet generation script.

This is not recommended for general users (care needs to be taken over passwords and seeds), but a script `genwallet.py` is added to allow non-manual creation of a wallet for those people scripting automation tools.

`93f0a67` `2f53c5f` Add genwallet.py script, add create_wallet tests

#### Ob-watcher improvements

Running ob-watcher locally should be simple enough since it doesn't require Bitcoin Core, but we no longer require installation of matplotlib either (which is a rather large python dependency). Also some untidy number formatting in the main orderbook table is cleaned up.

`6d62661` Allow running ob-watcher without matplotlib installed

`942ea58` Fix relfee cjfee display issues caused by the use of float

##### Various improvements and bugfixes

Of note here: command line now shows UTXO account/mixdepth info (as Qt already did).

`d946009` add mixdepth information in the list of utxos returned by the showutxos command

`0e5eb2f` More verbose absurd fee exception message

`5c85a3d` Log sendrawtransaction errors as warning not debug

`8d63cb8` correct sendpayment help message for -N

`2076dbf` Improve checks for send ("Single Join") in GUI

`5af2d49` handle Qt wallet load failure

`a2aafd2` `202f8ee` `5604857` Fixes [#673](https://github.com/JoinMarket-Org/joinmarket-clientserver/issues/673). Shutdown cleanly on failure to access blockheight

##### Documentation

The only change in this update is more notes on wallet creation and setup with the Core RPC wallet function.

`f6c980b` `f674388` Update Walkthrough with wallet creation steps, add clarifying notes on rpc wallet settings for Core
 

##### Installation script improvements

`03075a0` Fix libsecp256k1 build on FreeBSD


Credits
=======

Thanks to everyone who directly contributed to this release -

- @kristapsk
- @takinbo
- @jleo84
- @AdamISZ


And thanks also to those who submitted bug reports, tested, reviewed and otherwise helped out.
