Joinmarket-clientserver 0.9.9:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.9.9>

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

*Users are strongly encouraged to update immediately, mainly because of what is described in the first section below, on "Onion messaging related fixes and changes".*

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

### Onion messaging related fixes and changes

#### Changes to directory node defaults

We have removed one of the directory nodes that was proving unresponsive, and added a new one. These of course are only defaults; this list may change quite often (more often than the IRC list used to, probably!). We will investigate ways to let users find other directory nodes than just this list, in future.

We also increase the timeout for making the initial connection, as onion service connections can sometimes be very slow.

Note that this is also related to the following topic (slowing down connection reattempts).

* `8ab2d50` Increase directory node connection timeout to 60s
* `ebdbac7` Update configure.py
* `7aebed7` Remove jmdirjmioywe2s5jad7ts6kgcqg66rj6wujj6q77n6wbdrgocqwexzid.onion directory node from default config

#### Slow down connection reattempts to directory nodes

Several users reported not only a failure to connect to directory nodes, but also a very rapid cycling, attempting to reconnect every couple of seconds. Here we fix that bug, and ensure that connection attempts back off exponentially, eventually slowing down to once per ~ 3 hours. This will clear up spam from the log, but also may help, *if* the problem is related to DOS limits in Tor (further investigation is required), once all users update to 0.9.9. **This is one of the main reason users are encouraged to update immediately**.
* `9a412d8` Connections to dnodes slow down

### New public orderbook

http://nnuifroxn5aolsqa2svedcskojlqfp2ygt4u42ac7njehsbemagpwiqd.onion/

Provided by @kristapsk, added into README. As usual, users are advised that they can easily run their own orderbookwatcher on localhost, and this will be better in most situations.
* `34fa1b6` Add link to my public orderbook mirror


### Correct errors in transaction size estimation

This set of commits corrects pre-existing errors in estimation of transaction size, for nonstandard outputs. These errors were usually tiny and didn't matter, but caused problems for cases where a very low sats/vbyte was set by the user. In particular, the cases of spending to or from fidelity bond addresses (which are of type `p2wsh`), or spending to taproot addresses (`p2tr`), were not being calculated correctly.

We also added tests of our transaction size and weight estimation.

There can still be edge cases if the input or output type is unrecognized (most plausible case would be a customized script being spent, in a PSBT; it's not really possible for this to happen with Joinmarket's own coins), but the error in size (and therefore fee) estimation will still be small, even in these very exceptional cases.
* `bffad33` Tx size estimation allows varied in, out types `357b611` `c1d7f02` `e281c14` `7bf6696` `4921d01` `6250d24` `db71d30`

### Fixes to sendpayment

Two bugs in sendpayment were fixed:

Allowing sub-27K sats for non-coinjoin payments (our `DUST_THRESHOLD` is not "the" Bitcoin dust threshold, it was deliberately set higher to account for certain estimation uncertainties related to coinjoin; but they are irrelevant for non-coinjoins):
* `d6d40df` Allow amounts below DUST_THRESHOLD (0.00027300 BTC) for non-cj direct sends

Fixes a bug where sending to a BIP21 URI fails (bug as described [here](https://github.com/JoinMarket-Org/joinmarket-clientserver/issues/1356#issue-1384971769)).
* `9d9035b` Fix sendpayment without amount argument, BIP21 only

### Switch to venv from virtualenv

`venv` is provided as standard in all versions of Python that we support, so we don't actually need the dependency `virtualenv`. This removes it; there is no impact at the user level.
* `11ddec7` docs: Remove now-confusing mentions of virtualenv
* `6e3b6ec` Dockerfiles: Use Python venv instead of virtualenv
* `8bbca60` install: Use python3's venv module when available

### Bugfixes and minor changes

This fix prevents directory nodes crashing in certain edge cases:
* `bfb0e25` Account for missing nick fields in OnionPeer

This fix ensures fee randomness works even when a fee estimate can't be sourced from Core:
* `3d0f2d6` fix: randomize fallback transaction fee

* `2e44f00` Log IRC connection attempts when using SOCKS5 proxy or TLS too

* `2749da1` change payjoin default binding port

This was a rare to trigger, but pernicious bug: a user's wallet could show incorrect balances, if the RPC calls to the blockchain failed (the code in `sync_unspent` was incorrectly ignoring this failure), this is no longer allowed:
* `0b34e0b` Abort sync_unspent if blockheight RPC call fails

### Documentation

* `50e3196` Update onion-message-channels.md
* `44aea32` Fix typo in `gettimelockaddress`
* `b34b932` Correction to docs: no coinjoin spends of FBs
* `4c53bb5` Update link to RaspiBolt installation guide

### Installation and dependencies

* `63d74bc` Call num_cores() only after deps_install()
* `7d0ca22` Update local Tor to 0.4.7.12
* `01dc08a` Update local Tor to 0.4.7.13
* `e47f082` Allow to run install.sh from any current working directory
* `46013d2` chmod +x scripts/jmwalletd.py
* `8a25e3a` Pin remaining deps to specific versions, except for Qt and tests
* `22c13b0` Remove unused code instead of commenting out

Mostly applies to the shell scripts used for installation, hence included here:
* `b928713` Add ShellCheck linter script
* `4f0eebc` Apply all current shellcheck suggestions to rest of the scripts
* `f0b9872` Apply all current shellcheck suggestions to install.sh

* `bd5508c` Minor improvements for question prompts and feedback

* `5b8ef40` jmbitcoin: eliminate dependency on urldecode

* `1e159df` Update bencoder.pyx to 3.0.1

### Testing

* `61b6400` Tests: bind to any first free TCP ports instead of hardcoded ones
* `1370c12` Use different jm_test_datadir for each local user
* `06c29c2` Keep trying to receive websocket notification in test
* `3c8f247` CI: Run tests on both Linux and macOS
* `c4d9b92` tests: make setup fixtures optional.
* `a9deacc` Refactor `conftest.py`
* `980edd6` CI: Add Python 3.11
* `7b4c42a` Remove dead code
* `8d2a664` Fix for recent Bitcoin Core versions and add type hints
* `b59fdcd` Remove Python 3.6 (EOL), add 3.10
* `890dd50` Bump pytest version to 6.2.5

Credits
=======

Thanks to everyone who directly contributed to this release -

- @dongcarl
- @whitslack
- @hellodarkness
- @theborakompanioni
- @nyxnor
- @AdamISZ
- @kristapsk
- @PulpCattel

And thanks also to those who submitted bug reports, tested, reviewed and otherwise helped out.
