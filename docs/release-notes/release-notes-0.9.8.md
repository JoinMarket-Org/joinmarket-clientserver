Joinmarket-clientserver 0.9.8:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.9.8>

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

**This minor release is only mandatory for those using the RPC-API. If you use JoinmarketQt and/or the terminal/CLI version of Joinmarket, you may skip it, though installing it won't hurt.**

Changes
===============

### Fix to tumbler stalling via RPC API

This issue prevented the tumbler from continuing when it stalled due to a failed transaction attempt (which is a fairly frequent occurence, but should be fixed by the tumbler 'waking up' after some time, and trying again). This came from an error in the tumbler-related code in the RPC API, and so did not affect users on the command line, or using JoinmarketQt.

* `823d8fd` Don't disallow the stallMonitor in RPC tumbler

### Fixed incompatibility bug from new bond calculator script.

In Joinmarket 0.9.7 we introduced a tool `scripts/bond-calculator.py` that allows a user to estimate the value they get from creating a timelocked utxo as a fidelity bond. Unfortunately one part of that code was incompatible with versions of Python earlier than 3.8, though Joinmarket still supports Python 3.6+. This commit fixes that issue.

* `70aff64` Fix quantiles() compatibility issue

### Check package hashes early

This improvement checks the SHA256 hashes of downloaded packages during installation, before doing the gpg signature validation (note the change related to that in 0.9.7, described [here](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.9.7.md#installation)), rather than after, to avoid unexpected signature validation failure.

* `62dc983` Check sha256 hashes for downloads before GPG signature validation


Credits
=======

Thanks to everyone who directly contributed to this release -

- @AdamISZ
- @kristapsk
- @PulpCattel


And thanks also to those who submitted bug reports, tested, reviewed and otherwise helped out.
