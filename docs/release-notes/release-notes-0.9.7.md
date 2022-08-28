Joinmarket-clientserver 0.9.7:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.9.7>

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

Notable changes
===============

### Tumbler algorithm: fix, and cycling

This is a notable reworking of the tumbler algorithm, mostly motivated by finding an error which was causing failures for people that tried to use more than the default number of mixdepths (0-4). The tumbler is now able to work with the standard 5 mixdepths, even if you want to tumble through more mixdepths than that.
Also "restarting" is now the same as starting; it will operate based on whatever mixdepths are funded, there is no "starting mixdepth".
For details see the substantially updated [tumbler guide](../tumblerguide.md) which now has algorithm examples, and the explanation of the fix and change in the [PR](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/1324).

* `d3dc9d7` Change tumbler algo to cycle and add tests, and `d0bf888` `7ffc747` `e5ed7f2` `c0df868`
* `b4e4f2a` susbstantial rewrite of tumblerguide.md
* `524cbda` update Qt for new tumbler algo
* `75c444e` Update wallet_rpc for new tumbler code

### Disallowing utxos with unconfirmed spends

This fix is a bit technical but very important. The TLDR is that it should remove a common issue of makers sending spent utxos to takers as candidates for coinjoins, which affected some users. See [the PR](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/1295) for some detailed discussion.

`a3e1ba3` Default 3rd argument of gettxout should be True

### New script to calculate fidelity bond values

This new script is intended to help users make more informed choices about fidelity bonds. It gives data on the value of the bond dependent on locktime and amount, and optionally can compare with existing bonds in the orderbook (using a json export of the latter).

* `72bf447` Script: Add bond-calculator.py

### New display of 'available' balance

This new feature in the UI (both CLI and Qt) displays tags 'FROZEN', 'PENDING', 'LOCKED' to indicate the status of different utxos (with 'PENDING' meaning unconfirmed). Available balance is distinguished from total balance with parentheses.
As you can see from this description already, the situation is substantially more complex for Joinmarket than for simpler wallets because there are at least 3 ways in which utxos' usability might be restricted, and this is not necessarily the same for all use cases (e.g. maker vs taker). Still, this UI addition gives the user a lot more information.
This additional 'available balance' information is now also returned in the RPC API.

* `015cb4a` If there is unavailable fund, display 2 balances: total balance and unlocked balance.
* `ea6c34d` update yaml for new available_balance fields
* `75a93df` fix available_balance

We also had to update the json-ified wallet display to accommodate this:

* `08581f8` Fixes json serialization of wallet display

### RPC-API updates

There continue to be several small updates to the API, most notable this time is the addition of schedule status to the `/session` endpoint.

* `8ee6b39` Report offerlist in /session call if possible
* `b2ab4db` add nickname field to session response
* `2cb41fc` review: reaqd schedule from taker object, also `190d56e` `57d1476`
* `ab2803e` fix: include schedule in session instead of status flag, and `521189a`
* `77496cd` Disallow RPC directsend if coinjoin state enabled
* `cde5cfb` feat: scheduler status flag in session
* `3f358ed` Add options to scheduler API endpoint
* `12bcbe1` docs: add flag to session response spec

### Tor updates

* `adc11a1` Add separate documentation for Tor configuration
* `f8497f0` add missing text to tor.md
* `d46a2c6` Use valid tor_root also for tor_install()
* `5e9044e` Install Tor binaries under /usr/local for --docker-install

### Qt changes

We now allow access to the xpub information in the Qt interface (previously it was not displayed in the GUI).

* `d95e279` Display the account xpub in QT interface
* `e4f249a` Show QR code for xpub

### Installation

The installation now will automatically check release GPG signatures for libsodium and Tor; this can be switched off with `--no-gpg-validation`.

* `be51866` GPG release signature validation for libsodium and Tor

### Documentation

* `7f2c965` Fix "Using Tor as a Maker" table of contents link
* `baa1d48` Add link to JoininBox to README
* `e42f829` docs: fix link in SOURCING-COMMITMENTS.md
* `94a43ab` docs: link to latest version of start-dn.py script
* `bb79a6d` Remove hint to restart Bitcoin Core with -rescan parameter
* `4d4cae5` docs: Creating Core wallet is required for v0.21+

### Dependencies

* `da88b1f` Bump local Tor to latest version (0.4.7.8)
* `48935fe` Bump pyjwt from 2.1.0 to 2.4.0 in /jmclient

### Minor changes and fixes

Fixes a non-trivial edge case where the application starts up
with a currently unconfirmed transaction:

* `5a7b68b` Track txs which are unconf at process startup

Allows `bitcoin:` prefix in `sendpayment.py` (we alreadly allowed BIP21 URIs):

* `83c6bc0` Allow bitcoin: prefix for addresses with sendpayment.py

Test-related changes:

* `74616f0` Refactor tests to make fidelity bond usage optional.
* `8f60cf0` Bump minfeerate for payjoin test
* `36bf36b` fix: enable addr status in regtest

The orderbook.json file returned by the ob-watcher service was wrong in certain cases:

* `2b277b0` fix(ob-watcher): consistent orderbook.json response

The maker already doesn't start without any coins, but this fixes the edge case where it currently has timelocked coins but no others:

* `904cb35` Don't start maker with only expired-timelock utxos

We don't yet have descriptor support; this is a first step:
* `fc5bda4` Basic output descriptor functions (generate only)

Other minor changes:

* `38d00e5` Remove unused CLI options in tumbler
* `447cdb2` Change verbosity of on_nick_leave_directory log message from info to debug
* `c2abb93` Ensure OnionDirectoryPeerNotFound is raised
* `67d0801` multiple spaces after operator


Credits
=======

Thanks to everyone who directly contributed to this release -
- @dnlggr
- @BitcoinWukong
- @AdamISZ
- @theborakompanioni
- @kristapsk
- @chris-belcher
- @PulpCattel


And thanks also to those who submitted bug reports, tested, reviewed and otherwise helped out.
