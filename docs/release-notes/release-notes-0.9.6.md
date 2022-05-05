Joinmarket-clientserver 0.9.6:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.9.6>

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

### New p2p onion messaging channels, with directory nodes

**Do not forget to re-create your joinmarket.cfg to activate this!**

This is an implementation of the ideas first laid out in [#415](https://github.com/JoinMarket-Org/joinmarket-clientserver/issues/415), i.e. less or non-reliance on central servers for passing messages. That reliance has disadvantages even considering that the transaction negotiation is end to end encrypted, in regards to speed, scalability, censorship resistance and metadata leakage. So while IRC servers, used redundantly, as pre-0.9.6 Joinmarket, works, it has limitations.
**This does not (yet) mean we stopped using IRC** - this is an added message channel, and all message channels are used redundantly. The user can choose to use any set of message channels they prefer, but the defaults are obviously the best choice for most.
From this release onwards, we have multiple (currently three, managed by @AdamISZ @bisqubutor @openoms) "directory node" onion addresses which serve a similar function to IRC servers with a difference: once takers find makers' onion addresses via this server, they communicate peer to peer. This should result in faster transaction negotiation and the possibility of much larger anon-set coinjoins getting negotiated, as well as being a little better as a privacy model.
The directory nodes function principally as 'name servers' allowing takers to find makers by Joinmarket nick. They also allow 'pubmessage' sending, i.e. sending to every known nick, just as with IRC. Note that these "directory nodes" are ridiculously cheap to set up and don't need any access to Bitcoin core/nodes/wallets/coins. They transfer names and onion locations, and broadcast some messages to clients.

For more details, please read the [documentation](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/onion-message-channels.md).
The default configuration file `joinmarket.cfg` *will* allow negotiation via these new channels. As per that documentation, note that **Tor is now a requirement for running Joinmarket** (except for testing use cases).

(For those interested in the details, please note that this new 'onion messaging channel' functions as *one* message channel, along with the existing IRC server message channels, even though under the hood it consists of multiple directory nodes. 

The original 2 commits contain the bulk of the new code:

* `fd550ee` Onion-based message channels with directory nodes
* `830ac22` Allow taker peers to not serve onions + bugfixes.

Several bugfixes/updates after testing, notably:

* `a278b91` `706bdb0` Directories forward disconnection events

and various minor updates to things like ports, default directory nodes, handshake protocol:

* `1583e4f` `56402af` `6b093bc` `a293da5` `704ffcf` `041ea4a` `fbcb9fd` `cc6d341` `e915dae` `5cc1695`

Testers/developers please review the proposed documentation of the new 'onionmessage' protocol [here](https://github.com/JoinMarket-Org/JoinMarket-Docs/pull/12).

### Change to fidelity bond parameter: the 'exponent'

For the basics read [here](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/fidelity-bonds.md), for the discussion leading to this update see [here](https://github.com/JoinMarket-Org/joinmarket-clientserver/issues/1247), and for the detailed mathematics see [here](https://gist.github.com/chris-belcher/87ebbcbb639686057a389acb9ab3e25b).

Significant community discussion has centered around to what extent the current settings for fidelity bonds are optimal, in particular whether the emphasis on size implicit in the formulas leads to too strong of a centralizing force. Though it's impossible to get a clean consensus, we've decided on two steps:

* Change the exponent which converts the bond's BTC value to its measured 'fidelity bond value' from 2 to 1.3. This number must be larger than one to create a disincentive to spread out the fidelity bond, but there is no requirement that it be any particular value. By reducing this value we make a less extreme emphasis on larger rather than smaller bonds.
* Make this exponent a configurable variable. While it is difficult for many to understand the significance of this variable, still the documentation helps, and for those that want to value bonds differently, they now can, using the config variable `bond_value_exponent`.

We did *not* decide to change the default value of `bondless_maker_allowance` from 0.125, this representing what fraction of makers the taker does not pay attention to fidelity bonds for. This is also user-determined via the config variable, but we were discussing only whether to change the default.

* `044bef6` Change default fidelity bond exponent settings.

In addition to the above, a couple of minor fixes/changes were made to fidelity bond handling:

For future-compatibility with a changed signature message format:

* `1440817` Accept fidelity bonds with ascii cert messages

Fixes a bug whereby the ob-watcher script would not work with fidelity bonds due to not having an address:

* `9594238` Output script instead of address in /orderbook.json

### RPC-API updates

The most notable change here is:

* `a2d6f40` `1d5728f` `43b4eca` Add rpc endpoint for tumbler

This is functional but very limited in user feedback for now; so you *can* run an entire tumbler algorithm via the RPC-API, but in certain edge cases the API client may not yet receive sufficient feedback to handle error states. This is still being actively worked on.

Another small update, allowing auth-ed `/session` requests:

* `c7a2612` feat: validate auth header in session request if provided

* `a04fb60` add tests of /session auth-ed and not
* `7e4d2b1` docs: clarify handling of optional auth token in session endpoint

Bugfixes related to taker/maker state update via the RPC:

* `1510145` Taker stops cleanly if broadcast fails via RPC-API
* `65de6ac` Don't start maker via RPC-API with frozen coins
* `b1542c6` fix: update taker state after fee config check


### Wallet improvements/fixes

A notable overhaul of the way the Joinmarket wallet service functions was added, to reduce CPU cost and/or reduce unneeded polling of transaction events from the Core backend.

* `8fe5b7b` WalletService: clean up and fix callback handling
* `f52bf71` WalletService: reduce polling overhead
* `8d45427` BitcoinCoreInterface: improve _yield_transactions

The following is somewhat related to the above, but was discovered as a bug while analyzing behaviour using the RPC API: the 'confirmations' field of a utxo was not being updated in certain circumstances:

* `09b9747` Always track new transactions until confirmed

The following set of commits handle the issue that Core now defaults to descriptor wallets, which we do not yet use.

* `4e72040` Abort with error if descriptor wallet configured in rpc_wallet_file
* `44b61a1` Always use legacy Core wallet in tests

This improves the `freeze` functionality on command line, so that one can freeze/unfreeze all the utxos in a mixdepth in one action:

* `d832d78` Create un/freeze all command in wallet-tool freeze

### Installation

These are related to a new option to the installation script: to install Tor locally inside your Joinmarket venv, use `./install.sh --with-local-tor`.

* `7a88781` Add support to build and autostart local Tor instance in jmvenv
* `2692f08` Update local Tor config
* `5132342` update install.sh to build tor on macOS
* `8d7d82f` Add local Tor autostart to missing scripts

### Documentation

* `42e6459` User instructed to install from release
* `07cdd3a` add twitter joinmarket onion link to readme
* `97e4816` Update default makercount in USAGE.md
* `fbab9aa` Update YIELDGENERATOR.md
* `2bca836` doc: Document use of legacy wallet in USAGE.md
* `90ec479` Document wallet creation for old Core versions

### Dependencies

* `b4c8bf0` Bump twisted from 21.7.0 to 22.2.0 in /jmbase
* `1407700` Bump local Tor to version 0.4.6.10
* `3eec6e8` docker: remove pip from resulting image
* `5fa4a51` docker: base from buster to bullseye

### Minor changes

A bug in tumbler's `--restart` feature was fixed:

* `df429cd` Fixed so tumbler can restart if no utxos in depth 0

A bug in wallet display when `noblockchain` is configured was fixed:

* `9b15218` Don't crash in wallet_display() with no blockchain source

Better compliance with BIP32 + test:

* `9ab2315` Stricter BIP32 decoding and test vector 5

* `1db2c40` Add cmtdata/ to .gitignore
* `8eefb4d` unused and missing vars in jmbitcoin tx code
* `3b3bd39` Replaces test_full_coinjoin with test_e2e_coinjoin
* `62d7d73` Fix linter errors
* `308f739` Print which option is invalid in shell scripts
* `68fe12b` reorder IRC server config
* `c07fcfc` remove agora from configure
* `4f1571b` Update config-irc-update.md
* `a8e0a4a` Make commitmentlist be in datadir by default.


Credits
=======

Thanks to everyone who directly contributed to this release -
- @dnlggr
- @chris-belcher
- @AdamISZ
- @theborakompanioni
- @kristapsk
- @laanwj
- @bisqubutor
- @decentclock
- @jaimefoo
- @whitslack
- @they-call-me-steve
- @PulpCattel
- @3np

And thanks also to those who submitted bug reports, tested, reviewed and otherwise helped out.
