Joinmarket-clientserver 0.8.1:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.8.1>

This release contains some important new features and some fairly important bugfixes/improvements to performance. Upgrade is recommended as soon as possible.

A note that backing up and then recreating a default `joinmarket.cfg` file is *always* a good idea for a new release; make sure to do it for this release, so that all default values and comments are populated. A couple of new config settings now exist, which you should take note of.

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

### Yield Generator config moved to `joinmarket.cfg`.

This change is one of the reasons for the above note to recreate your `joinmarket.cfg` file. It's not appropriate to have these settings in a python source file, so the same settings are (a) now moved to a dedicated section in `joinmarket.cfg` called `[YIELDGENERATOR]` and (b) *all* of these settings can be modified on the command line when starting the maker; see the `--help` text for the script.

`a490ddf` Move YG settings to a config file

### Signing PSBTs

With the merge of [this PR](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/756) it should now be possible to take a PSBT you created in another environment, where one or more utxos from a Joinmarket wallet are used as input (or a destination is taken from JM as output), and co-sign and optionally broadcast the transaction in Joinmarket. Be aware this is for now experimental, so be cautious.

Basic documentation on this feature [here](../USAGE.md#psbt). 

`631352c` Add support to sign externally prepared PSBT

### Signet support

Signet is a new testnet for Bitcoin that is smaller, quicker to sync (*very* quick!) and supports new features like taproot (though we are not using that, yet). [This](https://gist.github.com/AdamISZ/325716a66c7be7dd3fc4acdfce449fb1) gist can help you set up Joinmarket on signet, which is much more convenient to use for testing, than testnet3.

`8526d73` Add signet support
`b914e75` Separate commitment files for signet and testnet
`1224214` Add comment about Bitcoin Core rpc_port defaults

### Constraining sweep transaction fees

This is a rather complex but impactful issue for any sweep coinjoins - fees are hard to predict but *have* to be estimated before full knowledge of transaction structure. A detailed analysis of the problem is given in [here](https://github.com/JoinMarket-Org/joinmarket-clientserver/issues/784#issuecomment-761057922).

Hence [this PR](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/786). The solution is to constrain the fee to only vary by x% in `joinmarket.cfg`, by default 80% (because there is very likely to be significant variance); it can be changed by resetting the value of `max_sweep_fee_change` in `[POLICY]`.

`8718ce1` Allow user to constrain coinjoin sweep fee.

#### Fix fee information in sendpayments

Logging messages about "tx fee floor" were rather (or very) confusing to users; see [this issue](https://github.com/JoinMarket-Org/joinmarket-clientserver/issues/736). This change makes the information displayed about bitcoin network fees calculated for coinjoin transactions more understandable and useful.

`bb15aa0` `8cdf3e0` Quiet/make more accurate fee information in sends


#### Allow upper/lowercase for BIP21URI as per spec

See [here](https://github.com/btcpayserver/btcpayserver/issues/2110) for background context; Joinmarket contained a mis-application of the spec with regard to capitalization in the "scheme" section (as did a number of other projects). This commit changes the parsing to be case-insensitive, as the spec requires.

`721b6ed` Allow any case for scheme part of BIP21 URI as per spec

#### Reduce rpc calls in transaction monitor

In [this PR](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/795) we prevent the once-per-5-seconds monitoring loop from unnecessarily calling the `gettransaction` RPC call more than once per txid (note: we *do* repeatedly call `gettransaction` on the same txid over *different* loop invocations, since we need to check confirmation status). The correction of this oversight should reduce the number of these calls fairly substantially, although for most reasonably performant systems the difference is negligible.

`4c44932` gettransaction called once per txid in monitor

#### Drop support for pre-0.17 Bitcoin Core

Upgrade your Bitcoin Core if you are still on an (ancient!) pre-0.17 version.

`81982c7` Drop support for pre-0.17 Bitcoin Core

#### Bugfix: allow schedules without payment arguments

Recent refactoring changes had broken the ability to run custom schedules of payments with `-S` argument to sendpayment. This is now fixed.

`462a95d` Allow schedule files without payment arguments.

##### Various improvements and bugfixes

Many small documentation fixes:

`0867166` `c46227a` `6e51e8c` `72d9922` `3e06c57` various typo/grammar fixes

`37cde23` Update Qt guide

`317eaa8` Add libsecp manual build to INSTALL.md

`86fd2cc` Remove comment about old transaction dict format, not used anymore

Some general minor bugfixes:

`0e483f1` Handle None return from _rpc() in get_transaction()

`f21c905` Fix bugs in utxo parsing in add-utxo.py

`20e94b0` cad76da Fix bug in test_taker (max_sweep_fee_change)

`80a324d` Fixes #742 - prevent wallet-tool crashing with wrong argument

`20b67e9` Wait for bitcoind to start instead of hardcoded sleep in tests.

`92c1b1a` Fix tests for Bitcoin Core v0.21+

`192c07a` Abort early and output error if first bitcoin-cli call fails

`184c274` Delete logs and wallets subdirectories from scripts directory.

Somewhat less minor bugfix - this is needed to ensure frozen addresses are actually frozen, in case you use the recovery sync option (usually only used with wallet-tool):

`0ea2c98` populate used_addresses list in recoversync

Other miscellaneous:

This proved particularly relevant for the Windows exe build, but also relates to (and, usually, solves) difficulties people occasionally have running the script version of Qt on Linux, too:

`61edd03` PySide2 version pinned to 5.14.2

Allows hosting ob-watcher with arbitrary URL:

`00be3a3` ob-watcher: Use relative link

The wallet-tool help message should now actually be readable! :

`dee40db` Modify optparse description format for wallet-tool.

The automated script `genwallet.py` for creating wallets is updated to bech32:

`0cd8a73` genwallet p2sh -> p2wpkh

@kristapsk's new public key:

`709db9e` Update my public key

Credits
=======

Thanks to everyone who directly contributed to this release -


- @kristapsk
- @ncstdc
- @dooglus
- @ph0cion
- @nixbitcoin
- @AdamISZ
- @erikarvstedt
- @bitcoinhodler


And thanks also to those who submitted bug reports, tested (especially bech32 testing!), reviewed and otherwise helped out.
