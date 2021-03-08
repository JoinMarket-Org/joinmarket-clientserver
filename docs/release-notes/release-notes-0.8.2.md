Joinmarket-clientserver 0.8.2:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.8.2>

**REQUIRED UPGRADE FOR TAKERS** - to fix a bug introduced in 0.7.0 that revealed information about inputs to makers. Read [here](#bugfix---stop-takers-from-sending-info-revealing-transaction-inputs-to-makers) for context on this bug.

It is not necessary for makers to upgrade, but best Joinmarket practices should involve using the Taker role anyway, so upgrading is strongly recommended for all.

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

### Bugfix - stop takers from sending info revealing transaction inputs to makers

In [this PR](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/536), merged July 2020, a refactoring change in the taker code had a very nasty side effect. Here's what the bug did:

* markers placed in the scriptSig of the prepared-to-sign (but not yet signed) transaction, which were only for the taker's internal record keeping, were now accidentally also included in the version of the transaction sent to the makers.
* this allowed makers to trivially (if they so chose) read from their log files, which of the inputs, in the coinjoin they participated in, belonged to the taker.

This was an unnecessary and unintended sharing of information with the makers in the transaction. As important context, here's what the bug did *not* do:

* It was a privacy failure w.r.t makers, but not a coin loss risk
* It did not give away the output address of the taker (that's the fundamental promise of these style of coinjoins, but it's a promise only honored for takers remember; as coordinator, the taker always knows the maker linkages in Joinmarket).
* It did not publish privacy-losing information on the blockchain, i.e. not to the public, but specifically to the makers in that transaction (in their log files).
* The most nuanced point, but important: the reveal, to makers, of taker inputs, was *mostly* revealing what is already deducible on the blockchain, by simple arithmetic - but the key word there is *mostly* - there are many cases where the taker's input is not revealed by arithmetic, and indeed that's a strengthening of the effect of the coinjoins. Revealing them to the makers was a significant failure in that regard.

The fix in [this PR](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/822) removes the method of essentially "watermarking" the taker's inputs with a random set of bytes `0xdeadbeef` and instead just checks which inputs belong to the taker; this removal is thus also a code cleanup, but mainly, it removes the need to send a *distinct* copy of the transaction to the makers, without watermarks, while keeping a watermarked copy locally (this was the situation before the introduction of the bug in July 2020).

`a340f06` remove magic 'deadbeef' identifier from taker.py

### Adds SNICKER for testing

[This PR](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/768) is now merged, and adds several tools for Joinmarket users to co-sign (as "receiver") or also create and publish (as "proposer") SNICKER-style coinjoins. For more information on what this is, read the [documentation](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/SNICKER.md). Notice that this is by default switched off. Yieldgen bots can have this service running in the background to receive SNICKER coinjoins, but that specific function is explicitly disabled for mainnet, for now; use of signet is recommended for those wishing to experiment, but if you did wish to try this out on mainnet, it's better to use the manual receiver script.

Also, those not interested in *this* function might still be interested in the script `scripts/snicker/snicker-finder.py` which can be used to scan for Joinmarket coinjoins with the `-j` flag.

`53a1822` Adds SNICKER functionality

`a857c12` disable for mainnet yieldgens

### Payjoin bugfixes

While other refactoring work is going on for payjoin, the basic functionality was discovered to have a couple of bugs, one very minor but the other quite meaningful.
The minor one was in Qt: the payjoin code was trying to broadcast the fallback after the success of the payjoin transaction, which results only in misleading log messages, but this was fixed.
The bigger one: if receiver's payjoin transaction used multiple of its own inputs, there was a bug in the sanity checks carried out by the sender that resulted in these proposals being rejected, and falling back to the non-payjoin payment; this has been fixed.

`65b06ef` Fix Qt BIP78receiver trying fallback after success

`dc4a5b2` Bugfix: correct check of receiver inputs in BIP78

### Improvements to ob-watcher function

The main point here is explained in [this PR](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/803) which addresses issue #804. Local hosting removes the risk of MitM attacks and privacy leaks (e.g. leaking the IP address of a user of Joinmarket).

`fc74c94` add missing jquery lib to ob-watcher.py

`5f82196` fix ob-watcher.py serving from relative location

`693609e` Vendorize js and css dependencies

`ddcfd60` simplify ob-watcher.py static file serving code

### Add per-mixdepth view for wallet-tool

This commit allows users to view in `display`/`displayall`/`summary` method, the information for one mixdepth only, rather than all.

`3f47813` Fix mixdepth option (-m) for wallet-tool's display/displayall/summary methods

### More minor fixes and improvements in the following:

##### Bugfix: convert_old_wallet using correct wallet type

The conversion script for very old (json formatted) wallets to the new jmdat format had a bug, fixed here.

`67791ed` provide wtype to get_wallet_cls

##### Update agora IRC server info

See https://anarplex.net/agorairc/connect/ . Agora *may* now be working as an additional optional IRC server, with an updated onion address, though it has not been added here to the default enabled servers.

`b498b18` agora's tor address changed

##### Avoid erroneous "FAIL" messages in installation

`0fb0cb9` Check for file existence before trying sha256_verify

##### Pin python cryptography package version

See [this issue in the cryptography repo](https://github.com/pyca/cryptography/issues/5771) for details; Rust was introduced as a dependency in newer versions, even though some systems don't have it available.

`b1ac4f6` Pin cryptography module to v3.3.2

##### Fix a formatting error in a help message

`9d7f332` Correct formatting of sendtomany help message.


Credits
=======

Thanks to everyone who directly contributed to this release -

- @gallizoltan
- @kristapsk
- @undeath
- @nkuttler
- @AdamISZ
- @3nprob

And thanks also to those who submitted bug reports, reviewed and otherwise helped out.


