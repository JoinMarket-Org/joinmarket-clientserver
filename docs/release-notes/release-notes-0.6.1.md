Joinmarket-clientserver 0.6.1:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.6.1>

This is a bugfix release: for users making multiple deposits to their wallet, to avoid having to do extra rescans; see first "Notable Change" below for details. Hence, any user wishing to deposit to the wallet more than 6 times should consider this an urgent upgrade.

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading 
=========

To upgrade (but: read and follow instructions in 0.4.0 if from pre-0.4.0):

First run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.
To install using Python2, use `./install.sh -p python2` ; the default is now Python3 and is strongly recommended.

Note that `.install.sh -?` will show the options for installation.

If you are running JoinmarketQt, note that Python2 is incompatible.

Notable changes
===============

### Bugfix: sometimes addresses were not imported into Core before being displayed

Background: Joinmarket's wallet uses the "watch-only" feature of Bitcoin Core to monitor addresses and transactions. In order to properly track specific addresses, it's necessary to call the `importaddress` (or `importmulti`) method of Bitcoin Core before actually using that address, as transactions involving it before import don't get picked up.

Generally this works as follows: before a particular address is either (a) used in a coinjoin or (b) displayed on the Qt GUI/command line, Joinmarket imports that address.

However a bug existed for quite a long time where using the form of wallet syncing we used to call "fast" (but is now the default for reasons explained in 0.6.0 release notes), whereby some addresses are displayed as available for deposit, which aren't actually yet imported.

As a result, it was possible in 0.6.0 (and also in earlier versions - except the bug usually didn't manifest for slightly complicated reasons) to deposit coins into addresses and not see the coins in Joinmarket's own wallet display (whether Qt or CLI). This would happen only for addresses beyond the initial gap limit (so generally, after 6 deposits in one mixdepth, usually).

What should you do to if this happened to you while running 0.6.0?

This situation can be rectified in two steps: (1) do `python wallet-tool.py --recoversync walletname.jmdat`; this step does the necessary imports (a reminder, the default sync is now the "fast" version as of 0.6.0 and this is still true in the new release), and then doing a `bitcoin-cli rescanblockchain X` where X is the blockheight, choosing X definitely before the deposit transaction (a reminder: `rescanblockchain` is just faster than ordinary rescan, which takes a very long time since it rescans from the genesis block).

After the below commit, the bug is fixed, and any time an address is displayed as available for deposit, it is preimported. Hence, if you didn't encounter the above error, you needn't do anything extra apart from this upgrade.

`f176aad` Ensure all displayed addresses are imported

### Other changes

Payjoin receiver side code would run without the receiver having any utxos to contribute; this commit quits early in that case, with a clear error message:

`1e1b03d` Don't allow receive-payjoin start up without coins

Recovery of wallets with more than the standard 5 mixdepths requires that you specify a number large enough on creation; documentation reflects that (and corrects earlier incorrect instructions):

`936036d` note in USAGE.md that recovery can require -m

`joinmarket.cfg` comments are useful info, here some old links and incorrect data were removed:

`b78b481` remove stale info from default config comments

Older Core wallets sometimes have transactions not indexed by txid, which can cause a crash condition, this is fixed here:

`d05e7a1` Fix bug where listtransactions result omits txid

Upgrade of our encryption library libsodium; API is unaffected and no security issues were found in old version after review, either.

`e5e33a7` Bump libsodium to 1.0.18


Credits
=======

Thanks to everyone who directly contributed to this release -

- @chris-belcher
- @kristapsk
- @AdamISZ

And thanks also to those who submitted bug reports, tested and otherwise helped out.
