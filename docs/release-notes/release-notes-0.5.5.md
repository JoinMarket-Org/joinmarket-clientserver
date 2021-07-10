Joinmarket-clientserver 0.5.5:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.5.5>

This is a minor release with several minor changes - mostly because it is the first
release in several months - some of which are practically important.

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading 
=========

To upgrade (but: read and follow instructions in 0.4.0 if from pre-0.4.0):

First run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.
To install using Python2, use `./install.sh -p python2` ; the default is now Python3.

Note that `.install.sh -?` will show the options for installation.

If you are running JoinmarketQt, note that Python2 is incompatible.

Notable changes
===============

### Default configuration change

Although this is not interesting, it's a practical change that everyone should be aware of. Our default two IRC servers are currently darkscience and Cyberguerrilla (CgAn). The latter had a wholesale change of servers, and while we investigated to ensure the new service is genuine, be aware of course that it doesn't matter if it isn't since everything private is E2E encrypted. Users should keep an eye on long running bots for messaging server failures; while their bots will keep running fine on one out of two (or three), it's good to make sure your availability (as a yield generator) is the maximum. This server failure happened a few weeks ago, and many bots have not updated. The new v3 onion for CgAn is particularly of note. It's **epynixtbonxn4odv34z4eqnlamnpuwfz6uwmsamcqd62si7cbix5hqad.onion** and the port is now 6697. Note that as usual, you can regenerate a default config by renaming or moving your existing `joinmarket.cfg` and then copy back any custom settings as you wish.

`b308e83` Update default configuration: changed CgAn onion

### Minor improvements to Qt GUI

These are mostly minor bugfixes / smoothing out, but of note is that there is now a QR code option for scanning for making deposits, accessible in the context menu (i.e. right click on an address).

`79eb790` Add QR code support to the GUI
`5ffa950` Better default column sizes in "JM Wallet" tab
`3fa0804` Qt error display if fatal sync error happens in Qt
`11d17bd` Bugfix: basename of schedule file path is a tuple in new Qt Previous to this commit, selecting a new schedule file would not "correctly" detect that an unfinished tumble run was selected (note that this "detection" is currently just checking the name of the file, so it may have to be changed in future). The reason for the failure to detect is that in the PyQt5 version, the filenames are returned as a tuple, and so the str() conversion did not match.
`22467f4` Use restartForScan callback in selectWallet

### Syncing improvements

As part of an ongoing project to make syncing Joinmarket wallets less cumbersome (there are too many edge cases where long waits or repeated syncing is necessary), these small changes prevent the most common annoyance, that of being required to run sync twice instead of once after restarting, when transactions have occurred. Users are reminded that the `--fast` option was created to make it much faster to sync a wallet which is fairly heavily used, and that it can be used for all scripts (sendpayment, tumbler, yg); but please note it is also MORE reliable than the detailed (slower) sync, if you have not moved your wallet between Core instances. The latter (non --fast) should only be needed occasionally. More will hopefully be done to improve wallet sync in future, see [359](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/359). Additionally, we switched to using `importmulti` instead of importing addresses individually, which is faster. Also, the user is now prompted to use the new `rescanblockchain` CLI command in Bitcoin, to which you can provide block height arguments, to help speed up those cases where a rescan is actually needed.

`4b4f8c9` Fix bug in detailed wallet sync relating to gap addrs.
`6c15bd7` Make address imports with address requests in wallet Prior to this commit, there was duplicated code in maker and taker modules to import addresses, now all calls to the wallet for fresh addresses can optionally pass a blockchaininterface instance and if this is done, the new address will be imported to the BCI at the same time.
`8d26ff6` Use importmulti instead of importaddress in import_addresses
`d909f62` Hint for `bitcoin-cli rescanblockchain` in `restart_msg`

### Fix several minor functionality bugs

(1) Fix bug where messages could not be verified on one IRC server for some users (DarkScience) due to inconsistent capitalization of the IRC network name (which we use to help provide anti-spoofing, see [here](https://github.com/JoinMarket-Org/JoinMarket-Docs/blob/master/Joinmarket-messaging-protocol.md#for-multiple-message-channels-message-signatures-for-anti-spoofing)).
(2) Fix two bugs in the tumbler when run in --restart mode. One was quite serious, or at least quite annoying: it would send funds back to the wallet instead of out to the intended destination, depending on exact parameters, if run in restart mode. The other was simply ensuring that when the tumbler was restarted, it could always correctly detect whether a previous transaction in the tumble had completed (previous to the fix, this would fail if the outputs of the already-tumbled transaction had been spent).
(3) Fix bug where the Taker bot crashed if the user selected the transaction push option `not-self`. Only the `self` push option (the default) is currently implemented.

`078b2e2` Message-signature-verification: also accept lowercase hostid as valid. The hostid upper/lowercase seems can be different depending on how someone connects to an IRC server (via TOR, clearnet,etc.). This leads to message signature verification failures, if the receiving counterparty has a differently capitalized id.
`6a4a7c8` Bugfix: ensure Taker sends coins out to destinations on tweaks after restarts, instead of sending coins back to wallet.
`3602b93` Restarting tumbler waits on gettransaction not gettxout
`1caf0da` Fix crash when pushing TX via "not-self"

### Extra warning for expensive coinjoins or tumbles

This provides an extra warning on the command line version if a user unwittingly schedules either an individual join or a tumble, with a small enough size for the specified parameters, that the reasonably expected bitcoin network transaction fees to be paid are as much as 5% of the total amount being processed. Users can easily, otherwise, unwittingly, spend a large proportion of the amount they are coinjoining, just on network fees, and this is particularly true when running the tumbler script. They are given the option to abort or continue.
(The fixes here are fixes to this new function, not to existing code).

`af11116` Estimate tx fees for sendpayment or full tumbler run and warn the user if the tx fee estimation exceeds 5% of the funds to be coinjoined/tumbled.
`d62a300` Fix sweeps with N=0 counterparties, which otherwise fails because the amount was changed from 0 too early
`b656f85` Sendpayment/Tumbler: fix division by 0 error on sweeps

### Minor changes

Several minor changes to the documentation, logs/error messages, or testing code.

documentation and logging

`99c0c70` (doc) Update tx_broadcast explanation
`8fb0b35` (docs) explain minimum_makers in joinmarket.cfg
`8140c68` Update Windows instructions
`f3f4aae` skip introduction by Giacomo Zucco
`57061fb` add link to video of demo given during understandingbtc
`3e78b46` add coin control note to README
`c4b40bf` Replace full Understanding Bitcoin video with individual JoinMarket video
`0385a5b` Metion bitcoind 0.17+ requirement in docs
`a7cc1e8` Change 'bitcoin core' to 'bitcoin node'
`f8ec97b` fix typo (s/butfailed/but failed/)
`86d5369` Trivial: more detailed logging on malformed offers and amount of coinjoins
`387704e` Improve error message in unknown wallettool method
`2cb5df4` Output full path/file name of lockfile in a case of lock

testing

`31eabde` Upgrade testing framework to use generatetoaddress.
`b1ca601` Changes to pytest syntax for pytest 5
`de786e0` Increase maker_timeout_sec in regtest to account for throttling
`7b5a127` Avoid "no such file or directory" error


Credits
=======

Thanks to everyone who directly contributed to this release -

- @AdamISZ
- @kristapsk
- @AlexCato
- @chris-belcher
- @d3spwn

And thanks also to those who submitted bug reports, tested and otherwise helped out.


