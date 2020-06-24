Joinmarket-clientserver 0.6.3:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.6.3>

**Note that this will probably be the last release supporting Python 3.5 or lower.**

Includes a few notable improvements to Qt as well as a few quite important back-end
bugfixes. Upgrading is recommended as soon as possible.

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading 
=========

To upgrade:

If you are upgrading from a version pre-0.6.2 then please see the section "Move user data to home directory" in 
[the 0.6.2 release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.6.2.md),
and follow the instructions there (except the `commitmentlist` file - that can actually
be left alone, the previous release notes were wrong on this point).

First run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.

**Reminder: Python 3 is required; Python 2 is no longer supported as it reached EOL.**

Note that `./install.sh -?` will show the options for installation.

Notable changes
===============

### Lock file name change

While this change is very minor, it can cause confusion if un-noticed. Previously the wallet was kept single access with a file, named wallet.jmdat.lock (or \*.lock where \* was whatever your wallet name is). Since this could result in accidental deletion of the wallet via tab completion, it was decided to change this to .\*.lock - note that many file system explorers/commands will hide this file by default as it's considered of a 'hidden' type. As a reminder, this file must be deleted in cases where there was a system or program crash (you are reminded of this in case it happens).

`92f12ab` Change lock filename from wallet.jmdat.lock to .wallet.jmdat.lock

### Backend fidelity bond wallet support

This feature is not yet enabled in the software, but the Joinmarket wallet now supports both sending to timelocked outputs and to burn outputs. This will be enabled as and when the Joinmarket protocol supports it. See [here](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/14f086bfe485a79f555f6355d6d34932fa858f01/docs/fidelity-bonds.md) for details.

`6b41b8b` Disable creation of fidelity bond wallets

`869ef55` Disable loading of fidelity bond wallets by Qt

`14f086b` Add usage guide for fidelity bond wallets

`2860c4f` Freeze timelocked UTXOs with locktimes in future

`ddb32ce` Rename functions to say "key" instead of "privkey"

`c70183b` Create tests for fidelity bond wallets

`a0a0d28` Add support for spending timelocked UTXOs

`762b1f6` Add watch only wallets for fidelity bonds

`a937c44` Add wallet-tool addtxoutproof method

`97216d3` Sync burner outputs and display in wallet-tool

`255d155` Add merkle proof functions to BitcoinCoreInterface

`2271ce0` Add support for burning coins with sendpayment

`dc715c9` Add timelock fidelity bond wallet sync and display

`ee70cd7` Add support for OP_CLTV timelock addresses

`d86df33` Rename functions which create multisig scripts

`53b056e` Rename variable internal to address_type

### Qt improvements and bugfixes

Most important here is the new amount widget that allows entry of bitcoin amounts in sats or BTC in an intuitive way.

`b1ee2f0` Make BitcoinAmountEdit behave the same on resize as QLineEdit

`d1323f6` BitcoinAmountEdit Qt widget

`48f5ddf` QValidator port number restriction only for ports

`d8fef95` Bugfix: recovered wallet file location

`3cd54cb` Adds JMIntValidator to ensure exact integer range

`6f90e30` Fix "Show seed" in Qt for wallets with mnemonic extension

`e536eb1` Add wrapper shell script for JoinMarketQt

`554ced0` Update all exit() calls to sys.exit()

`cfc4869` Install XDG desktop entry for JoinMarketQt

### Fix commitments recording in jmdaemon

For some time this bug resulted in bots silently ignoring commitments being broadcast in public by other bots (via `!hp2` messages). Whilst
this did not impact coinjoin functioning, it may have erroneously allowed more usages of PoDLE commitments than intended. Removing the reference to `jm_single()` fixes this.

`6d87322` Remove jm_single config var call from jmdaemon

### CLI improvements and bugfixes

This includes a change in default minimum size for yieldgenerators, the ability to query software version with the `--version` flag, and an occasionally important improvement in tumbler behaviour: sometimes attempts to broadcast transactions fail due to 'mempool conflict' (one of the inputs provided by a maker, is already spent). But the algorithm was treating this case very wrongly: it was assuming that the cause of the stalling was that some counterparty responded wrongly (e.g. not sending a signature), and so was re-attempting the transaction with all counterparties who *did* respond; this basically ensured repeated failure, because whatever input was already spent, is of course, always already spent. Instead after this fix, the bot will try again with new counterparties.

`3876c1c` Change shebang to python3 and +x for scripts

`49ea4e4` Correct display of wallet mnemonic extension in cli

`c8d10e5` Add python shebangs to joinmarketd.py and wallet-tool.py

`e5cf95d` Add --version option to cli scripts

`6fa7f4c` Display address for UTXO on wallet-tool.py freeze

`4af9c42` Don't use honest_makers in case: mempool conflict

`d2a1a9c` yg-privacyenhanced: change default cj min size to 0.001 btc

### Quit gracefully if connection to Bitcoin Core fails

Previous to this change, we could get a crash and hang of the process in some cases, if the RPC connection to Core failed, such as when Bitcoin Core stops running, or a network disconnect. After these changes we at least get a clear error message and a shutdown of the Joinmarket bot. In the future, this might be extended to support having the Joinmarket program simply wait until the connection comes back up, but there are some
open questions around that.

`52b9ba8` Initialization of BCI raises Exception not sys.exit

`cc219cc` Handles RPC failure in Qt with message box and quit.

`5ce4b55` Quit gracefully if Bitcoin RPC connection lost

`0c73074` Close wallet when WalletService is stopped.

### Support limited use of scripts and Qt without access to Bitcoin Core

In some cases when an RPC connection to a synced instance of Bitcoin Core is not available, it may be useful for users to be able to see, for example, wallet addresses, or other wallet info such as the seed. This is now supported by setting the `blockchain_source` field of the `BLOCKCHAIN` section to `no-blockchain`. (Note: this option existed already, but it previous to this change only allowed the running of the `ob-watcher.py` script; now it also allows these other things).

`f26186d` Allow accessing basic wallet info without blockchain source

### BIP21 support

This allows users to use BIP21 URLs instead of addresses both in the command line and JoinmarketQt.
The Payjoin referred to here is the Joinmarket-wallet-only protocol implemented already, not the BIP78 new PayJoin standard (which is in [this pull request](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/536)).

`4eced50` Add BIP21 support for Payjoin

`faaf51e` Add BIP21 bitcoin payment URI support to sendpayment.py

`a539345` Implement BIP21 in GUI

### Other changes

There are many commits less of interest to users, relating to: documentation, testing, and minor bugfixes:

##### Testing of Bitcoin amount parsing

These commits principally add extensive testing and appropriate exception raising for our bitcoin amount parsing.

`13436e0` Fix BTC amount formatting for small amounts and add amount tests

`bfe9f35` Raise ValueError on invalid Bitcoin amount strings

##### Documentation

`f2e100e` fix sample schedule for testnet

`031b8f6` Update tumbler doc for the new schedule format

`d275d82` Update readme.md: change Agora-->hackint

`6bd101e` Remove link to old non segwit version and change new version link to use JoinMarket github organization

`cadd8d8` Fix typo

##### ob-watcher improvements

`e8ec595` Shebang and +x for ob-watcher.py

`80333b2` Make ob-watcher independent of current working directory

`8997147` Terminate ob-watcher immediately if HTTP server fails to start

##### Developer (@kristapsk) pubkey update

`9baa04a` Update my pubkey (extended expiration date)

##### Don't use `--txfee` for initial guess

Initial fee guess no longer picks up value from the `--txfee` option, this was a minor bug in that it could end up printing out nonsense
warnings if you used a high value for `--txfee` (which you certainly might, to set the fee in sats/kbyte):

`ec2fd72` Change initial fee guess logic in taker scripts

##### Abort join early with wrong maker count

Fix for both Qt and CLI, taker side: Don't let user try to use a makercount that conflicts with their own config settings (quit early instead of realise it halfway through the join, which could cost both time and commitments):

`5976db7` Abort single join early if maker count below minimum_makers

##### Installation script improvements

`63c21a5` install.sh: use python3 virtualenv

`bf14146` install: fix deb_deps_install for Debian

Credits
=======

Thanks to everyone who directly contributed to this release -

- @kristapsk
- @AdamISZ
- @chris-belcher
- @AlexCato
- @nixbitcoin
- @undeath
- @openoms

And thanks also to those who submitted bug reports, tested and otherwise helped out.
