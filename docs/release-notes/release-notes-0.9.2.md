Joinmarket-clientserver 0.9.2:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.9.2>

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading
=========

To upgrade:

(If you are upgrading from a version pre-0.6.2 then please see the section "Move user data to home directory" in [the 0.6.2 release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.6.2.md), and follow the instructions there (except the `commitmentlist` file - that can actually be left alone, the previous release notes were wrong on this point).)

(If you are upgrading from a version pre-0.7.0 please read the "Upgrading" section in [the 0.7.0 release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.7.0.md).)

(If you are upgrading from a version pre-0.9.0 please read the [release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.9.0.md) to find out how about [fidelity bonds](../fidelity-bonds.md) are relevant to your use-case).

First run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.

Note that `./install.sh -?` will show the options for installation.

Notable changes
===============

### Re-enable Agora as a third IRC server

This change is placed prominently and mentioned in the release summary, because it's a change we want all users to notice: enable the Agora IRC server, so we have 3 by default, since there are reports that the hackint server is proving unreliable at the moment.

Remember that the default config (which you should always re-generate with each release and then apply your own settings) does not have Tor enabled; uncomment the relevant lines (in `MESSAGING:server3` in this case) to enable Tor.

It is still very much user choice though: you can choose any combination of servers you prefer, but obviously the defaults will likely contain the most users.


`fb9f593` Re-enable Agora IRC in configuration defaults

`d0966c3` Update Agora Tor host to onion v3

### JoinmarketQt chooses by fidelity bond by default

This is the main reason for the new release; on command line, takers now make their randomized maker choice weighted by fidelity bonds, but an oversight meant that for takers using JoinmarketQt, the default order choice mechanism was still the old randomized one, not weighted by fidelity bonds. This is now corrected so that Qt users get the same benefit of Sybil resistance, which was the point of the fidelity bond update in Joinmarket 0.9.

`8085a4e` Set `fidelity_bond_weighted_order_choose` as default

### Enable opt-in RBF for direct sends (non-coinjoin payments)

Under the hood our direct send code supported setting the opt-in RBF flag, but it is now made an option (`--rbf`) in CLI, for making payments. Note that this is only the flag-setting part; there already is a PR #1019 that will create a user script to actually create the replacement transaction. For now that is only possible by creating a PSBT, which is a bit non-trivial for most users.

Note also that to add this feature to coinjoins isn't really practical as it means re-signing by counterparties who are not still connected.

`b19888e` add opt-in rbf support for direct sends

`635f3f1` Adds test case for fee bumping a tx using PSBT

### Various QT improvements

The second of these (which are self-explanatory), is minor in itself, but is probably the start of a rationalization of the existing rather messy Qt code into a more harmonious form. Hopefully! (This will be of little interest to users though, except in as much as it should make the Qt app a little more user-friendly over time, if progress is made).

The third is also practically useful: if Qt misses a recent update, you can force a refresh of the wallet with the right click (context) menu, on the wallet pane.

`6ff1a65` Hide the donateLayout as it is currently disabled.

`1dd1679` Show an OpenWallet dialog upon launching JoinMarketQT

`f50fa4f` Add a menu action to force wallet refresh

### Backend code refactoring

These changes are not relevant to users, but important for any future development: we remove issues around encoding/decoding of data types from the business logic (mostly, the Taker and Maker code) for better encapsulation.

`7dcd3f3` move client/server data encoding to twisted

`e082c3c` remove unneeded hex encoding/decoding from sent_tx + push_tx

### Updates to genwallet.py

This script (whose name is self-explanatory) is not part of users' normal workflow but useful for people running Joinmarket in certain environments. It's updated for fidelity bonds and somewhat refactored:

`53e7bf1` genwallet.py: Add option --recovery-seed-file

`e4be034` Extract function `read_password_stdin`

`c5621ad` genwallet.py: Enable Fidelity Bonds by default

`91a8f7f` genwallet.py: Minor improvments

`c944046` chmod +x

### More minor improvements and fixes

The least minor of this set: this enables fidelity bonds for the manual order pick option (`-P`) on the command line:

`0e80b2d` Show fidelity bond value in manual order picking

These two fixed a bug after the dust_threshold was corrected, so although minor, they are needed for ob-watcher to function properly:

`7eaf368` Fix ob-watcher script after dust threshold change

`ab9b1a8` fix test of AMP commands for dust_threshold


`2ed3f21` Update the url links in setup.py files

`801dfa3` Fixes #991 - remove get_config_irc_channel

`7c4ba09` remove executable bit

`f93ccf0` remove unneeded shebangs

`dfc82ab` various whitespace fixes

`2fdebb8` do not call reactor.stop() in test_commands.py


Credits
=======

Thanks to everyone who directly contributed to this release -

- @wukong1971
- @kristapsk
- @takinbo
- @erikarvstedt
- @undeath
- @AdamISZ

And thanks also to those who submitted bug reports, reviewed and otherwise helped out.
