Joinmarket-clientserver 0.9.0:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.9.0>

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

**Note: this is very much "the fidelity bond release". There are almost no other changes in this release, because it's a big and important change.**

### Fidelity bond for improving sybil attack resistance

From the very beginning of JoinMarket it was possible to attack the system by creating many many maker bots all controlled by the same person. If an unlucky taker came along and created a coinjoin only with those duplicated maker bots then their coinjoins could be easily unmixed by the controller of those maker bots (but still could not be unmixed this way by outside observers). This is called a Sybil attack and until now it was relatively cheap to do against JoinMarket. Some yield generators were already doing this by running multiple bots, because they could earn higher coinjoin fees from their multiple makers.

Fidelity bonds are a new feature intended to resist Sybil attacks by making them a lot more expensive to carry out. It works by allowing JoinMarket makers to lock up bitcoins into time locked addresses. Until now takers have chosen their maker bots randomly. After this update takers will still choose randomly but with a higher probability of choosing makers who have advertised more valuable fidelity bonds. Any Sybil attacker therefore has to lock up many many bitcoins into time locked addresses.

For full details of the scheme see: [Design for improving JoinMarket's resistance to sybil attacks using fidelity bonds](https://gist.github.com/chris-belcher/18ea0e6acdb885a2bfbdee43dcd6b5af/)

This release implements all the features needed to add fidelity bonds to JoinMarket. Takers (via scripts such as `sendpayment.py` or `tumbler.py` or the Joinmarket-Qt app) will automatically give preference to makers who advertise fidelity bonds. Makers can optionally update their wallets to fidelity bond wallets. When a fidelity bond wallet is used with a yield generator script, it will automatically announce its fidelity bond publicly. Makers who don't create fidelity bonds by locking up bitcoins will still be chosen for coinjoins occasionally, but probably much less often than before.

For full user documentation see the file [fidelity-bonds.md](../fidelity-bonds.md) in the repository.

With realistic assumptions we have calculated that an adversary would need to lock up around 50000 bitcoins for 6 months in order to Sybil attack the JoinMarket system with 95% success rate. Now that fidelity bonds are being added to JoinMarket for real we can see how the system behaves in practice.

Fidelity bond coins cannot yet be held in cold storage, but this is easy to add later because the JoinMarket protocol is set up in a way that the change would be backward-compatible.

`199b571` Consider fidelity bonds when choosing makers

`97b8b3b` Show fidelity bonds on orderbook watch html page

`7a50c76` Announce yieldgenerator's fidelity bond

`6b6fc4a` Handle fidelity bonds in client-server protocol

`662f097` Write and update fidelity bond docs

`eb0a738` Add interest rate option to config file

`d4b3f70` Enable creation of fidelity bond wallets on cli

`b9eab6e` Increase max locktime of fidelity bond wallets

`a3b3cd4` Make fidelity bond wallets be native segwit

`a3b775b` Increase default fee by 4x

`9a372fd` Add getblockhash RPC method

`e6c0847` Add calculate fidelity bond value function + tests

`c70b12f` For timelock addrs use new pubkey foreach locktime

`3dc8d86` Fix importprivkey on fidelity bond wallets

`bbd3d1b` Print privacy warning when showing timelocked addr

`1ea62a7` Fix bug with timelocked addrs in receive payjoin

`4868343` Fix showutxos wallettool method for fidelity bonds

`b27659c` Support fidelity bond wallet in Qt

#### Minor Qt changes:

Recent testing indicated that the Qt view update can
be slow and profiling the code showed that this was due to
re-calculation of wallet view hitting the backend python-bitcointx
deserialization routines too hard. The obvious solution is to not
recalculate the wallet view in a polling loop, but only when a change
occurs in the wallet (though this can be optimized further, it's
already much more responsive than before):

`f857e6e` Fix Qt wallet view update to be reactive

`7be5e5d` By default auto-expand mixdepth 0

`0e2850a` Auto expand internal addresses that has non zero balances,
          and only auto expand the external addresses of mix depth 0.

#### Documentation updates

`e970a01` Create release notes section for fidelity bonds

`55d1bc9` Update readme.md and yieldgenerator.md for f-bonds

`cea4d95` add hosted obwatcher reference to readme

`17dd296` Add workflow status badge to top of README

### Testing and dev related background fixes

These are almost entirely not related to user functionality.
We have re-instantiated CI via Github Actions (Travis was used a long
time ago), which seems to be working well so far.

`81bade7` Update ygrunner to use fidelity bonds

`6cf4162` Add fidelity bond protocol tests

`940b083` Remove unused imports

`57f4720` Fix payjoin test of lowfeerate

`d9d594c` Allow bitcoin_path both with and without trailing slash

`e25dfda` first GA commit

`e3cc49b` github action test runner

`41a3ae4` make flake verbose and remove comments

Credits
=======

Thanks to everyone who directly contributed to this release -

- @wukong1971
- @kristapsk
- @bisqubutor
- @chris-belcher
- @AdamISZ
- @Evanito
- @undeath

And thanks also to those who submitted bug reports, reviewed and otherwise helped out.


