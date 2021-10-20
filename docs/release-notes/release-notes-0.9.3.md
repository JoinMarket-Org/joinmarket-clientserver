Joinmarket-clientserver 0.9.3:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.9.3>

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

**THIS RELEASE IS AN URGENT UPDATE FOR MAKERS** (see "Bugfix: don't allow negotiation of coinjoin with size less than `minsize`" for why).

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

### Bugfix: don't allow negotiation of coinjoin with size less than `minsize`

Placing this subsection first for those who don't have time to read the explanation (but, you should!):

#### Scope of the bug and remedial action:

All makers running *all* previous versions of Joinmarket-clientserver are affected, if they:

* use `reloffer` offer type, not `absoffer`.
* use `txfee` yieldgenerator setting of greater than zero.

It seems that overwhelmingly, users have either left that `txfee` (or `txfee_contribution`) field at the default of 100 sats (sometimes randomized), or set it to 0. **If you have a maker bot running with the above two conditions, stop it immediately**.

Possible losses are restricted to whatever is the size of that `txfee` field, per coinjoin. An attacker could run this with trivially modified code, but since it costs them money, they are not incented to; see `Exploitation of the bug` below for more details.

(Upon restarting your bot with v0.9.3, `txfee_contribution` now defaults to zero (remember to update your `joinmarket.cfg`). Though technically you can change it, there is no reason to. We will deprecate this variable at some point.)

#### Explanation

First, some background: the yield-generator config variable `txfee` (now renamed `txfee_contribution`, see commit below) was created at the start of the project back in 2015 as something the maker chips in to the network transaction fee paid by the taker. However, since the taker accounts for this when deciding which offers to choose (i.e. the taker considers the value `coinjoinfee - txfee_contribution` rather than only `coinjoinfee` in economic calculations, in simple terms), it means that it's effectively just a change to the maker's overall fee, so realistically, an un-needed complexity. This was understood early on, but it was never seen as worth the hassle to remove it.

The default value for this variable is 100 sats and has been so for many years. Indeed almost every Maker currently in the pit (as of 20 Oct 2021) has a value of 120sats or less (it is randomized up to 30% in newer bots), with most of them at zero.

Now the bug: in 2017, in the process of my refactoring to joinmarket-clientserver (in [this](https://github.com/JoinMarket-Org/joinmarket-clientserver/commit/bba43dbf2abf24a97d3694e51c1e1f5d4ca26624) commit), the check which says "is the amount from the Maker bigger than our minsize?" is actually ignored (there should be a `return`, i.e. stop processing if that check fails, but it is absent), and coinjoin processing can continue. For `absfee` offers this doesn't matter, but for `relfee` offers it can be the case that the `txfee_contribution` as mentioned above, is higher than the `coinjoinfee`, meaning the Maker actually gets a *negative* return instead of positive, as we intended to ensure.

A user on Telegram reported seeing a -54 sat return on one transaction and a -84 sat transaction on another, prompting me (@AdamISZ) to examine their logs and realise that the above bug existed.

#### Exploitation of the bug:

The motivation is, in practice today, not present, since the attacker loses at least some sats to fees (i.e. their profit would be negative), in making such transactions, but note this is only true because Makers are not setting their `txfee` to above the ~ 140 sats that it costs to get 1 input and 2 outputs (worst case) mined at 1 sat/vbyte (if a Maker set say `txfee=1000`, then an attacker could make money that more than offset a low 1sat/vbyte network fee). This is doubtless the reason we have not seen a significant number of such negative yielding coinjoins so far.

(Note that a miner who wanted to do this could do so at a "profit" of about 100 sats/1 input, 2 output, but since it fills block space and makes ~ 0.7 sat/vbyte, it would be a reduction in income, i.e. a net negative.)

`16fa85b` Prevent amounts less than minsize being processed

### New JSON-RPC server

This provides a script (`scripts/jmwalletd.py`) to be run as a daemon, currently serving over TLS (we will add onion service later), and an OpenAPI spec for clients to use the API. Details on what the API provides are in the documentation [here](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/JSON-RPC-API-using-jmwalletd.md).

The motivation here is to allow people to write different UIs in e.g. Javascript frameworks. The daemon serves all the main functions of the wallet including maker, taker coinjoins, showing wallet contents and utxos, etc. Some extra functions are not yet supported. See above document for more details.

`80e17df` Add jmwalletd script as RPC server.

`1688d2d` Adds listutxos and heartbeat route, several fixes

`7e73e4c` Add websocket for subscription, OpenAPI spec

`5146ae3` Bump autobahn from 20.7.1 to 20.12.3 in /jmclient

### Miner fee randomization

This commit allows you to change what was previously hardcoded: a 20% randomization in the network mining fee for your transaction.

It can now be altered in the config variable `[POLICY]`, `tx_fees_factor`:

`df5f241` Add configurable miner fee randomization factor

### Option to skip OS package manager's dependency check

See [PR #1028](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/1028) for details.

`ba63b01` Option to skip OS package manager's dependency check

### Make onion service hosting location flexible

This currently only applies to payjoin, but this change allows a user
to run an onion service on a host different from their local machine:

`13f9bb7` change default to IP

`b5a4ba3` Allow user to configure host,port of onion.

### Documentation, comment, naming fixes

`3f5abee` Fix help description of yg's command line txfee options

`6ff6c80` `9abae09` `c2729c0` fix typos

`f929fe2` Update config-irc-update.md

`d7d2de3` use btc.amount_to_str for potentially earned

This last one is more important: related to the main bug fixed in this release,
we rename `txfee` to `txfee_contribution`; as noted it's generally best to
just set this value to zero anyway, but this renaming of the config variable
makes it clearer what it actually is (with all the caveats as per above):

`a542680` Rename yield generator's txfee settings to txfee_contribution

Credits
=======

Thanks to everyone who directly contributed to this release -

- @abhishek0405
- @shobhitaa
- @bisqubutor
- @kristapsk
- @AdamISZ
- @xanoni

And thanks also to those who submitted bug reports, reviewed and otherwise helped out.
