Joinmarket-clientserver 0.5.2:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.5.2>

This release contains a fix for IRC connection difficulties which should be
installed as soon as possible. It also adds the ability to make payments with PayJoin (aka P2EP),
a CoinJoin variant, including using bech32 wallets (for PayJoin but not Joinmarket coinjoin, at the moment),
colored log formatting and a number of other minor improvements.

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

### PayJoin feature (aka Pay-to-Endpoint/P2EP).

In short, this allows users of Joinmarket wallet to pay each other with a coinjoin.
This has a number of excellent properties in terms of improving privacy. To use, the
receiver runs the new script `receive-payjoin.py` and the sender runs `sendpayment.py`
with the option `-T`. See [here](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/PAYJOIN.md)
for more detailed instructions on how to use.

See [here](https://reyify.com/blog/payjoin) for conceptual explanation, which also links to other
writeups about the concept.

This can be used with a BIP84 bech32 wallet, but the latter is *not* compatible with Joinmarket coinjoins.

`28abddf` Implement payjoin (p2ep) direct payment joins

`72b2014 add normal payment info to PAYJOIN doc

### Fix IRC connection issues (startup and new server)

See #51 for background. While IRC server drops during operation were handled transparently, with
communication continuing on the remaining message channels, the bots would, prior to this fix, not start
up at all if *all* the configured message channels did not start up successfully. In recent days one of the
two default pre-configured public IRC servers (agora/anarplex.net) stopped functioning/allowing bots to join.
Hence many users on default setups would find their bots blocked from joining the joinmarket pit.
Hence this fix (long overdue!) to continue/complete the startup process after a timeout of 60 seconds, if one
of the configured message channels (there can be as many as you like) fails to complete its startup. In short,
as long as one server is available, your bot will start up after at most 60 seconds.
Shorter timeouts are probably undesirable, particularly Taker side, since you don't want to miss half the
liquidity in the pit just because you were too impatient to wait for the server to fully connect.
Additionally, a third default server (darkscience) has been added to the config, which supports connecting
to a hidden service over Tor.

(Joinmarket's architecture in principle supports an arbitrary number of message channels, and they don't have to
be IRC servers (as long as derived classes implement 4 key methods).)

**Users should refresh/recreate a joinmarket.cfg** (by setting their current one's name to joinmarket.cfg.bak for
example) and then copy over the new default MESSAGING section settings, and then edit them as they prefer.

`c6dabae` Add startup redundancy to IRC servers.

`7ee18af` Add darkscience IRC to default configuration.

### Colored terminal logging

We now use a python package [chromalog](https://chromalog.readthedocs.io/en/latest/) to support colored logging
of Joinmarket bots on the terminal; this is due to the fact that logs are pretty noisy but also sometimes necessary
to look at (and this is particularly true of the new PayJoin feature, among some others). For those who find
the color scheme unreadable or undesirable on their chosen terminal setup, set `color = false` in the LOGGING
section of joinmarket.cfg and it will be switched off. Note of course that log *files* are unaffected by this.

`c139067` Include chromalog package for colorized logs

`bc6228f` Fix "AttributeError: 'NoneType' object has no attribute 'replace'" when jmprint() called with None as msg

`0ce9392` Allow user to switch off colored logging New config setting [LOGGING]color=true/false


### Minor changes

Will probably not be of interest to non-developers (these are mostly changes to logging/documentation).


`faee0eb` Reset http connection on EPROTOTYPE errors.

`1909656` Add hostid to "On disconnect fired, nicks_seen is now" log message

`dbac8ed` remove electrum references and add multiwallet ref to USAGE.md

`2dda70a` message_channel.py should not have execute permissions set

`1e2154d` python 3.4 byte string formatting fix for authorization header

`8ca65a7` Log initial offerlist on startup for a Maker

`8140543` demote nick drop to debug from warn

`fc66381` show hostname in logs for signedOn and joined

`a88cce4` We aren't Python2-only anymore

`965d190` update stale help msg on utxo type in sendtomany.py

Credits
=======

Thanks to everyone who directly contributed to this release -

- @AdamISZ
- @jameshilliard
- @AlexCato
- @kristapsk
- @gallizoltan

And thanks also to those who submitted bug reports, tested and otherwise helped out.


