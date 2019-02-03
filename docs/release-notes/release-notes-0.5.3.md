Joinmarket-clientserver 0.5.3:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.5.3>

This is a bugfix release that improves the reliability of the messaging code, fixes some suboptimal behaviour in the new PayJoin function.
Joinmarket coinjoin users should upgrade because of the former, and any users of PayJoin should upgrade because of the latter.

There are also a couple of other minor bugfixes and improvements.

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

### PayJoin improvements and fixes.

As a result of some basic user testing, a few issues with PayJoin cropped up. None of them were security issues;
some were user-interface annoyance, and others were suboptimal behaviour. The most significant point that indicates
update is required is that in some cases a coinjoin would not be done when it could be (i.e. fallback to non-coinjoin
unnecessarily).

(1) a bug in coin selection such that UIH2 (see documentation) was not being avoided when it could be.

(2) incorrect logic on choosing to fall back to a non-coinjoin (although the existing code still was functionally the same, it printed incorrect information messages).

(3) too easy for users to accidentally choose ordinary coinjoin instead of PayJoin (see [this](https://github.com/JoinMarket-Org/joinmarket-clientserver/issues/305) issue).

(4) PayJoin didn't work when the daemon `joinmarketd.py` was run separately, this is fixed.

(5) Minor fix to ensure that the script quits gracefully sender-side when it times out after 10-20 mins, rather than raising an Exception.

(6) Check sequence and locktime in returned partially signed proposal are unaltered.

`ac0ecfb` Fix UIH2 avoidance algo when sender input utxo > payment

`01a48be` Clarifies INFO messages to user about the fallback non-coinjoin

`371772f` No coins fallback if mixdepth empty

`fd5e6d8` Fixes #305

`0c967bc` Support payjoin when daemon run separately (joinmarketd)

`1c3a153` graceful sender-side timeout of PayJoin if fails

`f539b02` Check sequence and locktime are conforming to payjoin v0 in transaction from receiver to sender.

### Fix bug in message channel switching, and fix rare crash condition; remove Agora from default.

A long standing but rare bug was recorded first in [this](https://github.com/JoinMarket-Org/joinmarket-clientserver/issues/105) issue.
A crash condition occurred where an attempt to switch over to another channel failed. This condition was aggravated by recent problems with
flaky connections to one of the IRC channels (Agora). Careful analysis showed that the source of the problem was faulty logic in the privmsg
function (`MessageChannelCollection.prepare_privmsg` to be more specific). This logic was fixed and now bots will make much better use of
the ability to switch communications from one message channel to another in cases where one drops (which is far from uncommon), and also will
under no circumstances simply crash when they cannot find any route to the counterparty.

Further, since Agora seems to drop connections actively during transaction negotiation (due to flooding limits), it has been removed for now
from the default configuration. Users are advised to remove it from their `joinmarket.cfg` by commenting out that section, although feel free
to experiment with using it. Everything should still work (live testing shows that with the new code, your bot *will* dynamically switch its
connections from Agora to another mchan in this case), but there are no guarantees.

`3a2c462` Fix bug in channel selection in prepare_privmsg

`9deb3e5` Do not raise exception when privmsg fails

`3bfc39a` Remove agora from default IRC configuration

### Add documentation for installation on Windows

Joinmarket and Joinmarket-Qt are runnable on Windows 10 - by far the simplest way to do it is to
use the Windows Linux subsystem. This can "talk to" a Bitcoin Core installation on Windows itself,
with the aid of some simple software. The documentation added to INSTALL.md explains how to do this.

`cbc39bc` `8e6a099` `275d24b` `769990d` `993f3fd` `3cefc47` Add instruction for running JoinMarket-Qt on Windows

`de3818d` add note to Windows install, update JMQT guide

### Fix bug in sendpayment script

After the logging change in the previous release, a bug was introduced which would cause the sendpayment
script to crash in case it had trouble with blocking counterparties during the first attempt. This is fixed here.

`9e7b619` bugfix jmprint call in taker_finished

### Transaction fee floor

This is a follow up to #271 - here we actually prevent the user accidentally setting a fee lower than the
minimum relay fee.

`4462ab6` Add tx fee floor if manually chosen

### Fix potential crash from rpc gettransaction call

Code previously only gracefully handled an RPC error, this prevents crashing under any condition.

`3045370` Bugfix crash on unexpected error from gettransaction call.

### Minor changes

Backend testing changes and slight changes to docs/logging.

`2db4e23` Fix F632 use ==/!= to compare str, bytes, and int literals flake8 errors

`ba4ae04` conditionally run docker tests on travis

`37b7a07` Report which nick lead to sig verification failure

`29fc29b` Better formatting for a "withdraw" rows in wallet history output

`4c3b2ff` Sender should use his own wallet, not the receiver's one.


Credits
=======

Thanks to everyone who directly contributed to this release -

- @fivepiece
- @d3spwn
- @AdamISZ
- @jameshilliard
- @AlexCato
- @kristapsk

And thanks also to those who submitted bug reports, tested and otherwise helped out.


