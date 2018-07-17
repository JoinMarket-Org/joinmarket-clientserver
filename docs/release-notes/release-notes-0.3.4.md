Joinmarket-clientserver 0.3.4:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.3.4>

Minor release with improved completion rate of joins, 
and a few important bugfixes (removing possible crash vector for Makers).
The application now also supports (old Joinmarket-style) non-segwit wallet usage (although this is not recommended),
, supports the Core multiwallet feature and also rpc cookie auth.

Please also note that the default fee for the yield-generators (Makers) in `script/yield-generator-basic.py` and
`yg-privacyenhanced.py` are reduced by a factor of 10. Please review the fee configuration at the top of the file
you're using and change the default values as you wish.

Due to the DOS implications of the bugfix, upgrade immediately if you are a Maker; you may otherwise lose your connection at any time.

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading 
=========

To upgrade: run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.


Notable changes
===============

Most changes in this release are backend (many connected with testing or installation), so
are not listed here. Their not being described here does not imply that they are not important,
only that they won't be of interest to users.

### Restart-with-subset of honest makers

`b741b24764ebb1b1e89a9f516e64a98eeda86557`

The code already has a facility called "complete-with-subset" which enables a Taker to continue and
complete a CoinJoin when one or more of the counterparty Makers refuses to send a valid `!ioauth` message
in the first stage of negotiation. This is the relatively easier kind of DOS vector to address - since
the Taker has not yet, at this stage, constructed the full CoinJoin transaction, and can therefore
construct it using the utxos of the honest makers who did send valid `!ioauth`s. It is limited to only
continue if the number of honest makers is at least as high as the setting `minimum_makers` in the `POLICY`
section of `joinmarket.cfg`.

However, a DOS-ing Maker can still refuse to send the signature (`!sig`) at the end of the negotiation. In
this case the Taker must start from scratch as the currently prepared transaction is no longer valid. To aid
this scenario, this commit allows the Taker to restart with *specifically that set of makers who were honest
in the first attempt*. This does still cost an additional commitment (it is possible but quite a bit more
complex to alter the code so that that isn't the case), but it will mean that hopefully very few transactions
indeed cannot complete. Note that when using `sendpayment` this may require waiting and re-confirming the new
set of fees (they will usually be the same as the first attempt, but could be different in theory).

With both complete-with-subset and restart-with-subset in place, the overall completion rate should be high
unless the number of malicious makers completely swamps the number of honest ones.

This is applied to all Taker modes (sendpayment, tumbler and also in Qt GUI).

### Fix bug in IRC collision handling

`ec60bcd14f871611459dd430550085035d750167`

Previously, if a bot reconnected and encountered a nick
collision, it would append '_' and connect, but counterparties
would ignore appended characters after NICK_MAX_ENCODED+2, and
so would send to the other nick. This happens in network
connection failure scenarios.
Strategy here is to simply insist on regaining the nick on that
message channel where it has been lost, retrying every 10s.
There is also a loud warning message printed.
Bots with fairly stable connection (including Tor) probably never encountered
this, but if (for example) your ISP force-disconnects, your Maker could be left
essentially disconnected from the trading pit, without your knowing. This was quite
a bad bug; now it will almost certainly be successful in reconnecting to the pit after some seconds
or minutes, and if not it will at least print a very large warning, repeatedly.
More sophisticated solutions are difficult to obtain.

### Support for Bitcoin Core multiwallet feature

`91ffa6cb6c165fa26ae5e1d2881cb1c9792dd094`

Adds support for use of multiple Bitcoin Core wallets, a feature introduced in Bitcoin Core 0.15.0,
see [release notes](https://bitcoincore.org/en/2017/09/01/release-0.15.0/#multiwallet) for details.

### RPC credentials from cookie auth file

`ea67a8bf85edd7fb6b5c5113d6485eaa42bf0129`

Adds support for use of cookies as alternative to rpcuser/pass for authentication of RPC
connections to Bitcoin Core.

### Support for non-segwit takers/makers.

`816078b437d9a0b6d31be4d2b827582602717abc`,
`4e6bee33336a0fb915a24e5626af053f4a137b66`,
`619b4a123f441531dbd54d353ab64e3f771bdba1`,
`966bce19a42926f74c19fe1db98ab8edc2648e03`

Although as noted in the README now, this is highly dis-recommended (almost nobody is using
non-segwit joinmarket anymore), there is support for backwards compatibility now, of the
old-style Joinmarket wallets now (they are not BIP39 and use p2pkh addresses ("1")), and
running a Taker or Maker is possible. You shoud set `segwit=false` in `joinmarket.cfg` to
use this feature.

### SIGHASH_SINGLE bugfix for segwit

`589ed31fde771c606488412324d0affd76e8b670`

SIGHASH_SINGLE handling in the signing code for segwit was wrongly coded, this fixes it.
There is no current usage of this feature in Joinmarket.

### Reduce default Maker fees

`f7029f64924dc9523258b336a4499f5551f8d6cf`

The **default** fees are reduced in both yield generator scripts to about 10% of what they were before,
to match more what is seen in the market; see the comment at the start of these release notes for user action.

Credits
=======

Thanks to everyone who directly contributed to this release -

- @AdamISZ
- @undeath
- @fivepiece
- @chris-belcher
- @kristapsk
- @adlai
- @mecampbellsoup
- @jameshilliard
- @AlexCato

And thanks also to those who submitted bug reports, tested and otherwise helped out.
