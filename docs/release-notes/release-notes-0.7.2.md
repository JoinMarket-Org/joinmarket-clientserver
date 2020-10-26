Joinmarket-clientserver 0.7.2:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.7.2>

This release requires Python 3.6+ - see "Upgrading" section in the 0.7.0 release notes for more information if needed.

This is mostly bugfix release, fixing some issues with certain cases of the new Payjoin functionality; anyone wishing to use that functionality should upgrade, to make it work much more reliably (remember: Payjoin falls back to normal payment if anything goes wrong).
It also adds a bit more functionality, in particular QR codes generate-able by the Payjoin receiver.

It also bugfixes the 'not-self' broadcast feature introduced in the last release.

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

### BIP 78 (Payjoin) improvements and fixes

See the [previous](release-notes-0.7.1.md) for details on how to use Payjoin as a receiver, or for more details on sending and receiving, see [this](../PAYJOIN.md) documentation.
In this release, a couple extra elements of functionality are added: the receiver can now create a QR code for the sender, in the Payjoin receiver dialog. Also, the Tor configuration settings: `tor_control_port` and `tor_control_host` are added in the `[PAYJOIN]` section of `joinmarket.cfg` for people who want to use non-default configurations of Tor.

More importantly perhaps, there are a couple of bugfixes where the implementation deviated slightly from the BIP78 standard, which led to payjoins failing in certain cases - for this reason, updating to this version should be considered required rather than optional.

`7414959` QR code support for BIP78 payjoin receiver in Qt GUI

`6a8149f` Removes utxo field from non-receiver inputs

`f931421` Payjoin receiver times out when sender falls back

`fde39a7` payjoin: make tor control host configurable

`e6bc0c1` Bugfix: don't randomize payjoin outputs

##### Various improvements and bugfixes

The most important here: in 0.7.1 we (re-)introduced 'not-self' (and 'random') broadcast via `tx_broadcast` config entry, however with `not-self` there was still a fallback to self-broadcast, in case the broadcast via maker failed; this makes little sense, so the fallback is removed, in the fix below. Those using this option should be strongly aware of the current limitation: if few or none of the makers you coinjoin with have updated to 0.7.1+ , and/or they simply fail to broadcast the transaction, your script will currently just hang, waiting for broadcast. You can do it manually via some other channel, but note how this is not really compatible with multi-transaction automated schedules like tumbler.
The other fixes here are minor.

`004945f` `d26cea8` Never self-broadcast with not-self, add warning message to GUI

`c7ee7ec` bugfix: remove P2EP factory from joinmarketd

`43368e1` Output values on "Not enough funds" exception

`7ea1c9a` Silence unnecessary warning


##### Documentation


`68fc551` Add orderbook.md doc file

`557f7a9` Minor fix in sourcing commitments doc

`9dcde07` Add link to IRC logs


Credits
=======

Thanks to everyone who directly contributed to this release -

- @kristapsk
- @PulpCattel
- @nixbitcoin
- @AdamISZ


And thanks also to those who submitted bug reports, tested, reviewed and otherwise helped out.
