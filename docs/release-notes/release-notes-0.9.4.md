Joinmarket-clientserver 0.9.4:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.9.4>

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>


Upgrading
=========

To upgrade:

*Reminder: always back up and recreate your joinmarket.cfg file when doing the upgrade; this is to make sure you have the new default settings. This particularly matters in releases like 0.9.4, where there are new network/IRC settings.*

(If you are upgrading from a version pre-0.7.0 please read the "Upgrading" section in [the 0.7.0 release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.7.0.md).)

(If you are upgrading from a version pre-0.9.0 please read the [release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.9.0.md) to find out how about [fidelity bonds](../fidelity-bonds.md) are relevant to your use-case).

First run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.

Note that `./install.sh -?` will show the options for installation.

Notable changes
===============

### User-chosen address labelling

See [PR](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/1015). This feature allows users to set a label for an address with the method `setlabel`, like this:

```
python wallet-tool.py mywallet.jmdat setlabel bc1fakeaddress "mynewcustomlabel"
```

where `bc1fakeaddress` should be any address "known" in the wallet (so anything up to 'used + gap limit', if that makes sense to you - if not, don't worry). This includes timelocked addresses. A few points of note:

* This can only be done on the command line, but you can view the labels in Qt. We will probably add the setlabel function to Qt at some point soon.
* These labels are separate to, and additional to, the existing "used/new" field which shows "coinjoin-out", "change-out", "deposit" etc. Those are set algorithmically according to the type of transaction (and should not be 100% relied on, if you do something unusual).
* You can remove an existing label by calling `setlabel` with "".


`21c0e3e` Implement address labeling


### Fix message signature encoding crash vector

See the [PR](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/1070) for details. This fixes a potential crash vector if the counterparty sends a non-hex-encoded string in place of a pubkey, so for this reason, makers in particular should update immediately.

`0507f6a` Validate message signature encoding


### New IRC server

See changes in the PR [here](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/1065/files).
You are strongly recommended to recreate your `joinmarket.cfg`, as always, but especially in cases like this: the list of IRC servers has been "cleaned up" somewhat to be more informative, and a fourth server ("Ilita") has been added as an alternative (but off, by default). A reminder that in theory you can run with any number of IRC servers connected. Also see the notes about Tor being the recommended option (which almost all users do use, today).

`af4f071` Add Ilita IRC server (.onion)


### Minor changes

`e7ff25d` Fix example date and example output in fidelity bond doc

`14bed14` Fix @fort-nix's public orderbook links

`840189c` Fix SNICKER daemon startup

`20e2e85` jmbase: upgrade twisted to latest (21.7.0)

`1e25d1f` Allow to not specify rpc_port in config, use network's default then


Credits
=======

Thanks to everyone who directly contributed to this release -

- @nixbitcoin
- @kristapsk
- @AdamISZ
- @xanoni

And thanks also to those who submitted bug reports, reviewed and otherwise helped out.
