This will serve as a high level overview of future changes either in progress or planned.
The Issues list is for specific bugs or feature requests.

### Python

* PEP8 compliance.
* Details which may or may not be included in PEP8 might be, consistent variable naming conventions, and use of single/double quotes.
* ~~Porting to Python 3~~. This is done in that we are now Py2 and Py3 compatible as of 0.5.0; but we may deprecate Py2 soon.

~~A note on the above - took a look at it last December, but had problems in particular with some twisted elements, specifically `txsocksx`~~ Done as of 0.4.2, now switched to txtorcon.

* Twisted related: there are cases where much better use of deferreds should be possible.

### Testing

* Find a correct model for tests using twisted; current arch. used in `test_client_protocol.py`
(and daemon) is extremely ugly, involving hardcoded timeouts. It uses `twisted.trial` which I believe(?) is the correct module
to use, but I don't seem to have figured out the right/best way to use it.
* Need end to end testing of user functions, especially on Qt. Currently this is done manually which is not practical.
* Current `test/ygrunner.py` is a nice way to do "by-hand" testing of various clients against either
honest or malicious counterparties (makers). Can and should be extended to be automatic, with taker
running in same process.
* Issues of running bots in parallel in tests: sourcing the configuration, and sharing of global files
like `commitmentlist`.

### Architecture

* Probably move all user data to ~ ; see [comment](https://github.com/JoinMarket-Org/joinmarket-clientserver/issues/62#issuecomment-318890399).
* Make use of the schedule design to fold together sendpayment and tumbler (they share a lot of cli options anyway).
* Investigate what refactoring of the daemon protocol is necessary so it is possible to run protocol instances concurrently.
* Moving elements shared into joinmarketbase - in particular, an object representing offers like `JMOffer`, which
could have serialization routines for passing between client and daemon.
* Do more work on TLS connection so that it becomes possible to run the daemon locally without any privacy
concern (there is already no bitcoin security concern even without it).

### Blockchain

* We should look into lite-client modes, in particular client-side filtering as used by Neutrino and others,
and described [here](https://github.com/Roasbeef/bips/blob/master/gcs_light_client.mediawiki}.

* Re-work the existing electrum code so it works reliably and with some decent performance (easier short term goal).
This was previously marked 'done' but is now very much "un-done" since the code has not been updated and doesn't work; it's debatable what should be done, if anything, about it. It's certainly useful to have Electrum for testing/testnet.

### Joinmarket protocol

* The [issue693](https://github.com/JoinMarket-Org/joinmarket/issues/693) problem is by far the most important one to spend time on.

Possible future update ("hard fork") for Joinmarket protocol may include:
* bech32 addresses for joins; possibly mixed address types, needs discussion.
* change format of data transfer (in particular, avoid double encoding which wastes space)
* with respect to above issue693, see fidelity bonds discussion in #371 ; if implemented this may (will?) require some changes to protocol messages.

 An additional possibility is discussesd in #415 namely, possible decentralized architecture for Joinmarket inter-participant communication.
### Qt GUI

* Binary build process automated and, more importantly, working for Linux, Windows and Mac.

There is no current process for building binaries on Mac or Windows (theoretically the latter is possible but a mess, so I'm not doing it).

* ~~Qt5 support, as Qt4 is being deprecated (see [issue204](https://github.com/JoinMarket-Org/joinmarket-clientserver/issues/204)).~~ Done as of 0.5.0.

### Alternative implementations

* Build an alternative client implementation in Java or Javascript for example, using some existing Bitcoin library in that language, perhaps using some lite client solution e.g. SPV, and then connecting to the daemon (executable or Python script).

### Bitcoin

We use coincurve as a binding to libsecp256k1.
The current jmbitcoin package morphed over many iterations from the original pybitcointools base code.
We need to rework it considerably as it is very messy architecturally, particularly in regard to data types.
A full rewrite is likely the best option, including in particular the removal of data type flexibility; use binary
only within the package (which will also require rewrite and simplification of some parts of the wallet code).

A rewrite of the transaction signing portion of the jmbitcoin code will need to account for the future
probable need to support taproot and Schnorr (without yet implementing it).

### Extra features.

PayJoin is already implemented, though not in GUI, that could be added.
Maker functionality is not in GUI, that could quite plausibly added and is quite widely requested.
SNICKER exists currently as a proposed code update but is not quite ready, see #403.