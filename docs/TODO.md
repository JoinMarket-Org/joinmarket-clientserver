This will serve as a high level overview of future changes either in progress or planned.
The Issues list is for specific bugs or feature requests.

### Python

* PEP8 compliance.
* Details which may or may not be included in PEP8 might be, consistent variable naming conventions, and use of single/double quotes.
* Porting to Python 3.
* Twisted related: there are cases where much better use of deferreds should be possible.

### Testing

* Find a correct model for tests using twisted; current arch. used in `test_client_protocol.py`
(and daemon) is extremely ugly, involving hardcoded timeouts. It uses `twisted.trial` which I believe(?) is the correct module
to use, but I don't seem to have figured out the right/best way to use it.
* Rewrites for several tests needed; in particular, blockchaininterface, segwit, transaction creation generally.
* Current `test/ygrunner.py` is a nice way to do "by-hand" testing of various clients against either
honest or malicious counterparties (makers). Can and should be extended to be automatic, with taker
running in same process.
* Issues of running bots in parallel in tests: sourcing the configuration, and sharing of global files
like `commitmentlist`.

### Architecture

* Probably move all user data to ~ ; see [comment](https://github.com/JoinMarket-Org/joinmarket-clientserver/issues/62#issuecomment-318890399).
* Investigate what refactoring of the daemon protocol is necessary so it is possible to run protocol instances concurrently.
* Moving elements shared into joinmarketbase - in particular, an object representing offers like `JMOffer`, which
could have serialization routines for passing between client and daemon.
* Do more work on TLS connection so that it becomes possible to run the daemon locally without any privacy
concern (there is already no bitcoin security concern even without it).

### Blockchain

* Investigate adding SPV mode inherited from work on Bitcoin Core
* Re-work the existing electrum code so it works reliably and with some decent performance (easier short term goal).

### Joinmarket protocol

* The [issue693](https://github.com/JoinMarket-Org/joinmarket/issues/693) problem is by far the most important one to spend time on.

### Qt GUI

* Binary build process automated and, more importantly, working for Linux, Windows and Mac. We have nothing for Mac and the Windows build process I'm using is horribly "custom".

### Alternative implementations

* Build an alternative client implementation in Java or Javascript for example, using some existing Bitcoin library in that language, perhaps using some lite client solution e.g. SPV, and then connecting to the daemon (executable or Python script).
