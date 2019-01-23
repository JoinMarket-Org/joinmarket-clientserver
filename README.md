# joinmarket-clientserver

Joinmarket refactored to separate client and backend operations

Joinmarket is coinjoin software, and includes a wallet, which requires Bitcoin Core as backend (version 0.16.3, 0.17.0 or later).

### Wallet features

* Segwit addresses in the backward compatible form (start with `3`)
* Multiple "mixdepths" or pockets (by default 5) for better coin isolation
* Ability to spend directly, or with coinjoin; export private keys; BIP49 compatible seed (Trezor, Samourai etc.) and mnemonic extension option
* Fine-grained control over bitcoin transaction fees
* Can run sequence of coinjoins in automated form, either auto-generated (see `tumbler.py`) or self-generated sequence.
* Can specify exact amount of coinjoin (figures from 0.01 to 30.0 btc and higher are practical), can choose time and number of counterparties
* Can run passively to receive small payouts for taking part in coinjoins (see "Maker" and "yield-generator" in docs)
* GUI to support Taker role, including tumbler/automated coinjoin sequence.
* PayJoin - more economical and private payments between Joinmarket wallets.

### Quickstart

Once you've downloaded this repo, either as a zip file, and extracted it, or via `git clone`:

    ./install.sh
    (follow instructions on screen; provide sudo password when prompted)
    source jmvenv/bin/activate
    cd scripts

(You can add `-p python2` if you want to use Python2. You can also add `--develop` as an extra flag to `install.sh` to make the Joinmarket code editable in-place.)

For the Qt GUI, pass the `--with-qt` flag to `install.sh` as well :

    ./install.sh --with-qt

Do note, Python 2 is incompatible with the Qt GUI.

You should now be able to run the scripts like `python wallet-tool.py` etc., just as you did in the previous Joinmarket version.

Alternative to this "quickstart" (including for Windows and MacOS): follow the [install guide](docs/INSTALL.md).


### Usage

If you are new, follow and read the links in the [usage guide](docs/USAGE.md).

If you are running Joinmarket-Qt, you can instead use the [walkthrough](docs/JOINMARKET-QT-GUIDE.md) to start.

If you used the old version of Joinmarket, the notes in the [scripts readme](scripts/README.md) help to understand what has and hasn't changed about the scripts.

### PayJoin

If you want to use the PayJoin feature to pay/receive money to/from another Joinmarket wallet user, read [this guide](docs/PAYJOIN.md).

### Joinmarket-Qt

Provides single join and multi-join/tumbler functionality (i.e. "Taker") only, in a GUI.
NOTE: This is currently **only available for Python3**, not Python2 (due to bugs in the PySide2 Python2 implementation).
It's possible but unlikely that the Python2 version will be fixed, but in any case Python2 will be deprecated at some point.

If binaries are built, they will be gpg signed and announced on the Releases page.

If you haven't used the `--with-qt` flag during installation with `install.sh`, then to run the script `joinmarket-qt.py` from the command line you will need to install two more packages.  Use these 2 commands while the `jmvenv` virtual environment is activated:

```
pip install PySide2
pip install https://github.com/sunu/qt5reactor/archive/58410aaead2185e9917ae9cac9c50fe7b70e4a60.zip
```
After this, the command `python joinmarket-qt.py` from within the `scripts` subdirectory should work.
There is a [walkthrough](docs/JOINMARKET-QT-GUIDE.md) for what to do next.

### Notes on architectural changes (can be ignored)

Motivation: By separating the code which manages conversation with other
Joinmarket participants from the code which manages this participant's Bitcoin
wallet actions, we get a considerable gain at a minor cost of an additional layer:
code dependencies for each part are much reduced, security requirements of the 
server/daemon layer are massively reduced (which can have several advantages such as
it being more acceptable to distribute this layer as a binary), and client code
can be written, implementing application-level logic (do join with coins X under condition X)
using other Bitcoin libraries, or wallets, without knowing anything about
Joinmarket's inter-participant protocol. An example is my work on the Joinmarket
electrum [plugin](https://github.com/AdamISZ/electrum-joinmarket-plugin).

It also
means that updates to the Bitcoin element of Joinmarket, such as P2SH and segwit, should
have extremely minimal to no impact on the backend code, since the latter just implements
communication of a set of formatted messages, and allows the client to decide on
their validity beyond simply syntax.

Joinmarket's own [messaging protocol](https://github.com/JoinMarket-Org/JoinMarket-Docs/blob/master/Joinmarket-messaging-protocol.md) is thus enforced *only* in the server/daemon.

The client and server currently communicate using twisted.protocol.amp, see
[AMP](https://amp-protocol.net/),
and the specification of the communication between the client and server is isolated to
[this](https://github.com/AdamISZ/joinmarket-clientserver/blob/master/jmbase/jmbase/commands.py) module.
Currently the messaging layer of Joinmarket is IRC-only (but easily extensible, see [here](https://github.com/JoinMarket-Org/joinmarket/issues/650).
The IRC layer is also implemented here using Twisted, reducing the complexity required with threading.

The "server" is just a daemon service that can be run as a separate process (see `scripts/joinmarketd.py`), or for convenience in the same process (the default for command line scripts).

### TESTING

Instructions for developers for testing [here](docs/TESTING.md). If you want to help improve the project, please have a read of [this todo list](docs/TODO.md).

### Support JoinMarket and bitcoin privacy

Donate to help make JoinMarket even better: `bc1q5x02zqj5nshw0yhx2s4tj75z6vkvuvww26jak5` or `1AZgQZWYRteh6UyF87hwuvyWj73NvWKpL`. Signed bitcoin addresses can be found [here](docs/signed-donation-address.txt).

JoinMarket is an open source project which does not have a funding model, fortunately the project itself has very low running costs as it is almost-fully decentralized and available to everyone for free. Developers contribute only as volunteers and donations are divided amongst them. Many developers have also been important in advocating for privacy and educating the wider bitcoin user base. Be part of the effort to improve bitcoin privacy and fungibility. Every donated coin helps us spend more time on JoinMarket instead of doing other stuff.
