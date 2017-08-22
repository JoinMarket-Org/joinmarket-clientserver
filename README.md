# joinmarket-clientserver

Joinmarket refactored to separate client and backend operations

**The [latest release](https://github.com/AdamISZ/joinmarket-clientserver/releases)
is upgraded for segwit and to be used only for that; to use non-segwit use [0.2.2](https://github.com/AdamISZ/joinmarket-clientserver/tree/v0.2.2) or earlier.**

### Quickstart

**You need Bitcoin Core to use; get it running first.**

Once you've downloaded this repo, either as a zip file, and extracted it, or via `git clone`:

    ./install.sh
    (follow instructions on screen; provide sudo password when prompted)
    source jmvenv/bin/activate
    cd scripts

You should now be able to run the scripts like `python wallet-tool.py` etc., just as you did in the previous Joinmarket version.

Alternative to this "quickstart": follow the [install guide](docs/INSTALL.md).

### Upgrade for segwit

See the [segwit upgrade guide](docs/SEGWIT-UPGRADE.md) if you need to update your wallet.

### Usage

If you are new, follow and read the links in the [usage guide](docs/USAGE.md).

If you are running Joinmarket-Qt, you can instead use the [walkthrough](docs/JOINMARKET-QT-GUIDE.md) to start.

If you are not new to Joinmarket, the notes in the [scripts readme](scripts/README.md) help to understand what has and hasn't changed about the scripts.

### Joinmarket-Qt

Provides single join and multi-join/tumbler functionality (i.e. "Taker") only, in a GUI.

Binaries that are built and signed will be in the Releases page. To run the script
`joinmarket-qt.py` from the command line, pay attention to the note [here](https://github.com/AdamISZ/electrum-joinmarket-plugin#a-note-on-pyqt4-and-virtualenv).

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

Instructions for developers for testing [here](docs/TESTING.md).
