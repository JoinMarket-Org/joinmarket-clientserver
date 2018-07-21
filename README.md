# joinmarket-clientserver

Joinmarket refactored to separate client and backend operations

**The [latest release](https://github.com/Joinmarket-Org/joinmarket-clientserver/releases) uses segwit wallets by default,
you are strongly recommended not to change this, but you can use a non-segwit wallet by setting `segwit = false` in joinmarket.cfg.**

### Quickstart

**For good quality privacy, performance and reliability, Bitcoin Core is required for Makers (yield generators), and recommended for takers (doing coinjoins). Use version 0.15+ ideally; 0.13.1+ required.**

For doing coinjoins (Taker side), you can also run without Bitcoin Core, connecting to Electrum servers.

Once you've downloaded this repo, either as a zip file, and extracted it, or via `git clone`:

    ./install.sh
    (follow instructions on screen; provide sudo password when prompted)
    source jmvenv/bin/activate
    cd scripts

You should now be able to run the scripts like `python wallet-tool.py` etc., just as you did in the previous Joinmarket version.

Alternative to this "quickstart" (including for MacOS): follow the [install guide](docs/INSTALL.md).

### Upgrade for segwit

See the [segwit upgrade guide](docs/SEGWIT-UPGRADE.md) if you need to update your wallet.

### Usage

If you are new, follow and read the links in the [usage guide](docs/USAGE.md).

If you are running Joinmarket-Qt, you can instead use the [walkthrough](docs/JOINMARKET-QT-GUIDE.md) to start.

If you are not new to Joinmarket, the notes in the [scripts readme](scripts/README.md) help to understand what has and hasn't changed about the scripts.

### Joinmarket-Qt

Provides single join and multi-join/tumbler functionality (i.e. "Taker") only, in a GUI.

Binaries that are built and signed will be in the Releases page.  
To run the script `joinmarket-qt.py` from the command line, both the `PyQt4` and `sip` libraries are needed as dependencies. To make these two libraries available to Joinmarket, it's best to create symbolic links (symlinks) for them in the virtualenv directory `jmvenv`.  
For Debian and Ubuntu users, the install script attempts to install `python-qt4` and `python-sip` from the repositories, and then creates appropriate symlinks for them in the `jmvenv` directory.  
The steps to manually set up the Qt dependencies on Ubuntu\Debian are

1. first activate the Joinmarket virtualenv
    ```
    source ./jmvenv/bin/activate
    ```
2. Install the required dependencies
    ```
    sudo apt-get install python-qt4 python-sip
    ```
3. Locate the installed files
    ```
    dpkg-query -L python-qt4 | grep -m1 "/PyQt4$"
    dpkg-query -L python-sip | grep -m1 "sip.*\.so"
    ```
4. Create symlinks to each of the paths returned by the two previous commands in the virtualenv directory
    ```
    ln -sf -t "${VIRTUAL_ENV}/lib/python2.7/site-packages/" <python-qt4 path> <python-sip path>
    ```

The last two commands can be combined as :
```
ln -sf -t "${VIRTUAL_ENV}/lib/python2.7/site-packages/" "$(dpkg-query -L python-qt4 | grep -m1 "/PyQt4$")" "$(dpkg-query -L python-sip | grep -m1 "sip.*\.so")"
```

Finally, the command `python joinmarket-qt.py` from within the `scripts` subdirectory should work. There is a [walkthrough](docs/JOINMARKET-QT-GUIDE.md) for what to do next.

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
