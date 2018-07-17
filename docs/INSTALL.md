### Notes on upgrading, binaries and compatibility

(You can ignore this whole section if starting from scratch).

#### Upgrading to new segwit version (0.3.0+ of this repo)

See [here](SEGWIT-UPGRADE.md).

#### Notes on upgrading versions generally:

If you just want the executable/GUI/binary version of the code, always use
the latest version of those files (example: joinmarket-qt.exe for Windows) found
on the [releases](https://github.com/AdamISZ/joinmarket-clientserver/releases) page.

(Note, sometimes this won't be the latest release, so you may have to scroll down
a little; not all releases, for now, will include binary builds).

Otherwise: if you are upgrading from an older version, just update using git: `git pull origin master`,
or `git fetch; git checkout tags/<tagname>` for a specific tagged release, then rerun the installation
process as described below. This will only work if the latest commit, or the tag,
is actually newer in version number, than what was there already.

### Installation on Linux

To install everything (client and server), install these packages:

    sudo apt-get install python-dev python-pip git build-essential automake pkg-config libtool libffi-dev libssl-dev

(+ `libsodium-dev` if you can find it, else build after)

(to build `libsodium` after):

    git clone git://github.com/jedisct1/libsodium.git
    cd libsodium
    git checkout tags/1.0.4
    ./autogen.sh
    ./configure
    make check
    sudo make install
    cd ..

Then install this repo:

    git clone https://github.com/AdamISZ/joinmarket-clientserver
    cd joinmarket-clientserver

Then:

    sudo pip install virtualenv
    virtualenv jmvenv
    source jmvenv/bin/activate

**At this point you should see `(jmvenv)` at the beginning of your command prompt.**


#### Installing packages to run everything in-one:

> *NOTE*: It is very important to have activated virtualenv before running this step. Otherwise, `setupall.py` will fail, you may be tempted to re-run it with `sudo setupall.py` which will cause problems in the future.

    python setupall.py --daemon
    python setupall.py --client-bitcoin

If you have installed this "full" version of the client, you can use it with the
command line scripts as explained in the [scripts README](https://github.com/AdamISZ/joinmarket-clientserver/tree/master/scripts).

### Installation on macOS

1) Install Apple Command Line Tools

    xcode-select --install

2) Install Homebrew

    /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
	
3) Install PyQt4

    brew install cartr/qt4/pyqt@4 libsodium
	
4) Create virtualenv "jmvenv"

```sh
    export PATH=/usr/local/opt/python/libexec/bin:$PATH
    pip install virtualenv
    virtualenv --python=/usr/local/opt/python/libexec/bin/python --system-site-packages jmvenv
    source jmvenv/bin/activate
```

At this point you should see `(jmvenv)` at the beginning of your command prompt.

5) Clone the joinmarket-clientserver repo. Follow 5a for segwit and 5b for non-segwit

 5a Segwit

    git clone https://github.com/Joinmarket-Org/joinmarket-clientserver
    cd joinmarket-clientserver
    git checkout v0.3.4

 5b Non-segwit

    git clone https://github.com/Joinmarket-Org/joinmarket-clientserver
    cd joinmarket-clientserver
    git checkout 6ad114d

6) Setup joinmarket-qt
```
    python setupall.py --daemon
    python setupall.py --client-bitcoin
```
7) Start joinmarket-qt
```
    cd scripts
    python joinmarket-qt.py
```
Alternative/custom installation:

#### Installing the daemon separately

Just do

    python setupall.py --daemon

Then, you can run the daemon on its own with

    cd scripts; python joinmarketd.py <port number>

The reason for doing this may be either (1) to run command-line scripts provided here, but
in a separate process from the daemon; or, (2) to run a separate (e.g. wallet plugin) codebase
to do the bitcoin operations.

In the former case you will need still to install the local packages:
 
    python setupall.py --client-bitcoin

and then edit your `joinmarket.cfg` section `DAEMON`, setting `no_daemon = 0`.

The latter case applies to the Electrum plugin (not currently operational), see [here](https://github.com/AdamISZ/electrum-joinmarket-plugin).

There, you need to install the client code (without Joinmarket's bitcoin):

    python setupall.py --client-only

#### Development (or making other changes to the code)

If you are a developer or you plan on modifying the code (for example to add customizations),
do not run the `python setupall.py` commands above. Instead run:

    python setupall.py --develop

The normal installation (`--daemon` or `--client-bitcoin`) would install the JoinMarket
packages to the virtualenv's `site-packages` directory. This would mean any changes you make to
the local code would not have effect until the packages are reinstalled.

Using `--develop` causes a `.egg-link` file to be added to `site-packages` for each package.
The `.egg-link` file acts like a symlink pointing to the local code. This means any changes you
make to the code will have effect immediately.
