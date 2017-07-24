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

Lastly, on compatibility, it's considered the responsibility of the developer(s) to
ensure that the code here is always compatible with that in the [main](https://github.com/Joinmarket-Org/joinmarket)
repo, so you should always be able to run the latest version and successfully transact
with other participants in the Joinmarket pit.

### Installation on Linux

To install everything (client and server), install these packages:

sudo apt-get install python-dev python-pip git build-essential
automake pkg-config libtool libffi-dev libssl-dev

(+ libsodium-dev if you can find it, else build after)

(to build libsodium after):

    git clone git://github.com/jedisct1/libsodium.git
    cd libsodium
    git checkout tags/1.0.4
    ./autogen.sh
    ./configure
    make check
    sudo make install
    cd ..

Then:

    sudo pip install virtualenv
    mkdir jmvenv
    virtualenv jmvenv
    source jmvenv/bin/activate

Install this repo:

    git clone https://github.com/AdamISZ/joinmarket-clientserver
    cd joinmarket-clientserver

#### Installing packages to run everything in-one:

    python setupall.py --daemon
    python setupall.py --client-bitcoin

If you have installed this "full" version of the client, you can use it with the
command line scripts as explained in the [scripts README](https://github.com/AdamISZ/joinmarket-clientserver/tree/master/scripts).

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

The latter case applies to the Electrum plugin, see [here](https://github.com/AdamISZ/electrum-joinmarket-plugin).

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
