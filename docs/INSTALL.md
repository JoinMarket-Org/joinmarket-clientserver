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
    cd jmvenv; source bin/activate; cd ..

Install this repo in the virtualenv:

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

