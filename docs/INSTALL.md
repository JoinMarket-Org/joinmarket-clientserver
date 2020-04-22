* [Notes on upgrading, binaries and compatibility](#notes-on-upgrading-binaries-and-compatibility)
* [Installation on Linux](#installation-on-linux)
* [Installation on macOS](#installation-on-macos)
* [Installation on Windows](#installation-on-windows)
* [Alternative/custom installation](#alternativecustom-installation)

### Notes on upgrading, binaries and compatibility

(You can ignore this whole section if starting from scratch).

#### Upgrading to new segwit version (0.3.0+ of this repo)

See [here](SEGWIT-UPGRADE.md).

#### Notes on upgrading versions generally:

If you just want the latest version in a new directory, go to the [releases](https://github.com/AdamISZ/joinmarket-clientserver/releases) page.
Binary executables are not currently being built; that may change in the future.

Otherwise: if you are upgrading from an older version, just update using git: `git pull origin master`,
or `git fetch; git checkout tags/<tagname>` for a specific tagged release, then rerun the installation
process as described below. This will only work if the latest commit, or the tag,
is actually newer in version number, than what was there already.

### Installation on Linux

To install everything (client and server), install these packages:

    sudo apt-get install python3-dev python3-pip git build-essential automake pkg-config libtool libffi-dev libssl-dev libgmp-dev

(+ `libsodium-dev` if you can find it, else build after)

(to build `libsodium` after):

    git clone git://github.com/jedisct1/libsodium.git
    cd libsodium
    git checkout tags/1.0.18
    ./autogen.sh
    ./configure
    make check
    sudo make install
    cd ..

Then install this repo:

    git clone https://github.com/Joinmarket-Org/joinmarket-clientserver
    cd joinmarket-clientserver

Then:

    sudo pip install virtualenv
    virtualenv --python=python3 jmvenv
    source jmvenv/bin/activate

**At this point you should see `(jmvenv)` at the beginning of your command prompt.**


#### Installing packages to run everything in-one:

> *NOTE*: It is very important to have activated virtualenv before running this step. Otherwise, `pip install` will fail, you may be tempted to re-run it with `sudo pip install` which will cause problems in the future.

    pip install -r requirements/base.txt

If you have installed this "full" version of the client, you can use it with the
command line scripts as explained in the [scripts README](https://github.com/AdamISZ/joinmarket-clientserver/tree/master/scripts).

### Installation on FreeBSD

1) Fetch and extract ports
    ```
    portsnap fetch
    portsnap extract
    
2) Install dependencies
    ```
    pkg install -y bash python py37-pip py37-openssl py37-gmpy py37-sqlite3 libffi libsodium

3) Build OpenSSL with SSL3 support
    ```
    cd /usr/ports/security/openssl/ && make deinstall && make WITH=SSL3 BATCH=1 install clean

4) Decide where to keep the application and settings
    ```
    JM_BIN_DIR_PATH=/usr/local/bin/joinmarket
    JM_ETC_DIR_PATH=/usr/local/etc/joinmarket

4) Clone the joinmarket-clientserver repo and checkout current release tag
    ```
    git clone https://github.com/Joinmarket-Org/joinmarket-clientserver $JM_BIN_DIR_PATH
    cd $JM_BIN_DIR_PATH && git checkout current_release

5) Install python dependencies
    ```
    cd $JM_BIN_DIR_PATH && pip install virtualenv && virtualenv --python=python3 jmvenv

6) Configure python virtual environment
    ```
    /usr/local/bin/bash -c "source $JM_BIN_DIR_PATH/jmvenv/bin/activate; python setupall.py --daemon"
    /usr/local/bin/bash -c "source $JM_BIN_DIR_PATH/jmvenv/bin/activate; python setupall.py --client-bitcoin"

7) Generate config file
    ```
    $JM_BIN_DIR_PATH/jmvenv/bin/python $JM_BIN_DIR_PATH/scripts/wallet-tool.py --datadir=$INTERNAL_ETC_PATH

8) Install rc.script
    ```
    cp $JM_BIN_DIR_PATH/FreeBSD_rc.sh /usr/local/etc/rc.d/joinmarket && chmod +x /usr/local/etc/rc.d/joinmarket

9) Update settings
    ```
    $EDITOR $JM_ETC_DIR_PATH/joinmarket.cfg
    $EDITOR $JM_BIN_DIR_PATH/scripts/yg-privacyenhanced.py

10) Generate wallet
    ```
    service joinmarket onegenerate

11) Write password to .secrets file to enable joinmarket to start automatically after booting
    ```
    echo REPLACE_THIS_WITH_YOUR_PASSWORD > $JM_ETC_DIR_PATH/.secrets

12) Automate startup
    ```
    sysrc joinmarket_enable="YES"
    service joinmarket start

#### Commands to control joinmarket on FreeBSD
    ```
    service joinmarket start    # start joinmarket
    service joinmarket stop     # stop joinmarket
    service joinmarket wallet   # list addresses
    service joinmarket history  # display history

### Installation on macOS

1) Install Apple Command Line Tools
    ```
    xcode-select --install
    ```
2) Install Homebrew
    ```
    /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    ```
3) Install python3 and libsodium
    ```
    brew install python libsodium
    ```
4) Create virtualenv "jmvenv"
    ```sh
    pip3 install virtualenv
    virtualenv jmvenv
    source jmvenv/bin/activate
    ```
    At this point you should see `(jmvenv)` at the beginning of your command prompt.

5) Clone the joinmarket-clientserver repo.
    ```
    git clone https://github.com/Joinmarket-Org/joinmarket-clientserver
    cd joinmarket-clientserver
    ```
6) Setup joinmarket-qt
    ```
    pip install -r requirements/gui.txt
    ```
7) Start joinmarket-qt
    ```
    cd scripts
    python joinmarket-qt.py
    ```

### Installation on Windows
> note: Installing JoinMarket on Windows using the following method requires Windows 10 version 1607 or later.

#### Enable Windows Subsystem for Linux
> note: a more detailed guide can be found [here](https://github.com/michaeltreat/Windows-Subsystem-For-Linux-Setup-Guide/blob/master/readmes/02_WSL_Ubuntu_setup.md).

 1. Open the `Control Panel` and navigate to `Programs`, `Programs and Features`, `Turn Windows features on or off`.
 2. Select `Windows Subsystem for Linux` and click `OK`.
 3. When asked, choose to restart.

#### Install Ubuntu from the Microsoft Store
1. Open the `Microsoft Store`, search for `Ubuntu 18.04 LTS` and click `Get`.
> note: other distributions are available, but this is the only one tested
2. When finished downloading click `Launch`.
3. A window should pop up, telling your `Installing, this may take a few minutes...`
4. After installation is done, you'll be asked to provide a `UNIX username` and `UNIX password`. This will be the administrator account for the Ubuntu installation.
5. Finish the installation with updating the software within Ubuntu by typing the command `sudo apt update && sudo apt upgrade -y`. When asked, type the password provided earlier.

#### Installing JoinMarket
At this point you have an (almost) fully featured Linux installation on Windows and you can install JoinMarket using the instructions in the [readme file](../README.md#quickstart) or [Installation on Linux](#installation-on-linux) section of this file.

#### Installing Bitcoin Core
If you haven't done so yet, install Bitcoin Core as described [here](https://bitcoin.org/en/full-node#windows-10). After starting it for the first time, it will start the Initial Block Download. JoinMarket cannot be used until this is finished. More information on that can be found [here](https://bitcoin.org/en/full-node#initial-block-downloadibd).

#### Configuring Bitcoin Core
Bitcoin Core needs to be configured to allow JoinMarket to connect to it. From the `Settings` menu choose `Options` and click `Open Configuration File`. Add `server=1`, save and close the file. After that restart Bitcoin Core.

#### Configuring JoinMarket
Lastly we must configure JoinMarket to allow it to connect to Bitcoin Core. Refer to [this](USAGE.md#managing-your-joinmarket-data) section in the usage guide to generate a `joinmarket.cfg` file using `scripts/wallet-tool.py`.

Edit your `joinmarket.cfg` file (in Ubuntu) and replace the following lines in the section `[BLOCKCHAIN]`

```
rpc_user = bitcoin
rpc_password = password
```

with

```
#rpc_user = bitcoin
#rpc_password = password
rpc_cookie_file = <path to the Bitcoin Core data directory>/.cookie
```

The location of the data directory was chosen when Bitcoin Core was first run. The default is `C:\Users\<your username>\AppData\Roaming\Bitcoin`. In Ubuntu this would be `/mnt/c/Users/<your username>/AppData/Roaming/Bitcoin`. Assuming your username is `Alice` the full line would be

```
rpc_cookie_file = /mnt/c/Users/Alice/AppData/Roaming/Bitcoin/.cookie
```

#### Running JoinMarket-Qt
> note: you need to have installed JoinMarket with Qt support (see [this](../README.md#joinmarket-qt) section in the readme file)
1. In Ubuntu, install additional dependencies `sudo apt install libgl1-mesa-glx`.
2. Download and install [MobaXterm](https://mobaxterm.mobatek.net). This program needs to be running before you can start JoinMarket-Qt. It requires no additional configuration.
3. Open WSL-Ubuntu session in MobaXTerm. Go to JoinMarket directory and run `source jmvenv/bin/activate` to activate Python virtualenv.
4. You can now start JoinMarket-Qt as described [here](JOINMARKET-QT-GUIDE.md).
If you find that the program crashes with `qt.qpa.plugin: Could not load the Qt platform plugin`, you can add Qt5 dependencies with `sudo apt install qtbase5-dev` and try again.

### Alternative/custom installation:

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

