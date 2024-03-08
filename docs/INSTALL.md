* [Notes on upgrading, binaries and compatibility](#notes-on-upgrading-binaries-and-compatibility)
* [Installation on Linux](#installation-on-linux)
* [Installation on macOS](#installation-on-macos)
* [Installation on Windows](#installation-on-windows)
* [Alternative/custom installation](#alternativecustom-installation)

JoinMarket requires Python 3.8, 3.9, 3.10 or 3.11.

### Notes on upgrading, binaries and compatibility

(You can ignore this whole section if starting from scratch).

#### Notes on upgrading versions generally:

If you just want the latest version in a new directory, go to the [releases](https://github.com/JoinMarket-Org/joinmarket-clientserver/releases) page.

If you are upgrading from an older version, just update using git: `git pull origin master`,
or `git fetch; git checkout tags/<tagname>` for a specific tagged release, then rerun the installation
process as described below. This will only work if the latest commit, or the tag,
is actually newer in version number, than what was there already.

### Installation on Linux

**WARNING: This manual process is more difficult**; the `install.sh` script is recommended, please go back to the [README](../README.md) unless you're sure you need to do this.

To install everything (client and server), install these packages:

    sudo apt-get install python3-dev python3-pip python3-venv git build-essential automake pkg-config libtool libffi-dev libssl-dev

(+ `libsodium-dev` if you can find it, else build after)

(to build `libsodium` after):

    git clone https://github.com/jedisct1/libsodium.git
    cd libsodium
    git checkout tags/1.0.18
    ./autogen.sh
    ./configure
    make check
    sudo make install
    cd ..

Then install this repo:

    git clone https://github.com/Joinmarket-Org/joinmarket-clientserver.git
    cd joinmarket-clientserver

Then:

    python3 -m venv jmvenv
    source jmvenv/bin/activate

**At this point you should see `(jmvenv)` at the beginning of your command prompt.**

Then build and install a local copy of libsecp256k1 for python-bitcointx:

    mkdir -p deps
    cd deps
    git clone https://github.com/bitcoin-core/secp256k1.git
    cd secp256k1
    git checkout v0.4.1
    make clean
    ./autogen.sh
    ./configure --prefix JM_ROOT --enable-module-recovery --enable-experimental --enable-module-ecdh --enable-benchmark=no
    make
    make check
    make install
    cd ../..

> *NOTE*: JM_ROOT must be replaced with the venv directory you've just created, so it will be `~/joinmarket-clientserver/jmvenv` if you installed to your home directory.


#### Installing packages to run everything in-one:

> *NOTE*: It is very important to have activated the virtual environment before running this step. Otherwise, `pip install` will fail, you may be tempted to re-run it with `sudo pip install` which will cause problems in the future.

    pip install .[services]

If you have installed this "full" version of the client, you can use it with the command line scripts as explained in the [usage guide](USAGE.md).

### Installation on macOS

**WARNING: This manual process is more difficult**; the `install.sh` script is recommended, please go back to the [README](../README.md) unless you're sure you need to do this.

1) Install Apple Command Line Tools
    ```
    xcode-select --install
    ```
2) Install Homebrew
    ```
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ```
3) Install automake, libtool, and libsodium
    ```
    brew install automake libtool libsodium
    ```
4) Build secp256k1
    ```
    git clone https://github.com/bitcoin-core/secp256k1
    cd secp256k1
    git checkout 490022745164b56439688b0fc04f9bd43578e5c3
    ./autogen.sh
    ./configure --enable-module-recovery --disable-jni --enable-experimental --enable-module-ecdh --enable-benchmark=no
    make
    make check
    sudo make install
    cd ..
    rm -rf secp256k1
    ```
5) Clone the joinmarket-clientserver repo.
    ```
    git clone https://github.com/Joinmarket-Org/joinmarket-clientserver
    cd joinmarket-clientserver
    ```
6) Create virtual environment "jmvenv"
    ```sh
    python3 -m venv jmvenv
    source jmvenv/bin/activate
    ```
    At this point you should see `(jmvenv)` at the beginning of your command prompt.

7) Setup joinmarket-qt
    ```
    pip install .[gui]
    ```
8) Start joinmarket-qt
    ```
    cd scripts
    python joinmarket-qt.py
    ```

### Installation on Windows

Before starting, note you need either (a) Bitcoin Core installed on Windows or (b) use a remote connection to Bitcoin Core specified in the `joinmarket.cfg` (explained at the end of this section).

If (a), then note the following two points:

##### Installing Bitcoin Core

If you haven't done so yet, install Bitcoin Core, version 0.18 or newer, as described [here](https://bitcoin.org/en/full-node#windows-10). After starting it for the first time, it will start the Initial Block Download. JoinMarket cannot be used until this is finished. More information on that can be found [here](https://bitcoin.org/en/full-node#initial-block-downloadibd).

##### Configuring Bitcoin Core

Bitcoin Core needs to be configured to allow JoinMarket to connect to it. From the `Settings` menu choose `Options` and click `Open Configuration File`. Add `server=1`, save and close the file. After that restart Bitcoin Core.

There are currently two choices for installing on Windows; one, directly installing on Windows, requiring the manual addition of a libsodium dependency, or, two, using Ubuntu via the WSL mechanism (which may require additional setup to make the Qt GUI work).

1) [Installation directly on Windows](#installation-directly-on-windows)

2) [Installation using WSL](#installation-using-wsl)

#### Installation directly on Windows

As per the note above, binaries for JoinmarketQt are being offered with releases as of 0.7.0+.
This section is for doing a full command line install, on Windows.

First, if you have not done so, install [Python](https://www.python.org/downloads/windows/) - specifically, the latest Python 3 version. Make sure to choose to install `pip` during the installation (it should be included automatically, but you can choose the custom installation option to choose it).

Be sure to choose the option that allows `python` to be in your PATH variable (you are prompted to do this at the end of the install).

Install Joinmarket, choosing the zip file of the latest [release](https://github.com/JoinMarket-Org/joinmarket-clientserver/releases). You should check the .asc signature file on the zip that you download.

Unzip the `joinmarket-clientserver-x.x.x` (where `x.x.x` is the release number) in any appropriate location.

Using the command prompt in Administrator mode, go to that directory and run the commands:

`pip install joinmarket[services]`

(replace `services` with `gui` for Joinmarket-Qt).

The final step is to manually add the libsodium dependency, as mentioned. Do the following:

Download the file at `https://www.nuget.org/api/v2/package/libsodium` and rename it to `.zip` so that you can unzip it. Once unzipped, find the `libsodium.dll` file at `runtimes\win-x64\native\libsodium.dll` and copy it into `C:\Windows\System` (note this will require Admin rights).

At this point Joinmarket should be ready to run both in command line and Joinmarket-Qt form (using `python joinmarket-qt.py` from the `\scripts` subdirectory of `joinmarket-clientserver`).

From here, go to `Configuring Joinmarket` below.

#### Installation using WSL

> note: The following method requires Windows 10 version 1607 or later.

##### Enable Windows Subsystem for Linux
> note: a more detailed guide can be found [here](https://github.com/michaeltreat/Windows-Subsystem-For-Linux-Setup-Guide/blob/master/readmes/02_WSL_Ubuntu_setup.md).

 1. Open the `Control Panel` and navigate to `Programs`, `Programs and Features`, `Turn Windows features on or off`.
 2. Select `Windows Subsystem for Linux` and click `OK`.
 3. When asked, choose to restart.

##### Install Ubuntu from the Microsoft Store
1. Open the `Microsoft Store`, search for `Ubuntu 18.04 LTS` and click `Get`.
> note: other distributions are available, but this is the only one tested
2. When finished downloading click `Launch`.
3. A window should pop up, telling your `Installing, this may take a few minutes...`
4. After installation is done, you'll be asked to provide a `UNIX username` and `UNIX password`. This will be the administrator account for the Ubuntu installation.
5. Finish the installation with updating the software within Ubuntu by typing the command `sudo apt update && sudo apt upgrade -y`. When asked, type the password provided earlier.

##### Installing JoinMarket
At this point you have an (almost) fully featured Linux installation on Windows and you can install JoinMarket using the instructions in the [readme file](../README.md#quickstart) or [Installation on Linux](#installation-on-linux) section of this file.

Once you have finished installing the program via one of the two above methods for Windows, the final step is to configure Joinmarket:

#### Configuring JoinMarket
Lastly we must configure JoinMarket to allow it to connect to Bitcoin Core. Refer to [this](USAGE.md#managing-your-joinmarket-data) section in the usage guide to generate a `joinmarket.cfg` file using `scripts/wallet-tool.py`.

Edit your `joinmarket.cfg` file (at `~/.joinmarket` in Ubuntu if you used WSL, or in `C:\Users\<your username>\AppData\Roaming\joinmarket` if not) and replace the following lines in the section `[BLOCKCHAIN]`

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

If you installed directly on Windows, this should work normally, as explained in the [usage guide](USAGE.md)

If you installed using WSL, the following configuration is necessary:

> note: you need to have installed JoinMarket with Qt support (see [this](../README.md#joinmarket-qt) section in the readme file)
1. In Ubuntu, install additional dependencies `sudo apt install libgl1-mesa-glx`.
2. Download and install [MobaXterm](https://mobaxterm.mobatek.net). This program needs to be running before you can start JoinMarket-Qt. It requires no additional configuration.
3. Open WSL-Ubuntu session in MobaXTerm. Go to JoinMarket directory and run `source jmvenv/bin/activate` to activate the Python virtual environment.
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

#### Docker Installation

The [Dockerfile](../Dockerfile) provided builds a minimal Docker image which can help in getting started with a custom Docker setup. An example of building and running the [wallet-tool.py](../scripts/wallet-tool.py) script:

```
docker build -t joinmarket-test ./
docker run --rm -it joinmarket-test bash -c "cd scripts && python3 wallet-tool.py --help"
```

A new Docker image can be built using `joinmarket-test` as a base using `FROM joinmarket-test`. See [Docker documentation](https://docs.docker.com/engine/reference/builder/) for more details.

#### Development (or making other changes to the code)

If you are a developer or you plan on modifying the code (for example to add customizations),
do not run the `python setupall.py` commands above. Instead run:

    python setupall.py --develop

The normal installation (`--daemon` or `--client-bitcoin`) would install the JoinMarket
packages to the virtual environment's `site-packages` directory. This would mean any changes you make to
the local code would not have effect until the packages are reinstalled.

Using `--develop` causes a `.egg-link` file to be added to `site-packages` for each package.
The `.egg-link` file acts like a symlink pointing to the local code. This means any changes you
make to the code will have effect immediately.

