#!/bin/bash
set -e
clear

#Adapted from https://github.com/tailsjoin/tailsjoin/blob/master/tailsjoin-fullnode.sh

# Check for root.
if [[ $(id -u) = "0" ]]; then
  echo "
YOU SHOULD NOT RUN THIS SCRIPT AS ROOT!
YOU WILL BE PROMPTED FOR THE ADMIN PASS WHEN NEEDED.
"
  read -p "PRESS ENTER TO EXIT SCRIPT, AND RUN AGAIN AS NON-ROOT USER. "
  exit 0
fi


# Make sure user has chosen the correct script.
echo "
          THIS SCRIPT WILL INSTALL JOINMARKET-CS AND DEPENDENCIES.
             ADMIN PASS WILL BE REQUIRED MULTIPLE TIMES.
"
read -p "PRESS ENTER TO CONTINUE. "
clear

# Update apt-get sources.
echo "
ENTER PASSWORD TO UPDATE SOURCES.
"
sudo apt-get update
clear


# Install dependencies for building libsodium.
echo "
ENTER PASSWORD TO INSTALL: python-virtualenv curl python-dev python-pip git build-essential automake pkg-config libtool libffi-dev libssl-dev
"
sudo apt-get install -y python-virtualenv curl python-dev python-pip git build-essential automake pkg-config libtool libffi-dev libssl-dev
clear

# Get libsodium, sig, and import key.
echo "
DOWNLOADING LIBSODIUM SOURCE AND SIGNING KEY...
"
gpg --keyserver pgp.mit.edu --recv-keys 54A2B8892CC3D6A597B92B6C210627AABA709FE1
echo "54A2B8892CC3D6A597B92B6C210627AABA709FE1:6" | gpg --import-ownertrust -
curl -L -O http://download.libsodium.org/libsodium/releases/libsodium-1.0.12.tar.gz -O http://download.libsodium.org/libsodium/releases/libsodium-1.0.12.tar.gz.sig
clear


# Verify download.
echo "
VERIFYING THE DOWNLOAD...
"
gpg --verify libsodium-1.0.12.tar.gz.sig libsodium-1.0.12.tar.gz
echo "
PLEASE REVIEW THE TEXT ABOVE.
IT WILL EITHER SAY GOOD SIG OR BAD SIG.
"
read -p "IS IT A GOOD SIG? (y/n) " x
if [[ "$x" = "n" || "$x" = "N" ]]; then
  echo "
YOU REJECTED THE LIBSODIUM SIGNATURE, GIVING UP...
"
  srm -drv libsodium*
  exit 0
fi
clear


# Build and install libsodium.
tar xf libsodium*.tar.gz
rm -rf libsodium*.tar.gz*

echo "
BUILDING LIBSODIUM...
"
cd libsodium-1.0.12/ && ./configure && make
echo "
LIBSODIUM SUCCESSFULLY BUILT. ENTER PASSWORD TO INSTALL.
"
sudo make install
cd ..
rm -rf libsodium*
clear

# Verify the signature on joinmarket-clientserver
# Currently commented out - doesn't apply if you've already downloaded the repo
# either as zip or clone; can check valid signature on github (OK?)
#gpg --keyserver pgp.mit.edu --recv-keys 46689728A9F64B391FA871B7B3AE09F1E9A3197A
#echo "46689728A9F64B391FA871B7B3AE09F1E9A3197A:6" | gpg --import-ownertrust -
#Todo: handle signing by another key and check the release tag, not commit.
#git verify-commit HEAD || {
# echo 'Latest code commit does not have a valid signature; quitting'
# exit 0
#}

#Run the python installation of joinmarket-clientserver;
#note that this is a 'full' installation, which is the default
#for an ordinary user; this should be enhanced to allow custom
#installation styles.
#Installs into a virtualenv, so instructions to run must be included.
if ! mkdir venv; then
 echo "virtualenv directory already exists; assuming valid."
fi
virtualenv venv
source venv/bin/activate
#required for older pips, e.g. on Ubuntu 14.04
pip install --upgrade setuptools
#Doing manually instead of as in setupall.py
cd jmbase
pip install .
cd ..
cd jmdaemon
pip install .
cd ..
cd jmbitcoin
pip install .
cd ..
cd jmclient
pip install .
cd ..

# Final notes.
echo "
          JOINMARKET SUCCESSFULLY INSTALLED.
          BEFORE RUNNING SCRIPTS, TYPE:
          source venv/bin/activate
          FROM THIS DIRECTORY, TO ACTIVATE THE VIRTUALENV.
"
read -p "PRESS ENTER TO EXIT SCRIPT. "
exit 0;
