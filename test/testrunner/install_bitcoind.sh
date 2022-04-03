#!/usr/bin/env bash

set -ev

if [[ -z "$BITCOIND_VERSION" ]]; then
    echo "BITCOIND_VERSION must be set"
    exit 1
fi

if [[ "$(uname)" == "Linux" ]]; then
    platform="x86_64-linux-gnu"
elif [[ "$(uname)" == "Darwin" ]]; then
    if [[ $BITCOIND_VERSION > 23.0 || $BITCOIND_VERSION == 23.0 ]]; then
        platform="x86_64-apple-darwin"
    else
        platform="osx64"
    fi
else
    echo "Unsupported platform: $(uname)"
    exit 1
fi

if sudo cp ~/bitcoin/bitcoin-$BITCOIND_VERSION/bin/bitcoind /usr/local/bin/bitcoind
then
    echo "found cached bitcoind"
    sudo cp ~/bitcoin/bitcoin-$BITCOIND_VERSION/bin/bitcoin-cli /usr/local/bin/bitcoin-cli
else
    mkdir -p ~/bitcoin && \
    pushd ~/bitcoin && \
    wget https://bitcoincore.org/bin/bitcoin-core-$BITCOIND_VERSION/bitcoin-$BITCOIND_VERSION-$platform.tar.gz && \
    tar xvfz bitcoin-$BITCOIND_VERSION-$platform.tar.gz && \
    sudo cp ./bitcoin-$BITCOIND_VERSION/bin/bitcoind /usr/local/bin/bitcoind && \
    sudo cp ./bitcoin-$BITCOIND_VERSION/bin/bitcoin-cli /usr/local/bin/bitcoin-cli && \
    popd
fi
