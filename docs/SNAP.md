# JoinMarket Snap

The Snap package makes installing and upgrading easier on linux distributions.

# Build

Run `snapcraft` from the JoinMarket root path.

# Install

Run `snap install --dangerous --devmode joinmarket_$VERSION_amd64.snap` to install the created `.snap`.

## Snapcraft store

The "edge" version of JoinMarket can be install from the Snapcraft store with `snap install --edge joinmarket`. The "edge" is based off of the latest code in the master branch of github.

# Usage

To use JoinMarket, first the configuration needs to be generated and set to connect to a Bitcoin full node. It is also recommended to connect to a Tor client for more privacy in your CoinJoin transactions.

## Generate config

Run `joinmarket generate` to generate the config. From which point, the config (located at `~/snap/joinmarket/.joinmarket/joinmarket.cfg`) can be modified.

## Generate wallet

Run `joinmarket generate` to generate a new wallet.

## Get help for commands

Run `joinmarket help` for a list of shortcut commands. Run `joinmarket ls` for a list of scripts which can be ran directly.

## Normal usage

Most users will probably want to run `joinmarket display` and `joinmarket sendpayment` to send and receive transactions.

# Known Bugs

- Currently the GUI does not work on Arch Linux. See this [Snapcraft forum thread](https://forum.snapcraft.io/t/python3-qt-application-on-arch-linux-segmentation-fault-core-dumped/15333/6) for details.
- Running `joinmarket` right after a new version is released will sometimes print a bunch of warnings which don't seem to effect JoinMarket but are annoying.
