Joinmarket-clientserver 0.3.1:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.3.1>

Minor release for several useful additional features, and some minor bugfixes.

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading 
=========

To upgrade: run the `install.sh` script as mentioned in the README.


Notable changes
===============

### Electrum (servers) Blockchain Interface

`ff70b3d` `b10cbe9`

This is intended to help those on temporary or constrained environments, who are OK (temporarily) with a less ideal privacy model.

By specifying `electrum-server` in the `blockchain_source` setting in `joinmarket.cfg` you will make your blockchain queries via a random Electrum server.

Wallet sync should be fast (usually a few seconds, depending on details); usually transactions should not be significantly slowed down, either.

This feature also works for testnet for testing (although there are few working Electrum servers, of course).

Trying to use this feature for long running yield generators is not supported. Please continue to use Bitcoin Core in that case.

### Two-Factor Mnemonic Phrases for BIP39 wallets

`74c019b`

This release adds support for two-factor mnemonic phrases. The user can optionally provide a passphrase or "mnemonic extension", both this extension and the 12-word mnemonic are required to recover the wallet. The feature is backward-compatible with existing BIP39 joinmarket wallet files and mnemonic phrases, and is disabled by default. See the [bitcoin wiki page](https://en.bitcoin.it/wiki/Mnemonic_phrase#Two-Factor_Mnemonic_Phrases) for more explanation on two-factor mnemonic phrases.

It's now possible to have a wallet password be an empty string, and JoinMarket won't prompt for a password if so.

### Significantly improved installation script

`10f20ed` `8027853` `9e65d2e` `28507bd` `15433df` `ad7309e` `69d274f` `4f4f0e5` 

The installation script in 0.3.0 was very primitive, this is much better. Tested on a variety of Debian/Ubuntu distros.

It also checks gpg signatures, sets up the virtualenv for running joinmarket, and has additional features to encapsulate build tests.

### Transaction Fees

`769f2d7`

This allows setting a value in `tx_fees` to customize the fee,
particularly useful in cases where Bitcoin Core (or Electrum servers, see above) are reporting an unnecessarily high fee.

See [here](https://www.reddit.com/r/joinmarket/comments/6x5m41/advice_on_fees/) for more details.

### ob-watcher.py script updated for segwit

`2d69a52` `5cdc379`

### New yg-privacyenhanced.py script for Makers

`6126697`

It isn't intended to support multiple yg scripts in the main repo, this is probably the version we will stick
with in future (there is a repo [here](https://github.com/Joinmarket-Org/custom-scripts) for experimental scripts).

For now this is provided as a recommended replacement for `yield-generator-basic.py`, and it randomizes offer amounts to help privacy.

### Update wallethistory feature for jm-cs/segwit

`cd60cc1` `2215318`

Re-implements the wallethistory option to `wallet-tool.py` as currently exists in Joinmarket-Org/joinmarket.

Credits
=======

Thanks to everyone who directly contributed to this release -

- @AdamISZ
- @AlexCato
- @fivepiece
- @chris-belcher
- @adlai
- @mecampbellsoup

And thanks also to those who submitted bug reports, tested and otherwise helped out.
