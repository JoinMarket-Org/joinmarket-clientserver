Joinmarket-clientserver 0.3.3:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.3.3>

Minor release with bech32 destination support, an important bugfix (removing possible crash vector),
and some other minor additional features including MacOS support in the installation script.

Due to the security implications of the bugfix, upgrade immediately.

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading 
=========

To upgrade: run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.


Notable changes
===============

### Catch decryption errors in libnacl

`66875aed6e1596cec3eac5323eddabc45e3bafb2`

In the newest versions of the package libnacl, used for e2e encryption of messages between
participants (since 1.5.1), a new Exception type CryptError was introduced. This will not be
caught in previous versions of Joinmarket-clientserver, leading to a crash on certain inputs.
For this reason it's essential to upgrade to this fix if you are running libnacl >= 1.5.1.
You can check your version (while in the virtualenv) by typing `pip show libnacl` on the command line.

### Support for spending to a bech32 address

`2916d528fef2bacec87173734dab11b8b406d9e1`

Now allows script and Qt users to have the destination address in any coinjoin or normal spend
be a bech32 (native segwit) address. The address validation code is also updated. Note this does
not add support for *spending* from bech32/native segwit.

### Improvements to installation script including MacOS support

`3a3b2e19295558bc563392f5aaccd33655d8708d`, `9a7bf492498f01404f577e7589ae0b6f541a43cb`, `f1be9748673cb68c1c31741b91d6e49900b94c78`, `96f29cd5a4c79f37d2af18153b67d0020e29eede`, `fc3904ee03d5f3920ea2e747e82939c930a3fe52`, `bac5390b19f2cccf5c494089975a681ebc1d11c1`, `bf1a816e27a61b1a5bdc40bc281ddf28f472ded7`

A dev mode for the install script; some minor fixes; support for installation script on MacOS.

### Custom sighash flag support for segwit, tainting tool

`6679f92eba02b27b435ad88ed2c0a1a78889e7e1`, `8c24701d107e1a0248ece1ced7b2e346bb173d4a`

This will not currently have any impact on everyday usage, but to support utxo tainting
tools (related to adversarial fork scenarios), support was added for usage of custom
sighash flags (SIGHASH_ANYONECANPAY, SIGHASH_SINGLE, SIGHASH_NONE) in segwit BIP141/143.
Additionally a small script was created to allow utxo tainting, although it's been little
tested or used for now.

### Implement 'summary' flag in wallet-tool

`5be58469469dbd60acd15552d7d213991eb21554`

This produces a neat and shortened summary of coins in the wallet in each mixdepth.

### Fix listening on all interfaces for standalone joinmarketd.py

`467053beb938faecf64d17ac7fba2f7ef6c0e07a`

This completes the fix in the previous release, applying it to the non-standard case
of running joinmarketd separately.

### Fix payment amount limit on 32 bit systems

`b353bae139e0d60756156cc4e0a47eda14660dda`

Python on 32 bit systems had a limit on integer size < the maximum spend size in satoshis,
this is fixed using the `numbers` module.

### Reconnect to bitcoind after timeout

`0a55558d9ec54e36dbd85d20ec5a54dcf1d23ff9`

Credits
=======

Thanks to everyone who directly contributed to this release -

- @jameshilliard
- @undeath
- @fivepiece
- @AdamISZ
- @mecampbellsoup
- @user112012

And thanks also to those who submitted bug reports, tested and otherwise helped out.
