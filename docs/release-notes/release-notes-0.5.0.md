Joinmarket-clientserver 0.5.0:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.5.0>

This release is mostly about "modernisation" - as of this release, Joinmarket **can be run under Python3** (including the GUI JoinmarketQt), as well as updating the binding to libsecp256k1. Big thanks to @jameshilliard for taking the initiative on getting this working.

However there also some bugfixes which prevent possible crash conditions, so you're recommended to upgrade immediately. Use of Python3 is optional; see the "Upgrading" note below on how to choose it.

Please note that although there is no current fixed timeline to deprecate Python2 entirely, it will be done at some point.

If you are upgrading from pre-0.4.0 you **must** read the [release notes for 0.4.0](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.4.0.md) and follow
the relevant upgrade instructions, which apply here exactly the same.

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading 
=========

To upgrade (but: see note above if from pre-0.4.0):

First run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.
To install using Python3, use `./install.sh -p python3` ; for now the default is still Python2.

If you are running JoinmarketQt, you *must* choose this Python3 option; see the README for the extra steps required.

Notable changes
===============

### Making the codebase compatible with Python3 usage

Here the python `future` package (see [here](https://python-future.org/)) has been used to allow the code to be compatible with Python 2.7 (in all earlier releases, only this version of Python was supported) and Python 3 (at least, 3.5 and 3.6, other versions of Py3 not tested). See above for the installation flags needed, and to repeat the previous note, Py3 is, from this release, required for the JoinmarketQt gui.

`3537fb4` Convert jmbitcoin to py3 style
`214dbf3` override system libsecp256k1 for coincurve
`6dc3504` Convert jmclient to py3 style
`8e5826d` Convert JoinmarketQt to PySide2
`9ce9ee5` Fix encode crash on IRC notice

### Fix crash conditions that may create DOS vectors for Makers/Takers

These edge conditions were discovered by @undeath and myself during the process of auditing the code that was necessary for the Python3 compatibility upgrade described above. They are all cases where some kinds of crafted input from a counterparty could cause the raise of an un-caught exception, resulting in the Maker or Taker process crashing (hence DOS vectors). They are not coin security risks. Nevertheless immediate upgrade, by Makers particularly (Taker crashes aren't really an issue), is recommended to make these impossible.

`979480e` fix possible crash on tx with odd scripts
`b112576` Validate maker destination addresses
`be6735d` Handle invalid utxos in query_utxo_set

### Use coincurve as new binding to libsecp256k1

Previously we were using the Python binding to [libsecp256k1](https://github.com/bitcoin-core/secp256k1) located [here](https://github.com/ludbb/secp256k1-py).
Now we have switched to [coincurve](https://github.com/ofek/coincurve) because it is actively maintained.
The changes to Joinmarket (as you can see in the below commit) are extremely minimal, as the interface is very close to the same.
We have audited and tested this change extensively, since it affects the core Bitcoin signing operations.

`abad597` Replace secp256k1-py with coincurve


### Minor technical changes

Will not be of interest to non-developers (these are mostly changes to tests/very minor refactoring).

`d353b5f` remove gpg verify disable flag from docker scripts
`fdc6687` remove gpg signature validation from install.sh
`5a0d5fe` Revert "Revert "Python 3 style conversion""
`8bcaf36` add full coinjoin test
`647335e` add undeath's pgp key
`249d547` clean up test_configure
`25ca6d2` testing: allow auditing maker wallets in manual test
`99ac1ca` update TESTING.md with latest test syntax
`512cddd` fix test_net_byte
`46e61f3` Fix bugs in bigstring and test_commands
`a43eceb` add very basic JMMakerClientProtocol test, fixes: 3ae5bff, 12705b5 
`d33cc5c` clean up Maker interface
`42060db` remove slowaes
`19fbef1` Fix nondeterministic failure in test tumbler tweak
`1033b64` remove unused locks from global config

Credits
=======

Thanks to everyone who directly contributed to this release -

- @jameshilliard
- @undeath
- @AdamISZ
- @fivepiece

And thanks also to those who submitted bug reports, tested and otherwise helped out.


