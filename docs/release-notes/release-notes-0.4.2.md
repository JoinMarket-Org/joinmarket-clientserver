Joinmarket-clientserver 0.4.2:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.4.2>

This is a bugfix release, and to be considered essential for Makers (yield-generator runners).
See "Notable changes", first section, for details of the issue.

If you encounter errors in installation, please read the second section ("Changes to gpg usage in install procedure"). 

If you are upgrading from pre-0.4.0 you **must** read the [release notes for 0.4.0](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.4.0.md) and follow
the relevant upgrade instructions, which apply here exactly the same.

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading 
=========

To upgrade (if from pre-0.4.0):

As mentioned above, follow the instructions as per "Upgrading" in [release 0.4.0](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.4.0.md).



Notable changes
===============

### Fix crash bug on receipt of invalid PoDLE proof

286d306 fix crash on bad podle revelation

This fixes an effective DOS vector against Makers (hence it's an immediately needed upgrade).
Because the PoDLEError was not caught in the Maker code, any invalidly formatted proof simply crashes the Maker before this fix (this bug has been present since July 2017).

### Changes to gpg usage in install procedure

69f898d check gpg signatures on travis
b102b5d use gpg for fetching pubkeys

This should make it less likely to encounter errors when trying to install
libsodium as part of the Joinmarket installation process. However note:

A known issue exists in install.sh in which the following error will be returned :

...
gpg: can't open `libsodium-1.0.13.tar.gz.sig'
gpg: verify signatures failed: file open error
Libsodium was not built. Exiting.

This issue might affect users who have installed Joinmarket previously using the --no-gpg-validation flag, and are now re-installing without the use of the flag (as is the default install method).
To work around this issue, remove the libsodium-1.0.13.tar.gz file from the ./deps/cache/ directory and re-run install.sh.

### Update from txsocksx to txtorcon

637911d Replace unmaintained txsocksx with txtorcon.
2313a8a Pass ClientContextFactory to TorSocksEndpoint

This is purely backend and doesn't affect functionality.
Previously txsocksx was used to allow connections to hidden service
onions for IRC servers via a socks proxy. Unfortunately this package
is not maintained and breaks on Py3. So the dependency is changed to the
more up to date / maintained txtorcon.

### Minor administrative changes

Will not be of interest to non-developers (the key update is mentioned
on the main release page):

55c9483 update to new code signing key for AdamISZ
e32ba20 Add Qt5 support to TODO list
a612ddb Make it possible to override default python version in install.sh
1d70783 Add miniircd.tar.gz to gitignore.
089f75c Replace deprecated py.test syntax with pytest.

Credits
=======

Thanks to everyone who directly contributed to this release -

- @undeath
- @jameshilliard
- @fivepiece
- @AdamISZ
- @kristapsk

And thanks also to those who submitted bug reports, tested and otherwise helped out.


