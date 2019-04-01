Joinmarket-clientserver 0.5.4:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.5.4>

This is a minor release adding a useful feature: basic coin control. Individual coins can
be frozen. Also there are some corrections/improvements to documentation, and some
minor fixes to the Qt GUI.

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading 
=========

To upgrade (but: read and follow instructions in 0.4.0 if from pre-0.4.0):

First run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.
To install using Python2, use `./install.sh -p python2` ; the default is now Python3.

Note that `.install.sh -?` will show the options for installation.

If you are running JoinmarketQt, note that Python2 is incompatible.

Notable changes
===============

### Basic coin control

See issue #274 for some motivation. As a privacy wallet, and especially considering active dust
attacks seen in the wild, this functionality is important. Note it is "basic" in the sense that it
neither detects and freezes unwanted dust deposits automatically yet (that is planned),
nor does it allow choosing coins to spend in a positive sense - to spend a specific coin(utxo),
you will have to first disable all other coins in the mixdepth/account.

This feature is also enabled in the Qt GUI in a new tab labelled "Coins". It's actually easier to use
in the GUI, since you can toggle "frozen/not frozen" statement with a right click menu choice; on
the CLI you will have to go through a menu for each coin you want to freeze.

The frozen-ness status of individual utxos/coins is of course persisted in the wallet file so it is
remembered between restarts.

Also, to be clear, "frozen-ness" means: the coin will not be chosen for any transaction, coinjoin
or otherwise. It *will* still be included in balance calculations, and shown in the wallet-tool output.

`9295673` Basic coin control.

`bfdf0b2` expand non-empty tree sections in Coins tab


### Minor changes

Several minor changes to the documentation to improve or correct it (thanks to @hyp-hen in particular
for correct the out-of-date MacOS install instructions), and a couple of small bugfixes in Qt GUI workflow.

`24e7bfe` Fix markup typo in README

`26e6e15` Minor updates to docs on installation and usage; add segwit donation address to Qt About page.

`2dd9c06` Update installation instructions for macOS

`46ce06d` Display GUI error to user when no password entered on wallet load

`9e2db3c` Don't ask for wallet password if "Cancel" pressed in "Load" dialog

`5026809` Don't ask for maxcjfee limits when manual order picking is selected

`b75702e` Correct help, Bitcoin Core wallets aren't supported for some time already


Credits
=======

Thanks to everyone who directly contributed to this release -

- @kristapsk
- @hyp-hen
- @chris-belcher
- @AdamISZ
- @undeath

And thanks also to those who submitted bug reports, tested and otherwise helped out.


