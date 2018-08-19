Joinmarket-clientserver future:
===============================


Upgrading 
=========

To upgrade: run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.

A new wallet format has been introduced. Old wallets require conversion. In order to convert your existing wallet to the new format you can use the included conversion tool at `scripts/convert_old_wallet.py`.

usage:

    python convert_old_wallet.py full/path/to/wallets/wallet.json

This will place the newly converted `wallet.jmdat` file in the existing joinmarket `wallets/` directory. The wallet name will be adopted accordingly if it differs from `wallet`.


Notable changes
===============


Credits
=======

Thanks to everyone who directly contributed to this release -


And thanks also to those who submitted bug reports, tested and otherwise helped out.
