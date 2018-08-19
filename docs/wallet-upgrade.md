A new wallet format has been introduced. Old wallets require conversion.
In order to convert your existing wallet to the new format you can use the
included conversion tool at `scripts/convert_old_wallet.py`.

usage:

    python convert_old_wallet.py full/path/to/wallets/wallet.json

This will place the newly converted `wallet.jmdat` file in the existing
joinmarket `wallets/` directory. The wallet name will be adopted accordingly
if it differs from `wallet`.

There is no need to move funds to the new wallet. All your funds, addresses,
private keys, history and also your seed will be retained.