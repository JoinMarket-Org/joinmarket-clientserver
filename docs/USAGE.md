### Zeroth step: configuring Bitcoin Core

Until such time as we have a better solution for a light client, Joinmarket only
realistically supports use with Bitcoin Core to connect to the Bitcoin network.
The node *can* be pruned.

**Use with another interface to the blockchain should be considered highly experimental
(and in most cases it doesn't really work, as well as being terrible for privacy). It is not supported at this time.**

For notes on how to configure your Core node for use with Joinmarket, read [here](https://github.com/JoinMarket-Org/joinmarket/wiki/Running-JoinMarket-with-Bitcoin-Core-full-node#requirements--how-to).


### First step: make a Joinmarket wallet

Use [this](https://github.com/JoinMarket-Org/joinmarket/wiki/Using-the-JoinMarket-internal-wallet) guide,
BUT: a couple of differences:

* The `wallet-tool.py` script is in the `scripts/` directory, so start there.
* The output when you "display balance" will look a bit different: the addresses start with '3'.
* The layout is also slightly different, but it's the same information.
* The BIP32 paths look like m/49'/0'/0'/0/000 instead of m/0/0/0/000; that's just a new segwit standard.

(The new standard *should* be compatible with TREZOR, including the 12 word seed; other wallets, mostly not, although standards haven't settled down yet).

### Second step: Funding the wallet.

Read [this section](https://github.com/JoinMarket-Org/joinmarket/wiki/Using-the-JoinMarket-internal-wallet#funding-wallet-and-displaying-balance)
in the previously linked page. Don't neglect the point mentioned that, if you are planning to do your own coinjoins
(act as "Taker", you must fund multiple different addresses to avoid inconvenience in future. For Makers, that's not necessary.

### Third step: Try out a coinjoin

To try doing one coinjoin, use the `sendpayment.py` script. See [here](https://github.com/JoinMarket-Org/joinmarket/wiki/Sending-payments-with-CoinJoin#send-payment)

(Note that the `patientsendpayment` option, also described on that page, is not yet implemented in this version, but probably will be soon).

(Note also that you can use 'schedule' files in this new version, but that's more advanced so ignore it for now.)

### 4a step: if you want to be a "Maker" or "yield generator".

Read the introductory guide [here](https://github.com/JoinMarket-Org/joinmarket/wiki/Running-a-Yield-Generator).

You can use the `yield-generator-basic.py` script in the `scripts/` directory.
The new script (much simplified) has the same fields at the top you can edit; note
the new offertypes are 'swreloffer', 'swabsoffer' - they function the same, but use segwit.


### 4b step: if you want to run the tumbler script.

Read the instructions [here](tumblerguide.md)