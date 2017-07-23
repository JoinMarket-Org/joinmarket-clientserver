### Migrating to a new segwit based wallet.

To do joinmarket coinjoins with other participants using segwit, you need to use
a wallet with segwit addresses. These addresses are P2SH (start with '3' on mainnet);
note they are *not* multisig, however, they are yours only (technically we are using
address type P2SH/P2WPKH).

#### If you don't have an existing Joinmarket wallet:

You can go into the `scripts/` directory, which contains the `wallet-tool.py` script,
and follow the instructions as in the first half of:

https://github.com/JoinMarket-Org/joinmarket/wiki/Using-the-JoinMarket-internal-wallet

You will notice the main difference from what's shown there is that after using
the `generate` command, your new wallet has addresses starting with '3' not '1'.
Also, the BIP32 paths are different, see the bottom of this page for some details on that.

#### If you do have an existing Joinmarket wallet:

Migrating coins to this new-style wallet can be done in these steps:

* Install this new version (0.3.0+), see [here](INSTALL.md)

* Generate a new wallet; go into the `scripts/` directory and do the same as before:

    python wallet-tool.py generate

Once you've written down the 12 word seed and saved the new .json file, check the
addresses with:

    python wallet-tool.py newwallet.json

(or whatever you called the file). You should see a set of '3' addresses (or '2' on testnet) instead of '1'. Also the
spacing/layout may look a bit different, but it's the same information.

Note down at least 3 addresses from mixdepth 0 if you plan to use as a Taker; if as
a Maker (yieldgenerator), best to note down one address from each mixdepth.

Next, load your old wallet; you have two options - either (1) use your old Joinmarket
installation (easier), or (2) use this one, and go into joinmarket.cfg and add:

    segwit = false

to the `[POLICY]` section. This will allow you to run `python wallet-tool.py` and it
will find the old wallet. Whether using method (1) or (2), the next step is the same:

Use `python sendpayment.py -N 0 -m [mixdepth] oldwalletname 0 destaddr` to send coins from
your old wallet, mixdepth 0, into the new one you've created, with a sweep from that
mixdepth. The -N 0 means using direct-send, i.e. not using joinmarket/IRC, so it's 
the cheapest/most convenient. Don't forget to reset `tx_fees` in your joinmarket.cfg
if you want to adjust the projected fee.

If you've used (2), then delete the line `segwit = false` from joinmarket.cfg, and
reload the new wallet with python wallet-tool.py newwalletname.json

Once you're sure it's working you can repeat this process for any number of mixdepths
for which you want to transfer coins.

#### Typical wallet output (testnet) for reference

```
JM wallet
mixdepth	0	tpubDC3ynQKo14bet1kCgg5ms7d5ABHVkrWLKLqbMQTiDY5T3nd4dUCCLNzJFyj78FvcQbDsJCk96AJfdATnS7Cf1VaM2JsqM73i2VyBeoQVSwa
external addresses	m/49'/1'/0'/0	tpubDEdFHGLtyru2nSRdv4F3GXw8MQBx5mVaJQeTP7Am6okGeQLfqt9ysD2npE9eFQXNBfcamxooyJ4nKfb2rQzG97zNsG9tex4YRUKRwRMBvR5
m/49'/1'/0'/0/000	2NGQED4c5BZL1RNVgzJHM7BAThPyT1GXXdf	2.00000000	used
m/49'/1'/0'/0/001	2N2xYemrtcTHdVxejvAKgYcbx27pJbWcC7D	0.00000000	new
m/49'/1'/0'/0/002	2N6D25kEWEgN78rG8i8soBo2N4kJ3U6jKhK	0.00000000	new
m/49'/1'/0'/0/003	2Mzerss9QDXi3PyyxiTwSN2xV3977EBmRK9	0.00000000	new
m/49'/1'/0'/0/004	2MtFEA9H43ptf2MUcZoA9WFQvg6XF5iVgsk	0.00000000	new
m/49'/1'/0'/0/005	2MzJTsaZFBc3HDktYKvd8rkTGeDMCmaMWPn	0.00000000	new
m/49'/1'/0'/0/006	2Mu2NezBjuzXKaJKrPAh7a9TcWa7REDXNXt	0.00000000	new
Balance:	2.00000000
internal addresses	m/49'/1'/0'/1	
Balance:	0.00000000
Balance for mixdepth 0:	2.00000000
mixdepth	1	tpubDC3ynQKo14bevgk8tW8uX6TbdThjGcLkULcZUtMkeH7QVK5wXXF9nLF8dYUrvVkVcbUpsSgCZyQDajHNJzcg8f6FDHSFgS4ask5BgdeTock
external addresses	m/49'/1'/1'/0	tpubDFRo71SzBY98U2suh1CVgFV8s7SbdTUYj3xgg4Zk9XrPAFfXg7krxCLsVmq8pYW7bWcnRMPrRP9uVrgLSztKGvHJE2Re64CgNPNddpqzArm
m/49'/1'/1'/0/000	2N42BUaNAGuEsVxXtgR2i2XRWwFyrcku7xJ	2.00000000	used
m/49'/1'/1'/0/001	2N6wivgfa9SNAmLkNLTA5tjLa6RbteiJ9NP	2.00000000	used
m/49'/1'/1'/0/002	2N8fsY6cPigbkyAUPoYuqXrvwSTNbDuSs38	2.00000000	used
m/49'/1'/1'/0/003	2N7p1vw9yB5GRyX2rDMfUGu6szVtNFrsJ4J	0.00000000	new
m/49'/1'/1'/0/004	2N8ezrbwLe4HVRKupxGDxqqah6QWvpafCMr	0.00000000	new
m/49'/1'/1'/0/005	2MshrDThyZD6irvPzqjPm7UENwptL9jwWMu	0.00000000	new
m/49'/1'/1'/0/006	2Mw8zcteMmzdEqtVDjWrJ425wSog3TsSzgt	0.00000000	new
m/49'/1'/1'/0/007	2MukpuXRWAa1oSZnvcodybvnEz9L2EF9bLv	0.00000000	new
m/49'/1'/1'/0/008	2N6Zhsg7E6KjEY3PUaLsZqpzpfLrqiTkUaE	0.00000000	new
Balance:	6.00000000
internal addresses	m/49'/1'/1'/1	
Balance:	0.00000000
Balance for mixdepth 1:	6.00000000
mixdepth	2	tpubDC3ynQKo14bf1LnhHPQQ2ReJCZzV24AViKCKGW99SBwFr3DLSio24mwjNcHZwDqdGUejr6K3WEhv7DdASLNrFsZhx8rgbjzTtYGjeuZLPtf
external addresses	m/49'/1'/2'/0	tpubDEunZR6GYohjUiAsNecPvm6zA63apCuKe4J8bJz9tjJAuNy485e4LQFAmuF3YVzHFbUvbDpGz1SvGx1tLvoYrExo5Cmhbnw9N4RcJfQVcy8
m/49'/1'/2'/0/000	2MujbkR3UsUfYf53e4TNErWqpxLEFeX7CjF	0.00000000	new
m/49'/1'/2'/0/001	2N6c1979MmfdZPhGQHpPx4upZoh9A66tpXx	0.00000000	new
m/49'/1'/2'/0/002	2N12iWBShn3NhbqiJVrERJ1ArE2aNbJLiuC	0.00000000	new
m/49'/1'/2'/0/003	2N2WRcxDYkaNHxnv4upAiqCCVRz9YyMqvCA	0.00000000	new
m/49'/1'/2'/0/004	2ND2k7Bsh21dNqC52dK5GtXeXhfQDUfpuc6	0.00000000	new
m/49'/1'/2'/0/005	2N9PvkbGu93vE52v433maZwjkjMQvcXgguc	0.00000000	new
Balance:	0.00000000
internal addresses	m/49'/1'/2'/1	
Balance:	0.00000000
Balance for mixdepth 2:	0.00000000
mixdepth	3	tpubDC3ynQKo14bf3T8XrYA9CgKLmpr1wsAZf2VuGhku36bXQMaCRYges3NWd9AW7GoFTiCAwyPWTTz4V99A3VDSKryPgG7US1vaNLB8daxFWXh
external addresses	m/49'/1'/3'/0	tpubDEf2oHNW6QCmUF4moLgMpjhgmsnJgDGdfrihxBFGAXncbnvhHBAWD8EFe6hphPpBxtoEaHVaSvqTQW52QJ282vMQxvDNPDzPrnrDu8Hem6p
m/49'/1'/3'/0/000	2N5Ybuqi3a8Wfg8gZfjN5CVNBUYPirsNda6	0.00000000	new
m/49'/1'/3'/0/001	2MxQgX1Ykcj1fJzeVZDJ7xmcdRZjxnB5PHp	0.00000000	new
m/49'/1'/3'/0/002	2N7JwhZEo2CjphzU8FRVJm7CU8UF2FVRYPF	0.00000000	new
m/49'/1'/3'/0/003	2N5MJvtRGTdQSipDsBgDLHQzc3hzwMdk6BK	0.00000000	new
m/49'/1'/3'/0/004	2NGUERANYNAZamXWGMtYxJy49WvQra69FPP	0.00000000	new
m/49'/1'/3'/0/005	2MvxVh7hpxCGfojwmtW32K9QkkahP2bvSyZ	0.00000000	new
Balance:	0.00000000
internal addresses	m/49'/1'/3'/1	
Balance:	0.00000000
Balance for mixdepth 3:	0.00000000
mixdepth	4	tpubDC3ynQKo14bf5z1LUdPiEFaJ3omV4y2VasyT5PUL8H9JhShXMvn24zRhRdpMA5oAVwheLmvL2J6r2NFoUdoSVhZjCWd1aUxsUfa332cnEpk
external addresses	m/49'/1'/4'/0	tpubDEW6kkqjuEdqiNCpPixL2ToQWsRNojGHzWBfXpUDp9cyix8en1HY2ZwndU3KCNBbdpac5GiUwkqR2jiZjtRedAAbnNHWL86cEDMsMoFXiTH
m/49'/1'/4'/0/000	2NEraA2d5cV83qQkg7oebhx2ugGT4eF9QY5	0.00000000	new
m/49'/1'/4'/0/001	2N5RKKMTFXA8Punt6H9JrPQFnNJFz3DSe9W	0.00000000	new
m/49'/1'/4'/0/002	2NBzFW263ohqGyK53HuFcB7kSLkvBSV38gc	0.00000000	new
m/49'/1'/4'/0/003	2NCLjgm6Dgc3q4QSNiRUMKbt2aQSidGNfrX	0.00000000	new
m/49'/1'/4'/0/004	2MvQkFkhZeymz8r1XtSUT3fz3hdaZp2dxt5	0.00000000	new
m/49'/1'/4'/0/005	2N9zM5Jv4tjwJ2ezKMQi4ECjvheWugWajhj	0.00000000	new
Balance:	0.00000000
internal addresses	m/49'/1'/4'/1	
Balance:	0.00000000
Balance for mixdepth 4:	0.00000000
Total balance:	8.00000000
```

### Information about the new wallet type and compatibility.

First, the seed phrase is now based on BIP39, but this is transparent: it's still
a 12 word seed, but based on a new dictionary.
It uses the [mnemonic](https://github.com/trezor/python-mnemonic) package/implementation.

Second, this new wallet type is not compatible with the old; that doesn't make sense - even if it generated the same private keys,
you would still have to transfer to new segwit style outputs.

Third, the new type is based on [BIP49](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki),
which is currently supported only by TREZOR to my knowledge, although others may later adopt it.
So these Joinmarket wallets could be loaded into TREZOR; at least, that's expected.

BIP49 is a modification of BIP44 for segwit, but really it's just a new BIP32 HD path.
(To get even further into the technical weeds, these standards (44/49) use hardened derivation except for keys below the account level).


### Fees

Segwit doesn't have much direct technical import for Joinmarket, since coinjoin
(at least when properly implemented) isn't subject to any dangers from transaction
malleability.

However, there can be significant, if not huge, fee savings based on the change from 'size'
to 'weight' in block limits. Instead of paying (fee/kB) * kB of tx size, you pay
for (non-witness + 0.25 * witness)/4 * (fee/kB) (very rough explanation), which rough
calculations suggests might give ~ 25-30% savings over a non-segwit tx in a typical scenario.
Somewhat higher fee savings may be achieved if we switched to a "native" segwit address in future,
rather than a P2SH-wrapped one.

#### Note for Makers

Since segwit-style joinmarket must be done "all-in-one" for privacy (otherwise a Taker
risks creating a single '1' address output), the yieldgenerator in this implementation
makes `swreloffer` and `swabsoffer` offer types, and won't also offer original-type offers.
However, the parameters of the offer are the same, and are still set in the (now much
simplified) `yield-generator-basic.py` script. Other variants may be added later subject to
anyone getting around to doing it.