# Fidelity bonds

Fidelity bonds are a feature of JoinMarket which improves the resistance to
sybil attacks, and therefore improves the privacy of the system.

A fidelity bond is a mechanism where bitcoin value is deliberately sacrificed
to make a cryptographic identity expensive to obtain. The sacrifice is done in
a way that can be proven to a third party. Takers in JoinMarket will
have a higher probability to create coinjoins with makers who publish more
valuable fidelity bonds. This has the effect of making the system much more
expensive to sybil attack, because an attacker would have to sacrifice a lot of
value in order to be chosen very often by takers when creating coinjoin.

As a maker you can take part in many more coinjoins and therefore earn more
fees if you sacrifice bitcoin value to create a fidelity bond. The most
practical way to create a fidelity bond is to send bitcoins to a time-locked
address which uses the opcode [OP_CHECKLOCKTIMEVERIFY](https://en.bitcoin.it/wiki/Timelock#CheckLockTimeVerify).
The valuable thing being sacrificed is the time-value-of-money. Note that a
long-term holder (or hodler) of bitcoins can buy time-locked fidelity bonds
essentially for free, assuming they never intended to transact with their coins
anyway.

The private keys to fidelity bonds can be kept in [cold storage](https://en.bitcoin.it/wiki/Cold_storage)
for added security. (Note: not implemented in JoinMarket)

For a more detailed explanation of how fidelity bonds work see these documents:

* [Design for improving JoinMarket's resistance to sybil attacks using fidelity
bonds](https://gist.github.com/chris-belcher/18ea0e6acdb885a2bfbdee43dcd6b5af/)

* [Financial mathematics of JoinMarket fidelity bonds](https://gist.github.com/chris-belcher/87ebbcbb639686057a389acb9ab3e25b)

## How to use fidelity bonds as a taker

In JoinMarket version v0.9 or later takers will by default use fidelity bonds. The user gains
very strong protection from sybil attacks without needing to do anything different.

The orderbook watcher script now displays information about any fidelity bonds
advertised by makers, as well as calculating how strong the system is against
hypothetical sybil attackers.

Some makers with high-valued fidelity bonds may choose to ask for a high coinjoin fee, so
for the strongest protection from sybil attacks make sure to set your maximum coinjoin fee
high enough (or if you think the sybil protection is too expensive then set the max fee
lower, as always its your choice as a taker in the market).

Takers will still choose makers equally (i.e. without taking into account fidelity bonds) with a
small probability. By default this probability is 12.5%, so approximately 1-in-8 makers. This can
be changed in the config file with the option `bondless_makers_allowance`.

The previous algorithm for choosing makers without regards to fidelity bonds can still be used by
passing the relevant CLI option when running a script (for example
`python3 sendpayment.py -R wallet.jmdat <amount> <address>`). As always use `--help` to get a full
list of options.


## How to create and use a fidelity bond as a yield-generator

You need to create a fidelity bond wallet and run the yield-generator script on it. In practice the
vast majority of wallets will contain just a single fidelity bond. If the wallet for some reason
has multiple fidelity bonds then the yield generator will automatically announce the most valuable
fidelity bond in its wallet. Fidelity bonds are only supported for native segwit wallets.

### Creating a JoinMarket wallet which supports creating a fidelity bond

When generating a JoinMarket wallet on the command line, supporting versions
will offer an option to make the wallet support creating a fidelity bond.

    (jmvenv) $ python3 wallet-tool.py generate
    Would you like to use a two-factor mnemonic recovery phrase? write 'n' if you don't know what this is (y/n): n
    Not using mnemonic extension
    Enter wallet file encryption passphrase: 
    Reenter wallet file encryption passphrase: 
    Input wallet file name (default: wallet.jmdat): testfidelity.jmdat
    Would you like this wallet to support fidelity bonds? write 'n' if you don't know what this is (y/n): y
    Write down this wallet recovery mnemonic

    use amateur twelve unfair weekend file canal frog cotton play renew illegal

    Generated wallet OK

As always, it is crucially important to write down the 12-word [seed phrase](https://en.bitcoin.it/wiki/Seed_phrase)
as a backup. It is also recommended to write down the name of the creating wallet
"JoinMarket" and that the fidelity bond option was enabled. Writing the wallet
creation date is also useful as it can help with rescanning.

#### Adding fidelity bond support to an existing wallet

On any **native segwit** wallet this can be done by using the `recover` method:

    (jmvenv) $ python3 wallet-tool.py recover

And then choosing `yes` to create a fidelity bond wallet.

#### Note on privacy

A Bitcoin transaction which creates a fidelity bond will be published to the entire world, so before
creating them make sure the coins are not linked to any of your privacy-relevant information.
Perhaps mix with JoinMarket. Also, use a sweep transaction which does not create a change output
when funding the timelocked address. Change addresses can also leak privacy information and the
best way to avoid that is to not create change outputs at all i.e. use only sweep transactions.

Once the timelocked addresses expire and become spendable, make sure you don't leak any information
then either, mix afterwards as well. If your timelocked address expires and you want to send the
coins to another timelocked address then you don't need to mix in between, because no
privacy-relevant information linked to you has been leaked.

This can all be done with `sendpayment.py` and coin control (i.e. freezing the UTXOs that you dont
want to spend).

### Obtaining a time-locked address

The `wallet-tool.py` script supports a new method `gettimelockaddress` used for
obtaining time-locked addresses. If bitcoins are sent to these addresses they will
be locked up until the timelock date passes. Only mixdepth zero can have a
fidelity bond in it.

This example creates an address which locks any coins sent to it until January 2025.

    (jmvenv) $ python3 wallet-tool.py testfidelity.jmdat gettimelockaddress 2025-1
    Enter wallet decryption passphrase: 
    path = m/84'/1'/0'/2/0:1748736000
    Coins sent to this address will be not be spendable until June 2025. Full date: 2025-06-01 00:00:00
    bcrt1qvcjcggpcw2rzk4sks94r3nxj5xhgkqm4p9h54c7mtr695se27efqqxnu0k


If coins are sent to these addresses they will appear in the usual `wallet-tool.py`
display:

    (jmvenv) $ python3 wallet-tool.py -m 0 testfidelity.jmdat
    Enter wallet decryption passphrase: 
    JM wallet
    mixdepth    0   fbonds-mpk-tpubDCv7SSisuV4AqNgRqHcXFAeCjV9Z5SPZgSVFjzydEZrS5Jg1uCkv4wGfMZc3wEaiC2hkEfbD753u4R6Shpgj8bR1kuKnEciB522kSpQ3j1v
    external addresses  m/84'/1'/0'/0   tpubDEdbDAFbNCXXN54M2qgzHBJYxkHK9hoeisyRsC2gC3WZuxziU5RkcJWgpw7nJqugPx26Ui9c2AqCy9gwZpgTtL1GW1TuPtKRX2SdrrjBY2W
    m/84'/1'/0'/0/0         bcrt1qwmj5yht2xxr3juxczt453uqjltc3xdyklkjnjt    2.00000000  used
    m/84'/1'/0'/0/1         bcrt1q99nzc6s8fh37rjju8gfws4dcfhrpcfz0jst829    0.00000000  new
    m/84'/1'/0'/0/2         bcrt1ql3fxzq2ueyhm8kwy7du6nsv7fgpvujupd2emms    0.00000000  new
    m/84'/1'/0'/0/3         bcrt1qgxr5mh8v4dj8kuqv98ckjzqdmzd4xjcn539nc6    0.00000000  new
    m/84'/1'/0'/0/4         bcrt1qhyhwzkh60p26pk2v008ejqhcl8g70h5vuw2fn6    0.00000000  new
    m/84'/1'/0'/0/5         bcrt1q9xuzrqql028wpj3933zyny6geg2u75rhaygv6z    0.00000000  new
    m/84'/1'/0'/0/6         bcrt1q8w7ewzl4q8mwxx7erf7pjq36z5g088jxzqjdcn    0.00000000  new
    Balance:    2.00000000
    internal addresses  m/84'/1'/0'/1
    Balance:    0.00000000
    internal addresses  m/84'/1'/0'/2   tpubDEdbDAFbNCXXSFfUKS5QAaxN9toxv8pFSn3TxRdhEij46wj88RCch7ZBA2fgqsocD7MZqowVAdm6LyYumKuKZbzT4V2CfudwDicrMnqqbjC
    m/84'/1'/0'/2/0:1748736000  bcrt1qvcjcggpcw2rzk4sks94r3nxj5xhgkqm4p9h54c7mtr695se27efqqxnu0k    2.00000000  2025-06-01 [LOCKED]
    Balance:    2.00000000
    internal addresses  m/84'/1'/0'/3   tpubDEdbDAFbNCXXUpShWMdtPMDcAogMyZJVAzMMn3wM9rC364sdeUuFMS7ZmdjoMbkf14jeK56uy95UBR2SA9AFFeoVv4j4CqMeaq1tcuBVkZe
    Balance:    0.00000000
    Balance for mixdepth 0: 4.00000000

#### Spending time-locked coins

Once the time-lock of an address expires the coins can be spent with JoinMarket.

Coins living on time-locked addresses are automatically frozen with
JoinMarket's coin control feature, so before spending you need to unfreeze the
coins using `python3 wallet-tool.py <walletname> -m 0 freeze`.

Once unfrozen and untimelocked the coins can be spent with a non-coinjoin transaction with
`sendpayment.py -N 0`. NB You cannot export the private keys (which is always disadvised, anyway)
of timelocked addresses to any other wallets, as they use custom scripts. You must spend them from
JoinMarket itself.

### What amount of bitcoins to lock up and for how long?

A fidelity bond is valuable as soon as the transaction creating it becomes confirmed. The
simplified formula for a fidelity bond's value is:

    bond_value = (locked_coins * (exp(interest_rate * locktime) - 1))^2

A few important things to notice:
* The bond value goes as the _square_ of sacrificed value. For example if your sacrificed value is
5 BTC then the fidelity bond value is 25 (because 5 x 5 = 25). If instead you sacrificed 6 BTC the
value is 36 (because 6 x 6 = 36). The point of this is to create an incentive for makers to lump
all their coins into just one bot rather than spreading it over many bots. It makes a sybil attack
much more expensive.
* The longer you lock for the greater the value. The value increases as the `interest_rate`, which
is configurable in the config file with the option `interest_rate`. By default it is 1.5% per
annum and because of tyranny-of-the-default takers are unlikely to change it. This value is probably
not too far from the "real" interest rate, and the system still works fine even if the real rate
is something like 3% or 0.1%.
* The above formula would suggest that if you lock 3 BTC for 10000 years you get a fidelity
bond worth `1.7481837557171304e+131` (17 followed by 130 zeros). This does not happen because the
sacrificed value is capped at the value of the burned coins. So in this example the fidelity bond
value would be just 9 (equal to 3x3 or 3 squared). This feature is not included in the above
simplified equation.
* After the locktime expires and the coins are free to move, the fidelity bond will continue to be
valuable, but its value will exponentially drop following the interest rate. So it would be good
for you as a yield generator to create a transaction with the UTXO spending it to another
time-locked address, but it's not a huge rush (specifically, there's likely no need to pay massive
miner fees, you can probably wait until fees are low).

The full details on valuing a time-locked fidelity bond are [found in the relevant section of the
"Financial mathematics of fidelity bonds" document](https://gist.github.com/chris-belcher/87ebbcbb639686057a389acb9ab3e25b#time-locked-fidelity-bonds).

At any time you can use the orderbook watcher script to see your own fidelity bond value.

Consider also the [warning on the bitcoin wiki page on timelocks](https://en.bitcoin.it/wiki/Timelock#Far-future_locks).

I would recommend locking as many bitcoins as you are comfortable with for a period of between 6
months and 2 years. Perhaps at the very start lock for only 1 month or 2 months(?) It's a
marketplace and the rules are known to all, so ultimately you'll have to make your own decision.

### Can my yield-generator use multiple timelocked addresses or UTXO?

Alternatively: Can I add more bitcoins to a fidelity bond that already exists?

No. Creating a new transaction which sends more bitcoins to a timelocked address will not add to
the existing fidelity bond, but instead create a new one. The two fidelity bonds will not be
combined. A yield-generator only announces a single fidelity bond transaction UTXO, and it choses
the most valuable one.

As a yield-generator, you are generally stuck with the fidelity bond you create until it expires.
You can still create a new fidelity bond and use that instead, but the old one will be unused. If you want
to increase the value of a fidelity bond the best way to do that is to wait until it expires and
then spend from the timelocked address combining with extra UTXOs you want to add, into a new
timelocked address. You can use JoinMarket's coin control feature to control this.

This is one reason why a yield-generator who creates a fidelity bond for the first time should only
lock up coins for a relatively short time, so that they can try out the whole thing, and don't
have to wait too long before they add more coins.

### Creating watch-only fidelity bond wallets

#### Note: Fidelity bond in cold storage cannot be advertised to takers right now. You can create watch-only fidelity bond wallets but cant advertise them yet. This feature is pretty easy to add though, and can be done without changing the JoinMarket protocol.

Fidelity bonds can be held on an offline computer in
[cold storage](https://en.bitcoin.it/wiki/Cold_storage). To do this we create
a watch-only fidelity bond wallet.

When fidelity bonds are displayed in `wallet-tool.py`, their master public key
is highlighted with a prefix `fbonds-mpk-`.

This master public key can be used to create a watch-only wallet using
`wallet-tool.py`.

    $ python3 wallet-tool.py createwatchonly fbonds-mpk-tpubDDCbCPdf5wJVGYWB4mZr3E3Lys4NBcEKysrrUrLfhG6sekmrvs6KZNe4i5p5z3FyfwRmKMqB9NWEcEUiTS4LwqfrKPQzhKj6aLihu2EejaU
    Input wallet file name (default: watchonly.jmdat): watchfidelity.jmdat
    Enter wallet file encryption passphrase: 
    Reenter wallet file encryption passphrase: 
    Done

Then the wallet can be displayed like a regular wallet, although only the zeroth
mixdepth will be shown.

    $ python3 wallet-tool.py watchfidelity.jmdat
    User data location: .
    Enter wallet decryption passphrase: 
    JM wallet
    mixdepth    0   fbonds-mpk-tpubDCv7SSisuV4AqNgRqHcXFAeCjV9Z5SPZgSVFjzydEZrS5Jg1uCkv4wGfMZc3wEaiC2hkEfbD753u4R6Shpgj8bR1kuKnEciB522kSpQ3j1v
    external addresses  m/84'/1'/0'/0   tpubDEdbDAFbNCXXN54M2qgzHBJYxkHK9hoeisyRsC2gC3WZuxziU5RkcJWgpw7nJqugPx26Ui9c2AqCy9gwZpgTtL1GW1TuPtKRX2SdrrjBY2W
    m/84'/1'/0'/0/0         bcrt1qwmj5yht2xxr3juxczt453uqjltc3xdyklkjnjt    2.00000000  used
    m/84'/1'/0'/0/1         bcrt1q99nzc6s8fh37rjju8gfws4dcfhrpcfz0jst829    0.00000000  new
    m/84'/1'/0'/0/2         bcrt1ql3fxzq2ueyhm8kwy7du6nsv7fgpvujupd2emms    0.00000000  new
    m/84'/1'/0'/0/3         bcrt1qgxr5mh8v4dj8kuqv98ckjzqdmzd4xjcn539nc6    0.00000000  new
    m/84'/1'/0'/0/4         bcrt1qhyhwzkh60p26pk2v008ejqhcl8g70h5vuw2fn6    0.00000000  new
    m/84'/1'/0'/0/5         bcrt1q9xuzrqql028wpj3933zyny6geg2u75rhaygv6z    0.00000000  new
    m/84'/1'/0'/0/6         bcrt1q8w7ewzl4q8mwxx7erf7pjq36z5g088jxzqjdcn    0.00000000  new
    Balance:    2.00000000
    internal addresses  m/84'/1'/0'/1
    Balance:    0.00000000
    internal addresses  m/84'/1'/0'/2   tpubDEdbDAFbNCXXSFfUKS5QAaxN9toxv8pFSn3TxRdhEij46wj88RCch7ZBA2fgqsocD7MZqowVAdm6LyYumKuKZbzT4V2CfudwDicrMnqqbjC
    m/84'/1'/0'/2/0:1748736000  bcrt1qvcjcggpcw2rzk4sks94r3nxj5xhgkqm4p9h54c7mtr695se27efqqxnu0k    2.00000000  2025-06-01 [LOCKED]
    Balance:    2.00000000
    internal addresses  m/84'/1'/0'/3   tpubDEdbDAFbNCXXUpShWMdtPMDcAogMyZJVAzMMn3wM9rC364sdeUuFMS7ZmdjoMbkf14jeK56uy95UBR2SA9AFFeoVv4j4CqMeaq1tcuBVkZe
    Balance:    0.00000000
    Balance for mixdepth 0: 4.00000000

### BIP32 Paths

Fidelity bond wallets extend the BIP32 path format to include the locktime
values. In this example we've got `m/49'/1'/0'/2/0:1583020800` where the
number after the colon is the locktime value in Unix time.

This path can be passed to certain wallet methods like `dumpprivkey`.

    $ python3 wallet-tool.py -H "m/49'/1'/0'/2/0:1583020800" testfidelity.jmdat dumpprivkey
    Enter wallet decryption passphrase: 
    cNEuE5ypNTxVFCyC5iH7u5AQTrddamcUHRPNweiLvmHUWd6XXDkz

### Burning coins

#### Note: There is no point using this feature. Fidelity bonds in JoinMarket cannot be created by burning coins right now. This feature is here only for historical reasons. 

Coins can be burned with a special method of the `sendpayment.py` script. Set
the destination to be `BURN`. Transactions which burn coins must only have one
input and one output, so use coin control to freeze all coins in the zeroth
mixdepth except one.

    $ python3 sendpayment.py -N 0 testfidelity3.jmdat 0 BURN
    User data location: .
    2020-04-07 20:45:25,658 [INFO]  Using this min relay fee as tx fee floor: 1000 sat/vkB (1.0 sat/vB)
    Enter wallet decryption passphrase: 
    2020-04-07 20:46:50,449 [INFO]  Estimated miner/tx fees for this coinjoin amount: 0.0%
    2020-04-07 20:46:50,452 [INFO]  Using this min relay fee as tx fee floor: 1000 sat/vkB (1.0 sat/vB)
    2020-04-07 20:46:50,452 [INFO]  Using a fee of : 0.00000200 BTC (200 sat).
    2020-04-07 20:46:50,454 [INFO]  Got signed transaction:

    2020-04-07 20:46:50,455 [INFO]  {'ins': [{'outpoint': {'hash': '61d69b4e7abe0ef8a5a9cbabb05463259c3b497a142130a56f81a9259f048cb0',
                           'index': 0},
              'script': '160014295beb4eba9b35896683d5b5ff455ee2c646054c',
              'sequence': 4294967294,
              'txinwitness': ['3045022100939de908e30015c6b22d2c0f25153e395268466ce44eeeb4ec03a8920440e87b0220155d1c43dedb3fc2654205541bb2821dd5211180e2d7f93d67301470652830d401',
                              '03ec0f8b267f99ff5259195ce63813d58f38ffbaada894ce06af0c0303c74bbf82']}],
     'locktime': 1361,
     'outs': [{'script': '6a147631c805d8ad9239677b8d7530353fda3fec07ca',
               'value': 11999800}],
     'version': 2}
    2020-04-07 20:46:50,455 [INFO]  In serialized form (for copy-paste):
    2020-04-07 20:46:50,455 [INFO]  02000000000101b08c049f25a9816fa53021147a493b9c256354b0abcba9a5f80ebe7a4e9bd6610000000017160014295beb4eba9b35896683d5b5ff455ee2c646054cfeffffff01381ab70000000000166a147631c805d8ad9239677b8d7530353fda3fec07ca02483045022100939de908e30015c6b22d2c0f25153e395268466ce44eeeb4ec03a8920440e87b0220155d1c43dedb3fc2654205541bb2821dd5211180e2d7f93d67301470652830d4012103ec0f8b267f99ff5259195ce63813d58f38ffbaada894ce06af0c0303c74bbf8251050000
    2020-04-07 20:46:50,456 [INFO]  Sends: 0.11999800 BTC (11999800 sat) to destination: BURNER OUTPUT embedding pubkey at m/49'/1'/0'/3/0

    WARNING: This transaction if broadcasted will PERMANENTLY DESTROY your bitcoins

    Would you like to push to the network? (y/n):y
    2020-04-07 20:47:52,047 [DEBUG]  rpc: sendrawtransaction ['02000000000101b08c049f25a9816fa53021147a493b9c256354b0abcba9a5f80ebe7a4e9bd6610000000017160014295beb4eba9b35896683d5b5ff455ee2c646054cfeffffff01381ab70000000000166a147631c805d8ad9239677b8d7530353fda3fec07ca02483045022100939de908e30015c6b22d2c0f25153e395268466ce44eeeb4ec03a8920440e87b0220155d1c43dedb3fc2654205541bb2821dd5211180e2d7f93d67301470652830d4012103ec0f8b267f99ff5259195ce63813d58f38ffbaada894ce06af0c0303c74bbf8251050000']
    2020-04-07 20:47:52,049 [WARNING]  Connection had broken pipe, attempting reconnect.
    2020-04-07 20:47:52,440 [INFO]  Transaction sent: 656bb4538f14f2cc874043915907b6c9c46a807ef9818bde771d07630d54b0f7
    done

Embedded in the `OP_RETURN` output is the hash of a pubkey from the wallet.

Now `OP_RETURN` outputs are not addresses, and because of technical reasons the
first time they are synchronized the flag `--recoversync` must be used. When
this is done the burn output will appear in the `wallet-tool.py` display.
`--recoversync` only needs to be used once, and after that the burner output is
saved in the `wallet.jmdat` file which can be accesses by all future
synchronizations.

    $ python3 wallet-tool.py --datadir=. --recoversync testfidelity2.jmdat
    Enter wallet decryption passphrase: 
    2020-04-07 23:09:54,644 [INFO]  Found a burner transaction txid=656bb4538f14f2cc874043915907b6c9c46a807ef9818bde771d07630d54b0f7 path = m/49'/1'/0'/3/0
    2020-04-07 23:09:54,769 [WARNING]  Merkle branch not available, use wallet-tool `addtxoutproof`
    2020-04-07 23:09:55,420 [INFO]  Found a burner transaction txid=656bb4538f14f2cc874043915907b6c9c46a807ef9818bde771d07630d54b0f7 path = m/49'/1'/0'/3/0
    2020-04-07 23:09:55,422 [WARNING]  Merkle branch not available, use wallet-tool `addtxoutproof`
    JM wallet
    mixdepth    0   fbonds-mpk-tpubDDCXgSpdxuVbXgzRYBggFeMRNeV9eH24jJuQNunyqwYtDFiB7ZS63LhXwHkf7o9ZcZW4qUz7uvD6yk4BkkF3bBPmJRPv7RBTEA5hHwEdV2f
    external addresses  m/49'/1'/0'/0   tpubDEJGorVywRb6LoLQbaqWZh2gYwpdZqViCNZ2ejB5kpBuUp16LHpK6ESFaJLixidtbmmjcDwVZ4QjnAbKmypfuGaEk3ifgonPv4vsugqgp9G
    m/49'/1'/0'/0/2         2MviB2FfLKZjFb3W2dJ8kXcQBj3jqMJg7TL 0.00000000  new
    m/49'/1'/0'/0/3         2MtsAQhE2u9VGV3aZ7XM4PzwWGHXr4PAhqP 0.00000000  new
    m/49'/1'/0'/0/4         2N3iXNjS4vkTXzy5Jidnovc6FJeNQJx5Fnt 0.00000000  new
    m/49'/1'/0'/0/5         2MtT4XAjwQQ7PBbrTxv7qcQMMmz4Rs5XrE3 0.00000000  new
    m/49'/1'/0'/0/6         2NEuG23BQESuZTqSDtab9zYsd1Jb4KfMULB 0.00000000  new
    m/49'/1'/0'/0/7         2N6NGJRX6KYQWtYWK8iHFuJNpZRs8NbUAC9 0.00000000  new
    Balance:    0.00000000
    internal addresses  m/49'/1'/0'/1
    Balance:    0.00000000
    internal addresses  m/49'/1'/0'/2   tpubDEJGorVywRb6T34X7ZAEz9hQYn6CCEhrcFa8kA2mqNau2DvoggZP2QTtXRe8t9NSfMkx3ye8QDzqCE9gEqso6fw5ALk5xycWLFwTRLSqSUV
    Balance:    0.00000000
    internal addresses  m/49'/1'/0'/3   tpubDEJGorVywRb6V5em9Q7LFJ9eLEAEZmZxUdDmkknrKNUs7vKcCWPKwP8YPjuxFCCXk2F1wJnubNbmgbtWed5yiE3D1qxzLonVuXT6QEZPaof
    m/49'/1'/0'/3/0         BURN-7631c805d8ad9239677b8d7530353fda3fec07ca   0.11999800  656bb4538f14f2cc874043915907b6c9c46a807ef9818bde771d07630d54b0f7 [NO MERKLE PROOF]
    Balance:    0.11999800
    Balance for mixdepth 0: 0.11999800

#### Adding the merkle proof of a burn transaction if missing

In order to prove a burn output exists, a merkle proof is needed. If the Core
node is pruned and the block deleted then JoinMarket will not be able to obtain
the merkle proof (as in the above example). In this case the proof can be
added separately.

Any other unpruned Core node can trustlessly obtain the proof and give it to
the user with the RPC call `gettxoutproof`.

First obtain the merkle proof:

    $ bitcoin-cli gettxoutproof "[\"656bb4538f14f2cc874043915907b6c9c46a807ef9818bde771d07630d54b0f7\"]" 4cce28f4eb1ea1762ec4ceb90529b3ab28c0423ac630c6292319e2b2712daada
    0000002056e4050f54084a1d6e6944b209cce76ebe2da4b37f3aa47ab6c612831d3220471015e80d3050cf0ee05b216036030fe3d4906221196943a30e828741ad4cfaeb05d98c5effff7f20010000000200000002a5910e5cf4e6cb6d55e1e2ca979987772a482e8a8f30b7a6cab8c5671f5c161df7b0540d63071d77de8b81f97e806ac4c9b6075991434087ccf2148f53b46b650105

Then add it to the JoinMarket wallet:

    $ python3 wallet-tool.py -H "m/49'/1'/0'/3/0" testfidelity2.jmdat addtxoutproof 0000002056e4050f54084a1d6e6944b209cce76ebe2da4b37f3aa47ab6c612831d3220471015e80d3050cf0ee05b216036030fe3d4906221196943a30e828741ad4cfaeb05d98c5effff7f20010000000200000002a5910e5cf4e6cb6d55e1e2ca979987772a482e8a8f30b7a6cab8c5671f5c161df7b0540d63071d77de8b81f97e806ac4c9b6075991434087ccf2148f53b46b650105
    Enter wallet decryption passphrase: 
    Done

The `-H` flag must point to the path containing the burn output.

Then synchronizing the wallet won't output the no-merkle-proof warning.

