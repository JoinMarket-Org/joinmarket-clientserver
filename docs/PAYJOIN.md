### PayJoin (aka P2EP) user guide.

(You've installed using the `install.sh` as per instructions in the README before
reading this).

This document does **not** discuss why PayJoin is interesting or the general concept.
For that, see [this](https://joinmarket.me/blog/blog/payjoin/) post.

Some instructions here will be redundant with the introductory [usage guide](USAGE.md);
this guide is aimed at users who have not/ will not use Joinmarket for ordinary coinjoins.
So just skip redundant info if you already know it.

### Preparatory step: configuring for Bitcoin Core.

Joinmarket currently requires a Bitcoin Core full node, although it can be pruned.

First thing to do: in `scripts/`, run:

    python wallet-tool.py generate

This *should* quit with an error, because the rpc is not configured. Open the newly created file `joinmarket.cfg`,
and edit:

    [BLOCKCHAIN]
    rpc_user = yourusername-as-in-bitcoin.conf
    rpc_password = yourpassword-as-in-bitcoin.conf
    rpc_host = localhost #default usually correct 
    rpc_port = 8332 # default for mainnet

Note, you can also use a cookie file by setting, in this section, a variable `rpc_cookie_file` to the location of the file,
as an alternative to using user/password.

If you use Bitcoin Core's multiwallet feature, you can edit the value of `rpc_wallet_file` to your chosen wallet file.

Then retry the same `generate` command; it should now not error - continue the generate process as per steps below.

However, if you still get rpc connection errors, make sure you can connect to your Core node using the command line first.

### Before I put funds in; how do I spend them/sweep them out?

Good question! Whichever Joinmarket wallet you set up, you can always make a normal
(non-coinjoin, non-PayJoin, nothing clever - just a normal payment) using the syntax:

```
python sendpayment.py -N0 -m <mixdepth> mywalletname.jmdat amount address
```

Amount can be specified as both bitcoins (if decimal value or has "btc" suffix) or satoshis (if integer value or has "sat" suffix). So, 0.1 BTC can be specified as 0.1, 0.1btc, 10000000 or 10000000sat.
Also very important: to empty an account or *mixdepth* (more on this below),
set the amount to 0. You will be prompted with the destination and amount before actually pushing the transaction
to the network, as a sanity check. It looks like this:

```
2019-01-19 18:20:08,509 [INFO]  Using a fee of : 0.00001672 BTC (1672 sat).
2019-01-19 18:20:08,510 [INFO]  Using a change value of: 1.89998328 BTC (189998328 sat).
2019-01-19 18:20:08,511 [INFO]  Got signed transaction:

2019-01-19 18:20:08,511 [INFO]  {'ins': [{'outpoint': {'hash': '0a00b5a40f4cd587b3158fbf37c75e1824df25b8c8a59e3760a6d3e4850e70e3',
                       'index': 0},
          'script': '1600146cac63b385d6e45acce4d814d9a5d4c36d7515a8',
          'sequence': 4294967295,
          'txinwitness': ['3045022100d9fe2096c689e882c560c3d5b7adf633b252c2ff8fed3fd81dd5523556ff404302204efdcc947899c7f330a321d5a7a4b56aec457ec5d6dfce72c93351bc65d1cb6c01',
                          '03f58d6a2f317f829b3bf21a3ba79887013597853e45d656e43222930c5a2854f1']}],
 'locktime': 0,
 'outs': [{'script': 'a9140b48ac588e74b7dc02755459dbd56ef39a55f06687',
           'value': 10000000},
          {'script': 'a91477967d4582ef80417943dc152ab36858de02dedf87',
           'value': 189998328}],
 'version': 1}
2019-01-19 18:20:08,511 [INFO]  In serialized form (for copy-paste):
2019-01-19 18:20:08,511 [INFO]  01000000000101e3700e85e4d3a660379ea5c8b825df24185ec737bf8f15b387d54c0fa4b5000a00000000171600146cac63b385d6e45acce4d814d9a5d4c36d7515a8ffffffff02809698000000000017a9140b48ac588e74b7dc02755459dbd56ef39a55f06687f824530b0000000017a91477967d4582ef80417943dc152ab36858de02dedf8702483045022100d9fe2096c689e882c560c3d5b7adf633b252c2ff8fed3fd81dd5523556ff404302204efdcc947899c7f330a321d5a7a4b56aec457ec5d6dfce72c93351bc65d1cb6c012103f58d6a2f317f829b3bf21a3ba79887013597853e45d656e43222930c5a2854f100000000
2019-01-19 18:20:08,512 [INFO]  Sends: 0.10000000 BTC (10000000 sat) to address: 2MtGtUpRFVYcQSYgjr6XDHo9QKhjsb3GRye
Would you like to push to the network? (y/n):
```

This means that if you only want to do PayJoins and normal payments, and never coinjoins,
you can do so and just use the above to move funds out of the wallet when it's time.

(Extra note: you can also use the `-p` option to `wallet-tool.py` (see the help for that script)
to get private keys if that's ever needed (never do this except in emergency cases). You can also
use the mnemonic phrase in some other wallets, e.g. Electrum.)

So now we know that, let's continue doing the `generate` command to make a new wallet ... :

### Make and fund the wallet

Continue/complete the wallet generation with the above (`generate`) method.

(But wait again! Before you finish: want a bech32 wallet? you probably don't,
but read [this](#what-if-i-wanted-bech32-native-segwit-addresses) if you do.)

The wallet you create is (if not bech32) BIP49 by default, using BIP39 12 word seed,
mnemonic extension optional (simplest to leave it out if you're not sure).

Once the `generate` method run has completed, successfully, you need to look at the wallet contents. Use
the `display` method which is the default:

```
python wallet-tool.py wallet-name-you-chose.dat [display]
```

("display" is optional because default; use `python wallet-tool.py -h` to see all possible methods).

Below is [an example](#sample-testnet-wallet-display-output) of what the wallet looks like (although
yours will be mainnet, so the addresses will start with '3' not '2').

Joinmarket by default uses *5* accounts, not only 1 as some other wallets (e.g. Electrum), this is to help
with coin isolation. Try to move coins from one account to another *only* via coinjoins; or, you can just
use one or two accounts (called **mixdepths** in Joinmarket parlance) as if they were just one, understanding
that if you don't bother to do anything special, the coins in those two mixdepths are linked.

**Fund** the wallet by choosing one or more addresses in the *external* section of the first account (called
"Mixdepth 0" here). When you fund, fund to the external addresses. The internals will be used for change.

(The new standard (BIP49) *should* be compatible with TREZOR, Ledger, Electrum, Samourai and some others,
including the 12 word seed, although consider privacy concerns when sending addresses to remote servers!).

### Doing a PayJoin payment.

(At the end of this file are full terminal outputs from a regtest run of the process,
you can read it after this to see that it makes sense; there's also a video
[here](https://joinmarket.me/blog/blog/payjoin-basic-demo) of the process running live with mainnet coins).

* Receiver needs to start: run (still in scripts/ directory):

```
python receive-payjoin.py -m 1 receiver-wallet-name.jmdat amount
```

Note : `-m 1` is choosing the *mixdepth* (see above) to *spend* coins from: in a payjoin,
the receiver also spends some coins, he just gets that amount back, as well as his payment.

If you funded into mixdepth 0 at the start, and you only have coins there, you must choose 0
here (which is the default). How much do you need? The code is fairly lenient and it doesn't
matter too much. But it needs to be more than zero!

The receiver will be prompted to read/note the receiving address, amount and "ephemeral nick", and then
the script will just wait (indefinitely). It'll look something like this:

```
2019-01-16 16:11:40,018 [INFO]  Your receiving address is: 2NA65YN6eXf3LiciBb1dEdS6ovaZ8HVBcHS
2019-01-16 16:11:40,018 [INFO]  You will receive amount: 27000000 satoshis.
2019-01-16 16:11:40,018 [INFO]  The sender also needs to know your ephemeral nickname: J5AFezpsuV95CBCH
2019-01-16 16:11:40,018 [INFO]  This information has been stored in a file payjoin.txt; send it to your counterparty when you are ready.
```

The "ephemeral nick" starts with J, version (5 currently), then a short base58 string. It's how the sender will find you in the
"joinmarket trading pit" (multiple IRC servers are used for this currently).

* Receiver sends data to sender (amount, address, ephemeral nick).

This data is stored in the file payjoin.txt but not currently using any encoding (that's a TODO).

* Sender starts up the sendpayment script:

```
python sendpayment.py -m 1 sender-wallet.jmdat 27000000 2NA65YN6eXf3LiciBb1dEdS6ovaZ8HVBcHS -T J5AFezpsuV95CBCH
```

Notice that the user has specified the three pieces of data given; using the `-T` flags this as a PayJoin; if you don't do this you will be
doing a Joinmarket coinjoin accidentally! (which wouldn't be the end of the world, the receiver would still get the money!).

As before -m 1 tells the wallet which mixdepth to source coins to spend from; it obviously needs to have at least the given amount
(in this case, 27 million satoshis or 0.27 btc).

* The two sides communicate

This takes generally only a couple of seconds, not including a relatively slow startup (30s-60s or so depending on configuration),
during which time the sender acts similarly to any other Joinmarket participant (and so does the receiver, likewise), to have
a slightly better "blend in with the crowd" effect.

Once the transaction is broadcast, you'll see a message to that effect and the script will shutdown. You can check the txid
on your favourite block explorer.

* What if something goes wrong and the payment fails to go through?

First, if the sender succeeds in doing the first step, the receiver will have a non-coinjoin ordinary payment transaction
to fall back on. It'll look like this:

```
2019-01-16 16:34:55,168 [INFO]  Network transaction fee is: 1672 satoshis.
2019-01-16 16:34:55,175 [INFO]  We'll use this serialized transaction to broadcast if your counterparty fails to broadcast the payjoin version:
2019-01-16 16:34:55,177 [INFO]  0200000000010152da645b5a2ec3a166ad8a933b1442fa38fc119faf7659d72033ba863fdd8d470000000017160014297b55001daa905a3552137ef19755cf4eae7babfeffffff02b8be4f0a0000000017a914e3cb2bf72ccd4412035f9668e07e17b6c9ebd58d87c0fc9b010000000017a914b8bf57f3bae00d23f9a60c9a6e4d4c7182ec87cc8702483045022100e3605548f5e07ebd14a0700dc3e54e7c8ae90ce0057a3fdc80b5fd37636b44a002202fd7942104fb344b80b8fd91faf0394a0f274f7a68fa462084b8ecf2fa245a65012102f823d62891d8bc8544d4369bb98c6fb8235a372d2c36196d40c448690b42754f42030000
2019-01-16 16:34:55,186 [INFO]  The proposed tx does not trigger UIH2, which means it is indistinguishable from a normal payment. This is the ideal case. Continuing..
....
```

If the final step fails and we don't get a PayJoin, the receiver can just use his favorite broadcast method (e.g.
`sendrawtransaction` in Bitcoin Core) to send the signed transaction above (02000...).

* Privacy and security controls

Just like Joinmarket, do note, that here the private information is communicated with **end-to-end encryption** - it's not like
the people/operators on the IRC servers are going to learn any information about your transaction.

Second, it's very recommended to use Tor connections to the messaging servers via their hidden services. See the
`[MESSAGING:serverN]` sections in the `joinmarket.cfg`. This keeps anyone from seeing your IP address origin.

This altogether means it's possible to have anonymity from your sender/receiver counterparty, if that's an issue.
You *do* still have to send them the payment information out of band, though. We could perhaps fold this in, although
it seems a bit tricky to do so without introducing a security issue.

An additional minor feature is that the receiver "fakes" being a Joinmarket maker, so his bot looks the same as the other
ones in the Joinmarket trading pit (at least, to a crude extent). And the sender fakes being a Joinmarket taker, too.

Also we try to make the PayJoin look as much as possible as an ordinary payment. For example:
 - we make the transaction version, locktime and sequence numbers look similar to those created by Core, Electrum.
 - we try to avoid "UIH2", meaning we avoid a situation where one input is larger than any output, since that would
   mean no other inputs are needed; wallet coin selection algorithms *usually* don't do that.
   
Security - since the receiver passively waits, what happens if a bad actor tries to connect to him? Nothing; an attacker
would fail to even start the process without knowing the payment amount and address, which the receiver is not broadcasting
around everywhere (especially not the amount and ephemeral nickname), and even if they knew that, the worst
they can do is learn at least 1 utxo of the receiver. The receiver won't pay attention to non-PayJoin messages, either.

### Controlling fees

**The fees are paid by the sender of funds; note that the fees are going to be a bit higher than a normal payment** (typically
about 2-3x higher); this may be changed to share the fee, in a future version. There are controls to make sure the fee
isn't *too* high.

In the joinmarket.cfg file, under `[POLICY]` section you should see a setting called `tx_fees`.
You can set this to any integer; if you set it to 1000 or less then it's treated as a "confirmation in N blocks target",
i.e. if you set it to 3 (the default), the fee is chosen from Bitcoin Core's estimator to target confirmation in 3 blocks.
So if you change it to e.g. 10, it will be cheaper but projected to get its first confirmation in 10 blocks on average.

If you set it to a number > 1000, though, it's a number of satoshis per kilobyte (technically, kilo-vbyte) that you want
to use. **Don't use less than about 1200 if you do this** - a typical figure might be 5000 or 10000, corresponding to
about 5-10 sats/byte, which nowadays is a reasonable fee. The exact amount is randomised by ~20% to avoid you inadvertently
watermarking all your transactions. So don't use < 1200 because then you might be using less than 1 sat/byte which is
difficult to relay on the Bitcoin network.

#### What if I wanted bech32 native segwit addresses?

You can do this, but bear in mind: PayJoin only gives its full effect if you and your receiver are using
the same kind of addresses; so do this only if you and your receiver(s)/sender(s) agree on it.

Also note: you *cannot* do Joinmarket coinjoins if you choose a bech32 wallet (this may change in future).

In the configuration file `joinmarket.cfg` (which was created in the preparatory step above), go to the
POLICY section and set:

```
[POLICY]
native = true
```

Note that this must be done *before* generating the wallet, as
the wallet internally, of course, stores which type of addresses it manages, and it can only be of two
types currently (ignoring legacy upgrades): bech32 or p2sh-segwit (starting with '3'), the latter being
the default (and the one used in Joinmarket itself).

Note that the bech32 style wallet is written to conform to [BIP84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki),
analogous to the BIP49 case for p2sh.

#### Sample testnet wallet display output

```
JM wallet
mixdepth	0	tpubDC4qk8DsyiFYY85uktoKaiR1srWLSNRxZ2A4MXYg5LHy9XHKSTcF2tNtFpGz4LzXPcDH1kNkiww7MwipNqNSps6HSyjPTqTB18J7C4jrFMi
external addresses	m/49'/1'/0'/0	tpubDFFCJfi4y6xPKquA6H6aP5EBZPupb6A9tJz8sErW8GN6D7D3s9MABPt1BczpQ3n8rBv7VLSVpu3ddvb7xEKMfNX2sMZ7XxiBD4J6kpfF7Ag
m/49'/1'/0'/0/0     	2NBT6npWKxBEG8fkDjSFLDZJ7fNda4kYnAx	2.00000000	deposit
m/49'/1'/0'/0/1     	2Mt7dBFikYwCQTDU129VTF9ahKWxeJjEUuF	0.00000000	new
m/49'/1'/0'/0/2     	2N94bte8xWojSaX6yq2th3R3mUhvKzZqDJ9	0.00000000	new
m/49'/1'/0'/0/3     	2MvSBTkCKwPHLdNPRXbovPXUM8oAfjUFPYc	0.00000000	new
m/49'/1'/0'/0/4     	2MzVn3Nc3RRyN7shiVajA225xCTcaGn1PRw	0.00000000	new
m/49'/1'/0'/0/5     	2MxJwv2dmkMupDuBLsEMa4HgG6GAieWHiXr	0.00000000	new
m/49'/1'/0'/0/6     	2MwhdkeAcnCkam1LdVBQJ7un8syyoYB1HVH	0.00000000	new
Balance:	2.00000000
internal addresses	m/49'/1'/0'/1	
Balance:	0.00000000
Balance for mixdepth 0:	2.00000000
mixdepth	1	tpubDC4qk8DsyiFYba4t8cSpadjoLYUdPwV5dAtBpzpPzgaDKPfSP42xNJq48QUKEVGHQRfFej6DCUjQqCKD8TtcqN932f27jmyjXaxVMpksos4
external addresses	m/49'/1'/1'/0	tpubDEnijtftQiJpVgezdRNyKVVWGr9xKV9RgPQWHYDHpQ5utdHF7Sqh7xMUyNHcpdeKcKdQ753hFbyccRZNEHTUkHLnDaVqoXRo9XkATPtHhCp
m/49'/1'/1'/0/0     	2NEsN45waxdkqjP5EnsP3K8YjMeZJh2RLx6	2.00000000	deposit
m/49'/1'/1'/0/1     	2Mzhewfg6fr5jR122txdTShmLi7rH9ZscTm	2.00000000	deposit
m/49'/1'/1'/0/2     	2N1vn44cv5m6PhRJMbZ1mR8dAJgHybnsT5u	2.00000000	deposit
m/49'/1'/1'/0/3     	2NFwBsHkQ8mxCJWRJhkxAY28Tj8YuUJio4t	0.00000000	new
m/49'/1'/1'/0/4     	2NA1YAa2VqHMSH9b2GYGBA8waUMxZTZwW5Z	0.00000000	new
m/49'/1'/1'/0/5     	2MvLLp4cnP8ZVuWWDZzRCLFM2YcTfo9ALec	0.00000000	new
m/49'/1'/1'/0/6     	2Mux3ZUHGmaMBiMsPDbQS56gRGGN26jMGzd	0.00000000	new
m/49'/1'/1'/0/7     	2N3MWFiSHyRY3QLZgb63Vfcp4BGSFs6Y3bV	0.00000000	new
m/49'/1'/1'/0/8     	2N3z5zKJPTfPc41esRRvMvjdKaSv6D6jqvY	0.00000000	new
Balance:	6.00000000
internal addresses	m/49'/1'/1'/1	
Balance:	0.00000000
Balance for mixdepth 1:	6.00000000
mixdepth	2	tpubDC4qk8DsyiFYdQBNNzo3vHq63Gag4eUJT29UaTVNHM89hJk6CshZ9WGemQNDh2LGDXCud8anAQ4UR7n7tSWiJtviR8WJuTB78ZbEHpFNcLH
external addresses	m/49'/1'/2'/0	tpubDEY4sVvs1TX82DftUUB51Agg4Ln7BksoRGESNWtrWTDntV2fCs5wNrqiPENcXBAEHtnaY9ZaK48PRFEw1GLhcTxdDNHUyuqDd2YyNYKoVAo
m/49'/1'/2'/0/0     	2NBSnSB3nVN4TA7EcNkhcRsmrdyXSQepDFE	0.00000000	new
m/49'/1'/2'/0/1     	2NFtrtpdvmCRXMy1fV8w1eLWpF8MC3nre7n	0.00000000	new
m/49'/1'/2'/0/2     	2NFHJvGLWU7KuNkbo8rzPwfGtCS5RtNDw7c	0.00000000	new
m/49'/1'/2'/0/3     	2NGJcmeScFnTSzZzSRNHiLL8zjYeA9ngx5A	0.00000000	new
m/49'/1'/2'/0/4     	2NBUAxKrNQtp49xYYHh9f6YHfo2FvYBP1NL	0.00000000	new
m/49'/1'/2'/0/5     	2MyQfzKyPTfYT4vTe2d3fyGvQMoGX6GAhcr	0.00000000	new
Balance:	0.00000000
internal addresses	m/49'/1'/2'/1	
Balance:	0.00000000
Balance for mixdepth 2:	0.00000000
mixdepth	3	tpubDC4qk8DsyiFYgXoNb3UmiaG2veSTdrLCxEBUsTEQnDgQLCaC8Yg1z1Bcwn4ZQivNhgBxHEWH7j8hbRx7rab2kYLy4r4PXxor4Ho3A5AJvVH
external addresses	m/49'/1'/3'/0	tpubDEnwog2atqaSLe9xVTTdqxY5ynysqeQPsXuaKrZ6HaYCJcFPY7LmhepmwFTJYTkqf1w5jgLQmoZvREyk9qiq4P2A2fSGTyj62WUE4VjXK76
m/49'/1'/3'/0/0     	2MtckYQLD6bJZiPXffW7m5rryMao7u4ktng	0.00000000	new
m/49'/1'/3'/0/1     	2N9KrH5Bi35ZH3DVUwD67eh8MtQD1LLhgCa	0.00000000	new
m/49'/1'/3'/0/2     	2N6zLabMeXTXfyzQttr6PBV2JdbZPrVd9i8	0.00000000	new
m/49'/1'/3'/0/3     	2MzYTWMjXcv4NBce5PKcDAceT7gMuYrGovc	0.00000000	new
m/49'/1'/3'/0/4     	2N6tYykyCZLtvP1RJZvgZ9a7c6xbQaqpE66	0.00000000	new
m/49'/1'/3'/0/5     	2N2o3eJ9h2BC5q3TzPVqhn9gmgWBjaL67Hu	0.00000000	new
Balance:	0.00000000
internal addresses	m/49'/1'/3'/1	
Balance:	0.00000000
Balance for mixdepth 3:	0.00000000
mixdepth	4	tpubDC4qk8DsyiFYj7GF4LV97c9f7Yff1mrwnxkpi5twGSLmesmPyM4xXBWsxMw9ZLFycVVC4TeeX1ESjNP4rVVrJEDVCm7C3UMvZH9vs6srsAi
external addresses	m/49'/1'/4'/0	tpubDFA3XKgf2ZiusZHr4we5utkrQ9toN5s7QGKndNMrdQFQfjQU6yiiMT65tmXFCPduSc7muLFegAi36pv4LCdRnhpRYp2QUpm1izyrboWSjzV
m/49'/1'/4'/0/0     	2N18HGRJyaaUwLQFTyfjqZoXGCV8Yv5rbwD	0.00000000	new
m/49'/1'/4'/0/1     	2Mt94Y4iguYLkBAhsXT5a1P8VMTQ4kxdZJD	0.00000000	new
m/49'/1'/4'/0/2     	2N5vYyG1gx8ht2JCKkuVqow3Qn51cHrwaxh	0.00000000	new
m/49'/1'/4'/0/3     	2N44ZtKYu21p1qN4DBoTCYZL2sms6YBeWVW	0.00000000	new
m/49'/1'/4'/0/4     	2NF9p2b2PfHvXiPmPP5JPq4CRxKn47LPZrW	0.00000000	new
m/49'/1'/4'/0/5     	2MwgfAvbPc4ASD84WdBYo2FM5bXBVG1rRG9	0.00000000	new
Balance:	0.00000000
internal addresses	m/49'/1'/4'/1	
Balance:	0.00000000
Balance for mixdepth 4:	0.00000000
Total balance:	8.00000000
```

#### Full sender-side log of a regtest run of PayJoin

(Note that the "Received offers from joinmarket pit" message is a privacy feature, we don't actually respond to any offers).

```
(jmvenv) me@here:~/jm/scripts$ python sendpayment.py -m1 b80d142a466dbf56f518a3a8c017ab85 27000000 2NA65YN6eXf3LiciBb1dEdS6ovaZ8HVBcHS -T J5AFezpsuV95CBCH
2019-01-16 16:34:44,877 [WARNING]  Cannot listen on port 27183, trying next port
2019-01-16 16:34:44,877 [WARNING]  Cannot listen on port 27184, trying next port
2019-01-16 16:34:44,877 [WARNING]  Cannot listen on port 27185, trying next port
2019-01-16 16:34:44,878 [WARNING]  Cannot listen on port 27186, trying next port
2019-01-16 16:34:44,878 [INFO]  Listening on port 27187
2019-01-16 16:34:47,495 [INFO]  Could not connect to *ALL* servers yet, waiting up to 60 more seconds.
2019-01-16 16:34:47,496 [INFO]  All IRC servers connected, starting execution.
2019-01-16 16:34:47,501 [INFO]  JM daemon setup complete
2019-01-16 16:34:52,508 [INFO]  INFO:Received offers from joinmarket pit
2019-01-16 16:34:52,531 [INFO]  total estimated amount spent = 27020000
2019-01-16 16:34:52,594 [INFO]  Makers responded with: ["J5AFezpsuV95CBCH"]
2019-01-16 16:34:52,600 [INFO]  Obtained proposed payjoin tx
{'ins': [{'outpoint': {'hash': '478ddd3f86ba3320d75976af9f11fc38fa42143b938aad66a1c32e5a5b64da52',
                       'index': 0},
          'script': '',
          'sequence': 4294967294}],
 'locktime': 834,
 'outs': [{'script': 'a914e3cb2bf72ccd4412035f9668e07e17b6c9ebd58d87',
           'value': 172998328},
          {'script': 'a914b8bf57f3bae00d23f9a60c9a6e4d4c7182ec87cc87',
           'value': 27000000}],
 'version': 2}
2019-01-16 16:34:52,602 [INFO]  INFO:Built tx proposal, sending to receiver.
2019-01-16 16:34:56,622 [INFO]  Obtained tx from receiver:
{'ins': [{'outpoint': {'hash': '478ddd3f86ba3320d75976af9f11fc38fa42143b938aad66a1c32e5a5b64da52',
                       'index': 0},
          'script': '',
          'sequence': 4294967294,
          'txinwitness': []},
         {'outpoint': {'hash': '5e19edacc10298e7761be7231db5fa44ad73903c3690c4b71b443355267d346a',
                       'index': 0},
          'script': '160014a5b07a64bff72b442c71761599e0b627c687661f',
          'sequence': 4294967294,
          'txinwitness': ['3044022077a811939910a935934f68ac8a70439bab665ce9ad4cd02e42289c3046d606e1022054ef241980733caa7c7c5b6bb1babf96caba83a9fb0a8e091d8358b1cb35fcdb01',
                          '02c7ceecf0783ecc7530e018397db434af63eda63765c79816f023699a22663926']}],
 'locktime': 834,
 'outs': [{'script': 'a914b8bf57f3bae00d23f9a60c9a6e4d4c7182ec87cc87',
           'value': 227000000},
          {'script': 'a914e3cb2bf72ccd4412035f9668e07e17b6c9ebd58d87',
           'value': 172997415}],
 'version': 2}
2019-01-16 16:34:56,630 [INFO]  INFO:Network transaction fee is: 2585 satoshis.
2019-01-16 16:34:56,641 [INFO]  txid = 1031780b31bd3b1cfdec44296fdb82e467284e93f871eb48d7d3e72df059f0ae
2019-01-16 16:34:56,661 [INFO]  Transaction broadcast OK.
2019-01-16 16:35:01,651 [INFO]  Transaction seen on network, shutting down.
2019-01-16 16:35:01,652 [INFO]  Txid was: 1031780b31bd3b1cfdec44296fdb82e467284e93f871eb48d7d3e72df059f0ae
```

#### Full receiver-side log of a regtest run of PayJoin

```
(jmvenv) me@here:~/jm/scripts$ python receive-payjoin.py -m1 84735f364c2cf4c8ddaa614315aeae14 27000000
2019-01-16 16:11:39,952 [INFO]  offerlist=[{'maxsize': 112412265, 'ordertype': 'swreloffer', 'cjfee': '0.00035792', 'oid': 0, 'minsize': 1095839, 'txfee': 493}]
2019-01-16 16:11:39,952 [INFO]  starting receive-payjoin
2019-01-16 16:11:40,011 [WARNING]  Cannot listen on port 27183, trying next port
2019-01-16 16:11:40,011 [WARNING]  Cannot listen on port 27184, trying next port
2019-01-16 16:11:40,011 [WARNING]  Cannot listen on port 27185, trying next port
2019-01-16 16:11:40,012 [INFO]  Listening on port 27186
2019-01-16 16:11:40,018 [INFO]  Your receiving address is: 2NA65YN6eXf3LiciBb1dEdS6ovaZ8HVBcHS
2019-01-16 16:11:40,018 [INFO]  You will receive amount: 27000000 satoshis.
2019-01-16 16:11:40,018 [INFO]  The sender also needs to know your ephemeral nickname: J5AFezpsuV95CBCH
2019-01-16 16:11:40,018 [INFO]  This information has been stored in a file payjoin.txt; send it to your counterparty when you are ready.
2019-01-16 16:35:00+0100 [-] Enter 'y' to wait for the payment:y
2019-01-16 16:34:32,449 [INFO]  Could not connect to *ALL* servers yet, waiting up to 60 more seconds.
2019-01-16 16:34:32,450 [INFO]  All IRC servers connected, starting execution.
2019-01-16 16:34:32,453 [INFO]  JM daemon setup complete

(note time gap here; just waiting)

2019-01-16 16:34:55,163 [INFO]  obtained tx proposal from sender:
{'ins': [{'outpoint': {'hash': '478ddd3f86ba3320d75976af9f11fc38fa42143b938aad66a1c32e5a5b64da52',
                       'index': 0},
          'script': '160014297b55001daa905a3552137ef19755cf4eae7bab',
          'sequence': 4294967294,
          'txinwitness': ['3045022100e3605548f5e07ebd14a0700dc3e54e7c8ae90ce0057a3fdc80b5fd37636b44a002202fd7942104fb344b80b8fd91faf0394a0f274f7a68fa462084b8ecf2fa245a6501',
                          '02f823d62891d8bc8544d4369bb98c6fb8235a372d2c36196d40c448690b42754f']}],
 'locktime': 834,
 'outs': [{'script': 'a914e3cb2bf72ccd4412035f9668e07e17b6c9ebd58d87',
           'value': 172998328},
          {'script': 'a914b8bf57f3bae00d23f9a60c9a6e4d4c7182ec87cc87',
           'value': 27000000}],
 'version': 2}
2019-01-16 16:34:55,165 [WARNING]  Connection had broken pipe, attempting reconnect.
2019-01-16 16:34:55,168 [INFO]  Network transaction fee is: 1672 satoshis.
2019-01-16 16:34:55,175 [INFO]  We'll use this serialized transaction to broadcast if your counterparty fails to broadcast the payjoin version:
2019-01-16 16:34:55,177 [INFO]  0200000000010152da645b5a2ec3a166ad8a933b1442fa38fc119faf7659d72033ba863fdd8d470000000017160014297b55001daa905a3552137ef19755cf4eae7babfeffffff02b8be4f0a0000000017a914e3cb2bf72ccd4412035f9668e07e17b6c9ebd58d87c0fc9b010000000017a914b8bf57f3bae00d23f9a60c9a6e4d4c7182ec87cc8702483045022100e3605548f5e07ebd14a0700dc3e54e7c8ae90ce0057a3fdc80b5fd37636b44a002202fd7942104fb344b80b8fd91faf0394a0f274f7a68fa462084b8ecf2fa245a65012102f823d62891d8bc8544d4369bb98c6fb8235a372d2c36196d40c448690b42754f42030000
2019-01-16 16:34:55,186 [INFO]  The proposed tx does not trigger UIH2, which means it is indistinguishable from a normal payment. This is the ideal case. Continuing..
2019-01-16 16:34:55,187 [INFO]  We selected inputs worth: 200000000
2019-01-16 16:34:55,195 [INFO]  We estimated a fee of: 2585
2019-01-16 16:34:55,196 [INFO]  We calculated a new change amount of: 172997415
2019-01-16 16:34:55,197 [INFO]  We calculated a new destination amount of: 227000000
2019-01-16 16:35:00,232 [INFO]  The transaction has been broadcast.
2019-01-16 16:35:00,232 [INFO]  Txid is: 1031780b31bd3b1cfdec44296fdb82e467284e93f871eb48d7d3e72df059f0ae
2019-01-16 16:35:00,233 [INFO]  Transaction in detail: {'ins': [{'outpoint': {'hash': '478ddd3f86ba3320d75976af9f11fc38fa42143b938aad66a1c32e5a5b64da52',
                       'index': 0},
          'script': '160014297b55001daa905a3552137ef19755cf4eae7bab',
          'sequence': 4294967294,
          'txinwitness': ['3045022100c1d579fb19f5b8710b407e3995657313d0b1c9fe1180b852834b2210ba19b5e30220464f034eef8d8975b4fe10db7edbf14fcfdc6d71ada3d2063d34fa5c04a38cb801',
                          '02f823d62891d8bc8544d4369bb98c6fb8235a372d2c36196d40c448690b42754f']},
         {'outpoint': {'hash': '5e19edacc10298e7761be7231db5fa44ad73903c3690c4b71b443355267d346a',
                       'index': 0},
          'script': '160014a5b07a64bff72b442c71761599e0b627c687661f',
          'sequence': 4294967294,
          'txinwitness': ['3044022077a811939910a935934f68ac8a70439bab665ce9ad4cd02e42289c3046d606e1022054ef241980733caa7c7c5b6bb1babf96caba83a9fb0a8e091d8358b1cb35fcdb01',
                          '02c7ceecf0783ecc7530e018397db434af63eda63765c79816f023699a22663926']}],
 'locktime': 834,
 'outs': [{'script': 'a914b8bf57f3bae00d23f9a60c9a6e4d4c7182ec87cc87',
           'value': 227000000},
          {'script': 'a914e3cb2bf72ccd4412035f9668e07e17b6c9ebd58d87',
           'value': 172997415}],
 'version': 2}
2019-01-16 16:35:00,234 [INFO]  shutting down.
```


