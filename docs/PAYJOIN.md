### PayJoin (aka P2EP) user guide.

(You've installed using the `install.sh` or similar as per instructions in the README before
reading this).

This document does **not** discuss why PayJoin is interesting or the general concept.
For that, see [this](https://joinmarket.me/blog/blog/payjoin/) post.

### Contents

1. [Preparatory step: configuring for Bitcoin Core](#preparatory)

2. [Before I put funds in; how do I spend them/sweep them out?](#before)

3. [Make and fund the wallet](#makefund)

4. [Doing a PayJoin payment](#doing)

   a. [Using BIP78 payjoins to pay a merchant](#bip78)

   b. [Using Joinmarket-wallet-to-Joinmarket-wallet payjoins](#jmtojm)

   c. [About fees](#fees)

5. [What if I wanted bech32 native segwit addresses?](#native)

6. [Receiving a BIP78 Payjoin payment](#receiving)

7. [Configuring Tor to setup a hidden service](#torconfig)

8. [Using JoinmarketQt to send and receive Payjoins](#using-qt)

7. [Sample testnet wallet display output](#sample)

Some instructions here will be redundant with the introductory [usage guide](USAGE.md); sections 1-3 are aimed at users who have not/ will not use Joinmarket for ordinary coinjoins.
So just skip those sections if you already know it.

<a name="preparatory" />

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

<a name="before" />

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

<a name="makefund" />

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

Below is [an example](#sample) of what the wallet looks like (although
yours will be mainnet, so the addresses will start with '3' not '2').

Joinmarket by default uses *5* accounts, not only 1 as some other wallets (e.g. Electrum), this is to help
with coin isolation. Try to move coins from one account to another *only* via coinjoins; or, you can just
use one or two accounts (called **mixdepths** in Joinmarket parlance) as if they were just one, understanding
that if you don't bother to do anything special, the coins in those two mixdepths are linked.

**Fund** the wallet by choosing one or more addresses in the *external* section of the first account (called
"Mixdepth 0" here). When you fund, fund to the external addresses. The internals will be used for change.

(The new standard (BIP49) *should* be compatible with TREZOR, Ledger, Electrum, Samourai and some others,
including the 12 word seed, although consider privacy concerns when sending addresses to remote servers!).

<a name="doing" />

### Doing a PayJoin payment.

This section gives details on how to make payments with Payjoin. You might prefer to start with the video linked [here](#using-qt) to see how this works if you are using JoinmarketQt rather than the command line.

<a name="bip78" />

#### Using BIP78 payjoins to pay a merchant.

The process here is to use the syntax of sendpayment.py:

```
(jmvenv)a$ python sendpayment.py -m 0 walletname.jmdat "bitcoin:bc1qxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx?amount=0.05933201&pj=https://some/url/payjoin"
```

Notes on this:
* Payjoins BIP78 style are done using the `sendpayment` script, or by entering the BIP21 URI into the "Recipient" field in JoinmarketQt.
* They are done using BIP21 URIs. These can be copy/pasted from a website (e.g. a btcpayserver invoice page), note that double quotes are required (on the command line) because the string contains special characters. Note also that you must see `pj=` in the URI, otherwise payjoin is not supported by that server.
* If the url in `pj=` is `****.onion` it means you must be using Tor, remember to have Tor running on your system and change the configuration (see below) for sock5 port if necessary. If you are running the Tor browser the port is 9150 instead of 9050.
* Don't forget to specify the mixdepth you are spending from with `-m 0`. The payment amount is of course in the URI, along with the address.
* Pay attention to address type; this point is complicated, but: some servers will not be able to match the address type of the sender, and so won't be able to construct sensible Payjoin transactions. In that case they may fallback to the non-Payjoin payment (which is not a disaster). If you want to do a Payjoin with a server that only supports bech32, you will have to create a new Joinmarket wallet, specifying `native=true` in the `POLICY` section of `joinmarket.cfg` before you generate the wallet.

Before you do such coinjoins, you may want to:
* regenerate `joinmarket.cfg`. First, rename your current `joinmarket.cfg` (in `~/.joinmarket` on Linux), then run a script once to have it regenerated from defaults. Then reapply your custom changes.
* once you have done this, you will see a new section:

```
[PAYJOIN]
# for the majority of situations, the defaults
# need not be altered - they will ensure you don't pay
# a significantly higher fee.
# MODIFICATION OF THESE SETTINGS IS DISADVISED.

# Payjoin protocol version; currently only '1' is supported.
payjoin_version = 1

# servers can change their destination address by default (0).
# if '1', they cannot. Note that servers can explicitly request
# that this is activated, in which case we respect that choice.
disable_output_substitution = 0

# "default" here indicates that we will allow the receiver to
# increase the fee we pay by:
# 1.2 * (our_fee_rate_per_vbyte * vsize_of_our_input_type)
# (see https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#span_idfeeoutputspanFee_output)
# (and 1.2 to give breathing room)
# which indicates we are allowing roughly one extra input's fee.
# If it is instead set to an integer, then that many satoshis are allowed.
# Additionally, note that we will also set the parameter additionafeeoutputindex
# to that of our change output, unless there is none in which case this is disabled.
max_additional_fee_contribution = default

# this is the minimum satoshis per vbyte we allow in the payjoin
# transaction; note it is decimal, not integer.
min_fee_rate = 1.1


# for payjoins to hidden service endpoints, the socks5 configuration:
onion_socks5_host = localhost
onion_socks5_port = 9050
# in some exceptional case the HS may be SSL configured,
# this feature is not yet implemented in code, but here for the
# future:
hidden_service_ssl = false
```

As the notes mention, you should probably find the defaults here are absolutely fine, and
modifying them probably isn't needed. But read the comments for what they are; the main point
is that you as a payer have control over how much additional fee you are prepared to pay to allow
the server to participate in a Payjoin transaction with you. By default we only allow them to
bump the fee enough to add one input to the transaction, and this should be fine in almost all cases.

<a name="jmtojm" />

#### Using Joinmarket-wallet-to-Joinmarket-wallet payjoins

This is now deprecated; if you still want to use it, use Joinmarket(-clientserver) version 0.7.0 or lower, and see the corresponding older version of this document.

<a name="fees" />

#### About fees

In the joinmarket.cfg file, under `[POLICY]` section you should see a setting called `tx_fees`.
You can set this to any integer; if you set it to 1000 or less then it's treated as a "confirmation in N blocks target",
i.e. if you set it to 3 (the default), the fee is chosen from Bitcoin Core's estimator to target confirmation in 3 blocks.
So if you change it to e.g. 10, it will be cheaper but projected to get its first confirmation in 10 blocks on average.

If you set it to a number > 1000, though, it's a number of satoshis per kilobyte (technically, kilo-vbyte) that you want
to use. **Don't use less than about 1200 if you do this** - a typical figure might be 5000 or 10000, corresponding to
about 5-10 sats/byte, which nowadays is a reasonable fee. The exact amount is randomised by ~20% to avoid you inadvertently
watermarking all your transactions. So don't use < 1200 because then you might be using less than 1 sat/byte which is
difficult to relay on the Bitcoin network.

BIP78 itself has various controls around fees - essentially it tries to let the receiver bump the fee but *only slightly* to account for the fact that the receiver is adding at least one more input and so increasing the size of the transaction, and also ensure that low fees do not accidentally fall too low (even, below the relay limit). Joinmarket's receiver will only add one input and never more, for now, and it looks like this is the tradeoff that most wallets will make. If you want to learn more investigate the `maxadditionalfeecontribution`, `additionalfeeoutputindex` and `minfeerate` parameters described in the BIP.

As a spender in the BIP78 protocol, you will usually see the following: a small reduction in the size of your change output as a result of the extra 1 input. Unless the payment is very small, this probably won't be significant.

<a name="native" />

#### What if I wanted bech32 native segwit addresses?

You can do this, but bear in mind: PayJoin only gives its full effect if you and your receiver are using the same kind of addresses; so do this only if you and your receiver(s)/sender(s) agree on it - most BIP78 receivers at least for now will only engage in the protocol if they can provide inputs of the same type as yours.

As was noted in the BIP78 section, it may be therefore that you *need* to do this (albeit that the worst that can happen is a fallback to non-payjoin payment, which isn't a disaster).

Also note: you *cannot* do Joinmarket coinjoins if you choose a bech32 wallet (this may change in future, see [this PR](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/656)).

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

<a name="receiving" />

#### Receiving payments using BIP78 Payjoin

Joinmarket allows you to receive payments from any wallet that supports spending via the BIP78 Protocol, using a Tor hidden service.

This hidden service is "ephemeral" meaning it is set up specifically for the payment and discarded after you shut down the receiving process. The setup takes some few seconds but it isn't too slow.

To make this work, you will need to do some minor configuring Tor, the first time. This is explained in detail [below](#torconfig). If you fail to do this step, you will see some rather unintelligible errors about connection failures when trying to run the script described next.

Once that is ready, you can run the `receive-payjoin.py` script something like this:

```python3
(jmvenv)a$ python receive-payjoin.py -m1 walletname.jmdat 0.32
```

The arguments provided are the wallet name and the exact amount you intend to receive (here it's 0.32 BTC (flagged as BTC because decimal), but you could also write `32000000` which will be interpreted as satoshis).

After a delay of 5-50 seconds (usually; Tor setup varies unpredictably), you will see a message like this:

```
Your hidden service is available. Please now pass this URI string to the sender to effect the payjoin payment:
bitcoin:bc1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx?amount=0.32000000&pj=http://p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion:7083
Keep this process running until the payment is received.
```

... which should be self explanatory. The sender may be using Joinmarket, or a different wallet that supports Payjoin, like Wasabi. As previously noted, Payjoins will not work if the address type in use by the two wallets is different, so for Wasabi it would be necessary to use a bech32 Joinmarket wallet (as was discussed [here](#native)).

When the payment goes through you will see a chunk of logging text (most of which is serialized PSBTs being exchanged). If Payjoin was effected as intended, you will see:

```
date string [INFO] Removed utxos= ...
date string [INFO] Added utxos= ...
date string [INFO] transaction seen on network: hex-txid
done
```

where hex-txid is of course the transaction id of the payjoin transaction which paid you.

If you see:

```
date string [INFO] Payment made without coinjoin. Transaction:
```

followed by a detailed transaction output, it means that some incompatibility or error between the two wallets resulted in the normal non-payjoin (non-coinjoin) payment being sent; you still received your money, so DON'T ask to be paid again just because Payjoin failed! This is part of BIP78 - we recognize that things can go slightly wrong in the arrangement (for example, the wrong address type, or a fee requirement that cannot be met), so allowing normal payments instead is very much *intended behaviour*.

On the other hand, if you see at the end:

```
2020-09-12 13:01:15,887 [WARNING]  Payment is not valid. Payment has NOT been made.
```

it means of course the other case. Double check with your counterparty, something more fundamental has gone wrong because they did not send you a valid non-coinjoin payment, as they were supposed to right at the start.

<a name="torconfig" />

#### Configuring Tor to setup a hidden service

(These steps were prepared using Ubuntu; you may have to adjust for your distro).

First, ensure you have Tor installed:

```
sudo apt install tor
```

Don't start the tor daemon yet though, since we need to do some setup. Edit Tor's config file with sudo:

```
sudo vim /etc/tor/torrc
```

and uncomment these two lines to enable hidden service startup:

```
ControlPort 9051
CookieAuthentication 1
```

However if you proceed at this point to try to run `receive-payjoin.py` as outlined above, you will almost certainly get an error like this:

```
Permission denied: '/var/run/tor/control.authcookie'
```

... because reading this file requires being a member of the group `debian-tor`. So add your user to this group:

```
sudo usermod -a -G debian-tor yourusername
```

... and then you must *restart the computer/server* for that change to take effect (check it with `groups yourusername`).

Finally, after system restart, ensure Tor is started (it may be automatically, but anyway):

```
sudo service tor start
```

 Once this is done, you should be able to run the BIP 78 receiver script, or [JoinmarketQt](#using-qt) and a hidden service will be automatically created for you from now on.

<a name="using-qt" />

### Using JoinmarketQt to send and receive Payjoins

All of the configuration details above apply to this scenario (for example, setting up Tor if you want to act as receiver.
But for the workflow on the GUI application, this video explains what to do:

https://video.autizmo.xyz/videos/watch/7081ae10-dce0-491e-9717-389ccc3aad0d

<a name="sample" />

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
