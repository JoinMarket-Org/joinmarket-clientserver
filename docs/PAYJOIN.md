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

   a. [Using BIP78 payjoins to pay a merchant or other user's wallet](#bip78)

   b. [Using Joinmarket-wallet-to-Joinmarket-wallet payjoins](#jmtojm)

   c. [About fees](#fees)

5. [What if I wanted p2sh segwit addresses?](#p2sh)

6. [Receiving a BIP78 Payjoin payment](#receiving)

7. [Configuring Tor to setup a hidden service](#torconfig)

8. [Using JoinmarketQt to send and receive Payjoins](#using-qt)

7. [Sample testnet wallet display output](#sample)

Some instructions here will be redundant with the introductory [usage guide](USAGE.md); sections 1-3 are aimed at users who have not/ will not use Joinmarket for ordinary coinjoins.
So just skip those sections if you already know it.

<a name="preparatory" />

### Preparatory step: configuring for Bitcoin Core.

Joinmarket currently requires a Bitcoin Core full node, version 0.18 or newer, although it can be pruned.

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

(But wait again! Before you finish: want a p2sh segwit wallet? you probably don't,
but read [this](#what-if-i-wanted-p2sh-segwit-addresses) if you do.)

The wallet you create is (if not p2sh) BIP84 by default, using BIP39 12 word seed,
mnemonic extension optional (simplest to leave it out if you're not sure).

Once the `generate` method run has completed, successfully, you need to look at the wallet contents. Use
the `display` method which is the default:

```
python wallet-tool.py wallet-name-you-chose.dat [display]
```

("display" is optional because default; use `python wallet-tool.py -h` to see all possible methods).

Below is [an example](#sample) of what the wallet looks like.

Joinmarket by default uses *5* accounts, not only 1 as some other wallets (e.g. Electrum), this is to help
with coin isolation. Try to move coins from one account to another *only* via coinjoins; or, you can just
use one or two accounts (called **mixdepths** in Joinmarket parlance) as if they were just one, understanding
that if you don't bother to do anything special, the coins in those two mixdepths are linked.

**Fund** the wallet by choosing one or more addresses in the *external* section of the first account (called
"Mixdepth 0" here). When you fund, fund to the external addresses. The internals will be used for change.

(The new standard (BIP84) *should* be compatible with TREZOR, Ledger, Electrum, Samourai and some others,
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
* If the url in `pj=` is `****.onion` it means you must be using Tor, remember to have Tor running on your system and change the configuration (see below) for socks5 port if necessary. If you are running the Tor browser the port is 9150 instead of 9050.
* Don't forget to specify the mixdepth you are spending from with `-m 0`. The payment amount is of course in the URI, along with the address.
* Pay attention to address type; this point is complicated, but: some servers will not be able to match the address type of the sender, and so won't be able to construct sensible Payjoin transactions. In that case they may fallback to the non-Payjoin payment (which is not a disaster). If you want to do a Payjoin with a server that only supports p2sh, not bech32, you will have to create a new Joinmarket wallet, specifying `native=false` in the `POLICY` section of `joinmarket.cfg` before you generate the wallet.

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

# for payjoin onion service creation, the tor control configuration:
tor_control_host = localhost
# or, to use a UNIX socket
# control_host = unix:/var/run/tor/control
tor_control_port = 9051

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

This can be done with the same [BIP78](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki) workflow described above; the "old style" internal Joinmarket payjoins from 2019 are now deprecated.

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

<a name="p2sh" />

#### What if I wanted p2sh segwit addresses?

You can do this, but bear in mind: PayJoin only gives its full effect if you and your receiver are using the same kind of addresses; so do this only if you and your receiver(s)/sender(s) agree on it - most BIP78 receivers at least for now will only engage in the protocol if they can provide inputs of the same type as yours.

As was noted in the BIP78 section, it may be therefore that you *need* to do this (albeit that the worst that can happen is a fallback to non-payjoin payment, which isn't a disaster).

In the configuration file `joinmarket.cfg` (which was created in the preparatory step above), go to the
POLICY section and set:

```
[POLICY]
native = false
```

Note that this must be done *before* generating the wallet, as
the wallet internally, of course, stores which type of addresses it manages, and it can only be of two
types currently (ignoring legacy upgrades): bech32 or p2sh-segwit (starting with '3'), the former being
the default in Joinmarket as of 0.8.0+.

Note that the p2sh-wrapped-segwit style wallet is written to conform to [BIP49](https://github.com/bitcoin/bips/blob/master/bip-0040.mediawiki),
analogous to the BIP84 case for native/bech32.

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

... which should be self explanatory. The sender may be using Joinmarket, or a different wallet that supports Payjoin, like Wasabi. As previously noted, Payjoins will not work if the address type in use by the two wallets is different, so for Wasabi it would be necessary to use a bech32 Joinmarket wallet (the default).

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

#### Configuring Tor to setup an onion service

Read about how to do this [here](./tor.md).

<a name="using-qt" />

### Using JoinmarketQt to send and receive Payjoins

All of the configuration details above apply to this scenario (for example, setting up Tor if you want to act as receiver.
But for the workflow on the GUI application, this video explains what to do:

https://video.autizmo.xyz/videos/watch/7081ae10-dce0-491e-9717-389ccc3aad0d

<a name="sample" />

#### Sample wallet display output

```
JM wallet
mixdepth	0	xpub6CMAJ67vZWVXuzjzYXUoJgWrmuvFRiqiUG4dwoXNFmJtpTH3WgviANNxGyZYo27zxbMuqhDDym6fnBxmGaYoxr6LHgNDo1eEghkXHTX4Jnx
external addresses	m/84'/0'/0'/0	xpub6FFUn4AxdqFbnTH2fyPrkLreEkStNnMFb6R1PyAykZ4fzN3LzvkRB4VF8zWrks4WhJroMYeFbCcfeooEVM6n2YRy1EAYUvUxZe6JET6XYaW
m/84'/0'/0'/0/0     	bc1qt493axn3wl4gzjxvfg03vkacre0m6f2gzfhv5t	0.00000000	new
m/84'/0'/0'/0/1     	bc1q2av9emer8k2j567yzv6ey6muqkuew4nh4rl85q	0.00000000	new
m/84'/0'/0'/0/2     	bc1qggpg0q7cn4mpe98t29wte2rfn2rzjtn3zdmqye	0.00000000	new
m/84'/0'/0'/0/3     	bc1qnnkqz8vcdjan7ztcpr68tyec7dw2yk8gjnr9ze	0.00000000	new
m/84'/0'/0'/0/4     	bc1qud5s2ln88ktg83hkr6gv9s576zvt249qn2lepx	0.00000000	new
m/84'/0'/0'/0/5     	bc1qw0lhq7xlhj7ww2jdaknv23vcyhnz6qxg23uthy	0.00000000	new
Balance:	0.00000000
internal addresses	m/84'/0'/0'/1	
Balance:	0.00000000
Balance for mixdepth 0:	0.00000000
mixdepth	1	xpub6CMAJ67vZWVXyTJEaZndxZy9ACUufsmNuJwp9k5dHHKa22zQdsgALxXvMRFSwtvB8BRJzsd8h17pKqoAyHtkBrAoSqC9AUcXB1cPrSYATsZ
external addresses	m/84'/0'/1'/0	xpub6FNSLcHuGnoUbaiKgwXuKpfcbR63ybrjaqHCudrma13NDqMfKgBtZRiPZaHjSbCY3P3cgEEcdzZCwrLKXeT5jeuk8erdSmBuRgJJzfNnVjj
m/84'/0'/1'/0/0     	bc1qhrvm7kd9hxv3vxs8mw2arcrsl9w37a7d6ccwe4	0.00000000	new
m/84'/0'/1'/0/1     	bc1q0sccdfrsnjtgfytul5zulst46wxgahtcf44tcw	0.00000000	new
m/84'/0'/1'/0/2     	bc1qst6p8hr8yg280zcpvvkxahv42ecvdzq63t75su	0.00000000	new
m/84'/0'/1'/0/3     	bc1q0gkarwg8y3nc2mcusuaw9zsn3gvzwe8mp3ac9h	0.00000000	new
m/84'/0'/1'/0/4     	bc1qkf5wlcla2qlg5g5sym9gk6q4l4k5c98vvyj33u	0.00000000	new
m/84'/0'/1'/0/5     	bc1qz6zptlh3cqty2tqyspjk6ksqelnvrrrvmyqa5v	0.00000000	new
Balance:	0.00000000
internal addresses	m/84'/0'/1'/1	
Balance:	0.00000000
Balance for mixdepth 1:	0.00000000
mixdepth	2	xpub6CMAJ67vZWVY2cq5fmVxXw92fcgTchphGNFxweSiupYH1xYfjBiK6dj5wEEVAQeA4JcGDQGm2xcuz2UsMnDkzVmi2ESZ3xey63mQMY4x2w2
external addresses	m/84'/0'/2'/0	xpub6DqkbMG3tj2oixGYniEQTFamLCHTZx9CeAbUdBttiGuYwgfGZbrLMor8LWeJBUqTpsa81JcJqAUXuDxhXdLpKDxJAEqKMqPgJyXstj5dp3o
m/84'/0'/2'/0/0     	bc1qwtdgg928wma8jz32upkje7e4cegtef7yrv233l	0.00000000	new
m/84'/0'/2'/0/1     	bc1qhkuk2gny4gumrxcaw999uq3jm3fjrjvcwz7lz3	0.00000000	new
m/84'/0'/2'/0/2     	bc1qvu753lkltc8akfasclnq89tdv8yylu2alyg76y	0.00000000	new
m/84'/0'/2'/0/3     	bc1qal3r040k26cw2f08337huzcf00hrnws5rhfrz3	0.00000000	new
m/84'/0'/2'/0/4     	bc1qpv4nm7wwtxesgwsr0g0slxls33u0w02gqx2euk	0.00000000	new
m/84'/0'/2'/0/5     	bc1qk3ekjzlvw3uythw738z7nvwe2sg93w2rtuy6ml	0.00000000	new
Balance:	0.00000000
internal addresses	m/84'/0'/2'/1	
Balance:	0.00000000
Balance for mixdepth 2:	0.00000000
mixdepth	3	xpub6CMAJ67vZWVY3uty61M6jeGheGU5ni5mQmqMW2QLQbEa8ZQXuBw1K2umKFZsmU8EMEafJZKQkGS1trtWE5dtz4XmDbvLvUccAPn26ZC5i2o
external addresses	m/84'/0'/3'/0	xpub6EvT4QFPRdkt2sji3QdLLZjkJQmk7G2y3umT99ceomKTXGYvZ5S9TLaGos6cEugXEuxS6s9kvSUj1Xvpiu65dn5yzK7CgdZLzXawpKC9Mpe
m/84'/0'/3'/0/0     	bc1q9ph5l2gknjezcmzv84rnhu4df566jgputzef7l	0.00000000	new
m/84'/0'/3'/0/1     	bc1qrlvmmxfuryr3mfhssjv45h0fl6s43g3vzrkwca	0.00000000	new
m/84'/0'/3'/0/2     	bc1q40xkajgv9q42ve92zstwjc9v4jgauxme9su6uc	0.00000000	new
m/84'/0'/3'/0/3     	bc1q38pfk8yfnu97v4mckkuk2dhk9u8geuyzu9c0hc	0.00000000	new
m/84'/0'/3'/0/4     	bc1q2qzxyw56em9qdxc5z5s5xjz3j6s2qlzn3juvtu	0.00000000	new
m/84'/0'/3'/0/5     	bc1qd2f8f3dau5pfjqu7dpuvt6fahj36w4rgl3xevr	0.00000000	new
Balance:	0.00000000
internal addresses	m/84'/0'/3'/1	
Balance:	0.00000000
Balance for mixdepth 3:	0.00000000
mixdepth	4	xpub6CMAJ67vZWVY7gT4oJQBMc1fhbausT57yNVLCLCMwaGed5spHKaQY1EMQxvL2vTgDfhEimuAy7bzBE1qx5uY6D7cpUjQtXPHpyJzFuUtQPN
external addresses	m/84'/0'/4'/0	xpub6EQWpKsBTG3N9TFU4v6WtCcBJuLAeTZTcUwVJTxYUAsHeVPFdey4qT1dg4G7MqvnFFgHZDxqTo37S81UWUA2BqKKoTff1pcHTcSFzxyp5JG
m/84'/0'/4'/0/0     	bc1qdpjh3ewm367jm5eazqdf8wfrm09py50wn47urs	0.00000000	new
m/84'/0'/4'/0/1     	bc1q2x0fmtms5nr3wz3x3660c8wampg7t22e6m30t8	0.00000000	new
m/84'/0'/4'/0/2     	bc1q23595yg3dkj8gd3jrgup0hyzslhzf9skrg50r5	0.00000000	new
m/84'/0'/4'/0/3     	bc1qw48asjpkwm3k2w8cketqhrre0uwq9f7ypwzmxl	0.00000000	new
m/84'/0'/4'/0/4     	bc1qf3wljw44utyv7qd0z57zvdkfl20y470mva0nes	0.00000000	new
m/84'/0'/4'/0/5     	bc1qz3f80rtv0ux85d7rc06ldtvmpqyfx6ly48c9pa	0.00000000	new
Balance:	0.00000000
internal addresses	m/84'/0'/4'/1	
Balance:	0.00000000
Balance for mixdepth 4:	0.00000000
Total balance:	0.00000000

```
