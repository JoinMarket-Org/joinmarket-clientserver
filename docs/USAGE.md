(You have either followed the Quick Install on the readme (`./install.sh`) (RECOMMENDED), or have
followed a manual installation as per [here](INSTALL.md)).

(If you want to run Joinmarket-Qt, start with the [walkthrough](JOINMARKET-QT-GUIDE.md) instead of this.)

# Contents

1. [Managing your Joinmarket data](#data)

   a. [Portability](#portability)

2. [Configuring for Bitcoin Core](#configure)

   a. [Setting a Core wallet (recommended)](#setting-core-wallet)

3. [Using the wallet-tool.py script](#wallet-tool)

   a. [Creating a Wallet](#generate)

   b. [Funding Wallet and Displaying Balance](#funding)

   c. [Spending from the wallet directly (without Coinjoin)](#spending)

   d. [Recovering a Wallet from mnemonic](#recover)

   e. [Recovering Mnemonic from a Wallet](#mnemonic)

   f. [Recovering Private Keys](#privkeys)

   g. [Wallet History](#history)

   h. [Importing External Private Keys](#importprivkeys)

   i. [What is the BIP32 wallet structure](#structure)

   j. [What is the Gap Limit](#gaplimit)

4. [Try out a coinjoin; using sendpayment.py](#try-coinjoin)

5. [Running a "Maker" or "yield generator"](#run-maker)

6. [Running the tumbler script to boost privacy of owned coins](#run-tumbler)

<a name="data" />

## Managing your Joinmarket data

First thing to do: go into `scripts/`, and run:

        (jmvenv)$ python wallet-tool.py generate

This *should* quit with an error, because the connection to Bitcoin Core is not configured; we'll cover that in the next section.
However, this first run will have automatically created a data directory.
Locate the newly created file `joinmarket.cfg` which will be in your user home directory under `.joinmarket/`.
So on Linux you should find it under `/home/username/.joinmarket/joinmarket.cfg`, and similarly for macOS and Windows.
You should see the following files and folders for an initial setup:

```
.joinmarket/
    joinmarket.cfg
    logs/
    wallets/
    cmtdata/
```

`joinmarket.cfg` is the main configuration file for Joinmarket and has a lot of settings, several of which you'll want to edit or at least examine.
This will be discussed in several of the sections below.
The `wallets/` directory is where wallet files, extension (by default) of `.jmdat` are stored after you create them. They are encrypted and store important information; without them, it is possible to recover your coins with the seedphrase, but can be a hassle, so keep the file safe.
The `logs/` directory contains a log file for each bot you run (Maker or Taker), with debug information. You'll rarely need to read these files unless you encounter a problem; deleting them regularly is recommended (and never dangerous). However there are other log files kept here, in particular one called `yigen-statement.csv` which records all transactions your Maker bot does over time. This can be useful for keeping track. Additionally, tumbles have a `TUMBLE.schedule` and `TUMBLE.log` file here which can be very useful; don't delete these.
The `cmtdata/` directory stores technical information that you will not need to read.

<a name="portability" />

### Portability

It is possible to use a different data directory than the default mentioned above (`~/.joinmarket/` or equivalent). To do this, run any Joinmarket script (see below for descriptions of the main ones) with the flag `--datadir=/my/data/directory`.
Then the above directory structure will be created there. If you move a wallet file from one directory to another it will work fine, as long as you are using the same instance of Bitcoin Core.

The slightly more difficult case is moving to a new machine and/or a new Bitcoin Core instance. There, apart from the obvious of needing to change your BLOCKCHAIN configuration settings (see next section), you will encounter an additional hurdle when you move your `.jmdat` file to the new setup.
Since the new Bitcoin Core instance doesn't have the addresses imported, you will need to do a rescan of the blockchain for some appropriate range of blocks.

The worst case is if you recover only from seedphrase and on a new Core instance; then you not only don't have the addresses imported, but Joinmarket will have to search through the addresses to find all usages, which can be tricky and might require multiple rescans in theory. Use the `--recoversync` option of `wallet-tool.py` and use a large gap limit (`-g`) if the wallet was heavily used.

<a name="configure" />

## Configuring for Bitcoin Core.

Bitcoin Core is required to use Joinmarket; note that the node *can* be pruned.

Note that if you compile Core yourself, it must have wallet support (the default), but does not need Qt.

Configuring Joinmarket for Core no longer needs any `walletnotify` setting.

In the `joinmarket.cfg` file described above, edit this section (comments omitted; do read them):

    [BLOCKCHAIN]
    rpc_user = yourusername-as-in-bitcoin.conf
    rpc_password = yourpassword-as-in-bitcoin.conf
    rpc_host = localhost #default usually correct 
    rpc_port = 8332 # default for mainnet

Note, you can also use a cookie file by setting, in this section, a variable `rpc_cookie_file` to the location of the file, as an alternative to using user/password.

<a name="setting-core-wallet" />

### Setting a Core wallet (recommended)

This point often confuses people. Joinmarket has its own wallet, with encryption and storage of keys, separate to Bitcoin Core,
but it *stores addresses as watch-only in the Bitcoin Core wallet*, and the relevant rpc calls to Bitcon Core always specify the
wallet they're talking to. As a result it's strongly recommended to use this feature, as it isolates those watch-only addresses
being stored in Bitcoin Core, from any other usage you might have for that Core instance.

If you don't do this, Joinmarket will use the default Core wallet `wallet.dat` to store these watch-only addresses in.

With `bitcoind` running, do:

```
bitcoin-cli createwallet "jm_wallet"
```

The "jm_wallet" name is just an example. You can set any name. Alternative to this `bitcoin-cli` command: you can set a line with `wallet=..` in your
`bitcoin.conf` before starting Core (see the Bitcoin Core documentation for details).

After you create the wallet in the Bitcoin Core, you should set it in the `joinmarket.cfg`:

```
[BLOCKCHAIN]
...
...
rpc_wallet_file= jm_wallet
```

Then retry the `generate` command we mentioned above; it should now not error (see [below](#generate)).

If you still get rpc connection errors, make sure you can connect to your Core node using the command line first.

<a name="wallet-tool" />

## Using the `wallet-tool.py` script

This section leads you through the basics of creating, funding, recovering and displaying information about the Joinmarket wallet using the `wallet-tool.py` script. A reminder that, at this point, you should be on the command line and in the `scripts/` subdirectory of the Joinmarket directory.

The Joinmarket wallet is hierarchical and deterministic, it can be entirely recovered from a single seed. At any point, you can use `python wallet-tool.py --help` on the command line for all options. We'll now go through all the main functions:

<a name="generate" />

### Creating a Wallet
Run wallet-tool.py with the `generate` method. Write down the 12 word seed on paper.

        (jmvenv)$ python wallet-tool.py generate
        Write down this wallet recovery mnemonic on paper:

        matter aim multiply december stove march wolf nuclear yard boost worth supreme

        Enter wallet encryption passphrase: 
        Reenter wallet encryption passphrase: 
        Input wallet file name (default: wallet.jmdat): 
        saved to wallet.jmdat
        $

So far you have just created the wallet. But to do the next step, you'll need to see the addresses.
Run `python wallet-tool.py wallet.jmdat` (or replace the wallet name with whatever you chose). You'll get this message:

   **restart Bitcoin Core with -rescan or use `bitcoin-cli rescanblockchain` if you're recovering an existing wallet from backup seed**
   **Otherwise just restart this joinmarket application.**

Notice that here you **don't** need to rescan, because you are not "recovering an existing wallet" but creating a new one. Because it is new, none of the addresses are used yet. You only need to rescan (or use `rescanblockchain` as mentioned, which by the way can be a more efficient way of rescanning) if the addresses *have* been used ...

<a name="funding" />

### Funding Wallet and Displaying Balance

... so, ignore this, and just run `python wallet-tool.py wallet.jmdat` again. You should get a large output like this:

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

The [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) xpub keys of each external branch are shown in case that is needed.
The BIP32 derivation paths are also shown; for Joinmarket they are defined by [BIP84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki); for more on this see [below](#structure).

If you set `native = false` in the `[POLICY]` section of your `~/.joinmarket/joinmarket.cfg` file, you will create a wallet with '3' addresses, which is p2sh wrapped segwit, instead of 'bc1' addresses; this uses BIP49 instead of BIP84, but is recoverable similarly (it is slightly more expensive in terms of tx fees; this was the default for Joinmarket pre-0.8.0).

**Bitcoins should be sent to empty external addresses** (sometimes known as receive addresses). You'll notice in
the above that while there are fields also for *internal addresses*, they are empty. That's because zero-balance internal addresses (also known as change addresses) are hidden by default. Using 'displayall' as the second argument will show all addresses in wallet, including empty used ones.

Read the instructions [here](SOURCING-COMMITMENTS.md) before funding the wallet.

Once you've funded it, run `python wallet-tool.py wallet.jmdat` again, enter your passphrase, and you should see the deposited coins.

<a name="spending" />

### Spending from the wallet directly (without Coinjoin)

Note that Joinmarket's wallet supports spending to all address types, including legacy addresses ('1'), P2SH addresses ('3') and bech32 addresses ('bc1'). To learn more about how to spend directly without using CoinJoin, see [here](#no-coinjoin-sending-funds).

<a name="recover" />

### Recovering a Wallet from mnemonic
In the event of loss of encrypted wallet file, use the 12 word seed to recover by running wallet-tool.py with 'recover' as first argument:

        (jmvenv)$python wallet-tool.py recover
        Input mnemonic recovery phrase: matter aim multiply december stove march wolf nuclear yard boost worth supreme
        Input mnemonic extension, leave blank if there isnt one: 
        Enter wallet file encryption passphrase: 
        Reenter wallet file encryption passphrase: 
        Input wallet file name (default: wallet.jmdat):
        Write down this wallet recovery mnemonic
        
        matter aim multiply december stove march wolf nuclear yard boost worth supreme
        
        Recovered wallet OK

#### Help! I recovered but some of my money is missing
Try increasing the gap limit up from its default of 6. This is more likely to happen if you ran a yield generator bot for a while (see below).

        (jmvenv)$ python wallet-tool.py -g 50 my-wallet-file.jmdat

Another possible cause is you used the tumbler script with a larger number of mixdepths than 5 in the old wallet. In that case increase the maximum mixdepth:

        (jmvenv)$ python wallet-tool.py -m 15 recover

Note that you have to make that decision *at the start*, when creating the new wallet file for this old seed, using the `recover` method. So, if you think the wallet was heavily used with large mixdepth numbers, err on the side of caution and use a larger `-m` value. If you don't specify it, it will just use the default 5.

<a name="mnemonic" />

### Recovering a Wallet's Mnemonic Phrase
The `showseed` command will display the mnemonic for an existing wallet file, in case you've forgotten it. **It is highly recommended to keep a written backup of this phrase, lest you forget it!**

        (jmvenv)$ python wallet-tool.py wallet.jmdat showseed

<a name="privkeys" />

### Recovering Private Keys
It is possible to recover a Joinmarket wallet in Trezor, Electrum or a number of other wallets, because it uses BIP84. But note that this is not ideal for privacy reasons (if you contact a server with your addresses), and also that because Joinmarket uses multiple accounts (=mixdepths), it may be more difficult than expected.

In difficult recovery situations, the `-p` command line flag can be used to print out private keys. Be very careful and consider this advanced usage:

```
   ...
   JM wallet
mixdepth	0	xpub6CMAJ67vZWVXuzjzYXUoJgWrmuvFRiqiUG4dwoXNFmJtpTH3WgviANNxGyZYo27zxbMuqhDDym6fnBxmGaYoxr6LHgNDo1eEghkXHTX4Jnx
external addresses	m/84'/0'/0'/0	xpub6FFUn4AxdqFbnTH2fyPrkLreEkStNnMFb6R1PyAykZ4fzN3LzvkRB4VF8zWrks4WhJroMYeFbCcfeooEVM6n2YRy1EAYUvUxZe6JET6XYaW
m/84'/0'/0'/0/0     	bc1qt493axn3wl4gzjxvfg03vkacre0m6f2gzfhv5t	0.00000000	new	Kyx53Zaq35EEPgCkA8bCf2GkmtMjSt261LznWJACb9NzwL8gE9zF
m/84'/0'/0'/0/1     	bc1q2av9emer8k2j567yzv6ey6muqkuew4nh4rl85q	0.00000000	new	KwY2ZANdevBVhdV1KxuadFe9tWoHvZGB2o1qLzgWB9uDgaZQhfPj
m/84'/0'/0'/0/2     	bc1qggpg0q7cn4mpe98t29wte2rfn2rzjtn3zdmqye	0.00000000	new	L5R9TD3c9NyV2Skjxhc58Gem3fhorfRrSTmMxd1JxEByFZifiuKX
m/84'/0'/0'/0/3     	bc1qnnkqz8vcdjan7ztcpr68tyec7dw2yk8gjnr9ze	0.00000000	new	Kxmj5YQ6V4j4jMjr3uK8kHnaDLSCuLao8Yyvn2e5pS4SR4ueCEJ6
m/84'/0'/0'/0/4     	bc1qud5s2ln88ktg83hkr6gv9s576zvt249qn2lepx	0.00000000	new	L2MZPx36cVTQCntDzwJF3AAYJroHEySCfBTG3o2bMCH1aDPjZS3y
m/84'/0'/0'/0/5     	bc1qw0lhq7xlhj7ww2jdaknv23vcyhnz6qxg23uthy	0.00000000	new	L3zrKnqxYDRDHLS3ey4a3BYkMtYPKj2eNAruiJ8SSRDA9tqceHSZ
Balance:	0.00000000
internal addresses	m/84'/0'/0'/1	
Balance:	0.00000000
Balance for mixdepth 0:	0.00000000
mixdepth	1	xpub6CMAJ67vZWVXyTJEaZndxZy9ACUufsmNuJwp9k5dHHKa22zQdsgALxXvMRFSwtvB8BRJzsd8h17pKqoAyHtkBrAoSqC9AUcXB1cPrSYATsZ
external addresses	m/84'/0'/1'/0	xpub6FNSLcHuGnoUbaiKgwXuKpfcbR63ybrjaqHCudrma13NDqMfKgBtZRiPZaHjSbCY3P3cgEEcdzZCwrLKXeT5jeuk8erdSmBuRgJJzfNnVjj
m/84'/0'/1'/0/0     	bc1qhrvm7kd9hxv3vxs8mw2arcrsl9w37a7d6ccwe4	0.00000000	new	KxpBewNsVCSBktvFUPhZLEaXB4pcMwpzWdaEZ1BYRtVK9waeNLbU
   .... etc
 ```

The above method (`-p`) still requires synchronizing the JoinMarket wallet. In the case where this isn't possible, individual private keys can still be exported:

        (jmvenv)$python wallet-tool.py -H "m/84'/0'/4'/0/0" wallet.jmdat dumpprivkey
        Enter wallet decryption passphrase: 
        L1YPrEGNMwwfnvzBfAiPiPC4zb5s6Urpqnk88zNHgsYLHrq2Umss

... using the derivation path (m/...) as specified in the output as above; note the need to use double quotes around it.

<a name="history" />

### Wallet History
The wallet transaction history can be displayed.
Prints a summary for every transaction.
If you have numpy/scipy installed it also calculates the effective interest rate you achieved as if your yield-generator was a savings account.

        (jmvenv)$ python wallet-tool.py wallet.jmdat history

         tx# timestamp type amount/btc balance-change/btc balance/btc coinjoin-n total-fees utxo-count mixdepth-from mixdepth-to
           0 2016-04-20 21:37 deposit     0.15000000 +0.15000000 0.15000000  # #             1  #  0
           1 2016-04-20 22:22 cj internal 0.02115585 +0.00006341 0.15006341  3 #             2  0  1
           2 2016-04-20 23:27 cj internal 0.15046475 +0.00021085 0.15027426  4 #             3  0  1
           3 2016-04-21 23:45 cj internal 0.01209051 +0.00003159 0.15030585  5 #             4  0  1
           4 2016-04-21 00:07 cj internal 0.03120432 +0.00006307 0.15036892  3 #             5  1  2
           5 2016-04-21 00:07 cj internal 0.05538475 +0.00017932 0.15054824  4 #             6  1  2
             2016-04-21 18:55 best block is 000000000000000005009c707b2427224c784c6224a5c44ee449d93b727739e7
        continuously compounded equivalent annual interest rate = 0.459494243045 %
        (as if yield generator was a bank account)
        $ 

You can create a csv file for opening with spreadsheet software:

        (jmvenv)$ python wallet-tool.py --csv wallet.jmdat history > history.csv

<a name="importprivkeys" />

### Importing External Private Keys

Individual private keys can be imported into JoinMarket wallets by using the 'importprivkey' method. Multiple private keys are imported by separating them with commas or spaces. Use the `-M` flag to control which mixing depth the private keys are imported into. Be warned that handling raw private keys like this is dangerous.
You should read the warnings and understand the non-intuitive behaviour before using.
With [this](https://bitcoin.stackexchange.com/questions/29948/why-doc-says-importing-private-keys-is-so-dangerous) and [this](https://bitcoin.stackexchange.com/questions/18619/why-so-many-warnings-about-importing-private-keys) page.
It is best to avoid importing private keys if you can.

        (jmvenv)$ python wallet-tool.py -m 0 example.jmdat importprivkey
        Enter wallet decryption passphrase: 
        WARNING: This imported key will not be recoverable with your 12 word mnemonic seed. Make sure you have backups.
        WARNING: Handling of raw ECDSA bitcoin private keys can lead to non-intuitive behaviour and loss of funds.
          Recommended instead is to use the 'sweep' feature of sendpayment.py 
        Enter private key(s) to import: KzHJDZrSmmwkZKdLNS8L91qGsL9By6b48deaZRExBg4vAiyiBE7V Kxo3mHpUcx6KcLsyGTETh3ZJHEeU73tNCwYM1Yk7MMoTcW4jZ7Mi L3SdjpTu8tGdtht74wwsUX37bqGmr44AoyvZSqvrhTieN2GhbP7e
        Private key(s) successfully imported
        $

<a name="structure" />

### What is the BIP32 wallet structure
#### The Mixing Depth Concept

The point of JoinMarket is to improve privacy. Merged transaction inputs are damaging to privacy because they provide evidence of common ownership. Each mixing depth is a different identity, coins are never merged in the same transaction across mixing depths, but may be merged within mixing depths. Coins move between mixing depths through coinjoins.
A change output stays in the same mixing depth. This prevents the situation where a change output is merged with a coinjoin output in a later transaction, which would render the coinjoin easily unmixable.

An example of the different identities being used is to not leak a lower limit of your wallet balance. Imagine if someone pays you $10 and sees it combined with $1 million, they could deduce you own at least that much. If instead those two payments go to different mixing levels then this analysis becomes harder. As coins move up the mixing levels via coinjoin, their identity becomes more uncertain. To introduce more uncertainty, have the coins separated by more mixing levels. E.G. A coin in level 0 and a second coin with level 1 will be merged with one set of coinjoins between them, the second coin at level 5 will be merged with 5 sets of coinjoins.

#### BIP32 Structure

m - generated from seed
m/84' - purpose: this is specified by [BIP84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki) for p2wpkh native segwit addresses
m/84'/0' - coin type 0 : see [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) which specifies this as the coin type for Bitcoin mainnet
m/84'/0'/n' - nth mixing depth (nth account) (as per BIP44)
m/84'/0'/n'/0/k - kth external address, for mixing depth n
m/84'/0'/n'/1/k - kth internal address, for mixing depth n

Note that the quote (') indicates hardened derivation. See [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) for technical details.

<a name="gaplimit" />

### What is the Gap Limit?

With a deterministic wallet you create a sequence of bitcoin addresses and private keys from an initial seed. This list is the same every time it's generated, it means the entire wallet can be backed up by saving only the initial seed.

You can create as many addresses as you like, but not all of them will appear the blockchain. For instance I might create one especially for you to give me 1,000,000 BTC. That is (alas!) probably not going to be used so will likely never appear on the blockchain.

When you are starting JoinMarket it does not know which is the last address used. So you start at the beginning and see what is on the blockchain. Then you look for the next one in the sequence. The gap limit is how many *misses* you accept before you give up and stop looking. The same concept is used in other deterministic wallets like Electrum.

<a name="try-coinjoin" />

## Try out a coinjoin; using `sendpayment.py`

**Doing single coinjoins doesn't really achieve a significant privacy boost; so you can skip much of this if that's your only interest, and go [here](#run-tumbler) instead to learn about the tumbler script; but do read here about how to spend coins from the wallet.**.

A single coinjoin *can* make destination (payment) outputs unclear, and can degrade automated blockchain surveillance significantly. We recommend using these opportunistically when making payments but on no account rely on any specific privacy gain from doing so.

Single coinjoins can be done using the script `sendpayment.py`. As with all Joinmarket user scripts, use `--help` to see a full list of options.

Here is an example:

        (jmvenv)$ python sendpayment.py wallet.jmdat 5000000 mprGzBA9rQk82Ly41TsmpQGa8UPpZb2w8c

Or you can use BIP21 bitcoin payment URI:

        (jmvenv)$ python sendpayment.py wallet.jmdat bitcoin:mprGzBA9rQk82Ly41TsmpQGa8UPpZb2w8c?amount=0.05

These send 5000000 satoshi (0.05btc) to the address *mprGzBA9rQk82Ly41TsmpQGa8UPpZb2w8c* (testnet), with the default 5-7 (randomized) other parties from the default 0-th mixing depth from the wallet contained in the file *wallet.jmdat*. This will take some time, since Joinmarket will connect to remote messaging servers and do end to end encrypted communication with other bots, and also you will be paying some fees (more on this later in this section).

<a name="no-coinjoin-sending-funds" />

#### No coinjoin, sending funds

Suppose you simply wanted to pay that address without coinjoin. Easy, just set the number of counterparties to zero:

        (jmvenv)$ python sendpayment.py wallet.jmdat -N 0 5000000 mprGzBA9rQk82Ly41TsmpQGa8UPpZb2w8c

Other options such as "sweep", and network fees (see below) work the same when you set `-N 0`. This is your basic wallet function without CoinJoin.

Here is another example of a CoinJoin usage:

        (jmvenv)$ python sendpayment.py -N 5 -m 1 wallet.jmdat 100000000 mprGzBA9rQk82Ly41TsmpQGa8UPpZb2w8c

Sends 1BTC (100 million satoshis) from mixing depth 1 (the second!), mixing with five other parties.

Amount can be specified as either bitcoins (if decimal value or has "btc" suffix) or satoshis (if integer value or has "sat" suffix). So, 1 BTC can be specified as 1.0, 1btc, 100000000, 100000000sat or 100000000.0sat.

Setting the *amount* to zero will cause the bot to sweep. Meaning it will empty that mixing depth, calculating the coinjoin fee so that no coins are left.

        (jmvenv)$ python sendpayment.py -N 7 wallet.jmdat 0 mprGzBA9rQk82Ly41TsmpQGa8UPpZb2w8c

... sends all coins in mixdepth 0 (default), minus whatever is needed as coinjoin and network fees, to the destination address, via a CoinJoin with 7 other parties. Note that CoinJoins that are sweeps are particularly powerful because no change is left behind to make future linkages.

### Fee settings

There are two different types of fee; bitcoin network transaction fees and fees paid to counterparties for providing liquidity for coinjoins (that latter being the central idea of Joinmarket).

#### Bitcoin network fees.

This is controlled using the setting of `tx_fees` in the `[POLICY]` section in your `joinmarket.cfg` file in the current directory. If you set it to a number between 1 and 1000 it is treated as the targeted number of blocks for confirmation; e.g. if you set it to 20 you are asking to use whatever Bitcoin Core thinks is a realistic fee to get confirmation within the next 20 blocks. By default it is 3. If you set it to a number > 1000, don't set it lower than about 1200, it will be interpreted as "number of satoshis per kilobyte for the transaction fee". 1000 equates to 1 satoshi per byte (ignoring technical details of vbyte), which is usually the minimum fee that nodes on the network will relay. Note that Joinmarket will deliberately vary your choice randomly, in this case, by 20% either side, to avoid you watermarking all your transactions with the exact same fee rate. As an example, if you prefer to use an approximate rate of 20 sats/byte rather than rely on Bitcoin Core's estimated target for 3 or 6 blocks, then set `tx_fees` to 20000.
Note that some liquidity providers (Makers) will offer very small contributions to the tx fee, but mostly you should consider that you must pay the whole Bitcoin network fee yourself, as an instigator of a coinjoin (a Taker). Note also that if you set 7 counterparties, you are effectively paying for approximately 7 normal sized transactions; be cognizant of that!

#### CoinJoin fees.

Individual Makers will offer to do CoinJoin at different rates. Some set their fee as a percentage of the amount, and others set it as a fixed number of satoshis. Most set their rates very low, so in most (but not all) cases the overall CoinJoin fee will be lower than the bitcoin network fees discussed above. When starting to do a CoinJoin you will be prompted to set the *maximum* relative (percentage) and absolute (number of satoshis) fees that you're willing to accept from one participant; your bot will then choose randomly from those that are below at least one of those limits. Please read these instructions carefully and update your config file accordingly to avoid having to answer the questions repeatedly.

Note also that you can use 'schedule' files, but that's more advanced so ignore it for now; see the README under scripts/ for more details.

<a name="run-maker" />

## Running a "Maker" or "yield generator".

Follow the guide [here](YIELDGENERATOR.md).

<a name="run-tumbler" />

### Running the tumbler script to boost privacy of owned coins.

Read the instructions [here](tumblerguide.md)
