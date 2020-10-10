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
The `logs/` directory contains a log file for each bot you run (Maker or Taker), with debug information. You'll rarely need to read these files unless you encounter a problem; deleting them regularly is recommended (and never dangerous). However there are other log files kept here, in particular one called `yigen-statement.csv` which records all transactions your Maker bot does over time. This can be useful for keeping track. Additionall, tumbles have a `TUMBLE.schedule` and `TUMBLE.log` file here which can be very useful; don't delete these.
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
mixdepth	0	xpub6Crt4fcfpnrNxW45MzuV626z4fjddsuFGwRn1DXdpwnDkBMR12GKdBzW8euDqLSqRRv2eZmcJy8FSQLWEosC6wFZAZEv3FJMtvZ7W1CkQDi
external addresses	m/49'/0'/0'/0	xpub6FQFAscJgwd8MXCcAT8A1hgx9vigrgVoXVNTAKHj2aK3NR2Zf1CbFNXD8G8X9dspGXLY9eiEzBWaypr24owJ8r1aTKgMbUZoTnQ36bBwQB3
m/49'/0'/0'/0/0     	35SrGbUt9FpfA6xqKMpNaiTNyeuXagBi7Y	0.00000000	new
m/49'/0'/0'/0/1     	39hc2xfA6i9kWZdXMwH4Pd9dWUvDKocGd3	0.00000000	new
m/49'/0'/0'/0/2     	371MJcjFG4cEpz8RVdYb1L8PkA9tZYySGZ	0.00000000	new
m/49'/0'/0'/0/3     	39eTy635wLCyBbphUTNnSB2V9LnvgdndNo	0.00000000	new
m/49'/0'/0'/0/4     	33T8eNr54maWNZYQjoZwpLA2HGk7RJaLVb	0.00000000	new
m/49'/0'/0'/0/5     	35kJoTSxHtQbKUg2jvjDVqcY9iXoH2cTqD	0.00000000	new
Balance:	0.00000000
internal addresses	m/49'/0'/0'/1	
Balance:	0.00000000
Balance for mixdepth 0:	0.00000000
mixdepth	1	xpub6Crt4fcfpnrP2GZnVuT1qi9aw9cpCuXcnGEjAKhaoWAHq5M4pWX64DNio3XHirY5uTCZCi6vTmaLjU5YQXbVsTjyEdCE2zn3S2fzBNFjxs8
external addresses	m/49'/0'/1'/0	xpub6E2EnYy6yBXvE9U1nR5sSH58YiwbsKFZzaMkgMY5jrt2XFe4D5HVwikeTWyjuoczjQhJNezkwxrKAbUPMEDYHmbiaaiEAeXcL1yAcEAqtd7
m/49'/0'/1'/0/0     	3DdhEr9GCoMDVRLNGAwi9rb8F4HQX8newY	0.00000000	new
m/49'/0'/1'/0/1     	342XPkCQYzZkdUaB9TGPfVhf1iX55yE4gH	0.00000000	new
m/49'/0'/1'/0/2     	33RaQJTn1P8KNUvNnPRFM19zHjPhzuyCqc	0.00000000	new
m/49'/0'/1'/0/3     	3LydaxypMyYrbDFFp61f9rnZRcAJnZ5sv5	0.00000000	new
m/49'/0'/1'/0/4     	36u2ykPy6Y9tg811B8XjYoPjpTtEg98RPd	0.00000000	new
m/49'/0'/1'/0/5     	3AfSFczJEUN5RRbXirf8Pc74ve3ZaBVF8r	0.00000000	new
Balance:	0.00000000
internal addresses	m/49'/0'/1'/1	
Balance:	0.00000000
Balance for mixdepth 1:	0.00000000
mixdepth	2	xpub6Crt4fcfpnrP2Tjc95HKmSgaCpi9P9EM54B12XAUfdnyAyoftFpNyikSK4pBtsvqZAnj8grDFf61xDmAHYimQXvaQkoTY3h9G5BAxHuYgvn
external addresses	m/49'/0'/2'/0	xpub6DrRZxJu5zEgxVMcrXmKGGeEQMgfh1MeZXvDXVYndqsqoFaJQUA94GbD1JX2p7Yw5NLcCUgg3WQXtXk5eP4vnNjGkDwA3FJoFFkE4PytauC
m/49'/0'/2'/0/0     	39uPqzuW6CiyRSUvdrBYfaqSD2AtH2k4wf	0.00000000	new
m/49'/0'/2'/0/1     	3FVYzJWE6g6kGj3hF7B5e7QpDQafBcUdnx	0.00000000	new
m/49'/0'/2'/0/2     	3HjYatHB5tZFGcC2SUCBqT1zCM7AwgGE5r	0.00000000	new
m/49'/0'/2'/0/3     	3CDco5iVa2iyEHGjXcAojsod6QDxeNedFg	0.00000000	new
m/49'/0'/2'/0/4     	3LKaYFENU16ix8FngQk6m9VmQFGaATEeCu	0.00000000	new
m/49'/0'/2'/0/5     	3B3TtgU6VgLF6BzQeG5znKZHpr3zgoftZC	0.00000000	new
Balance:	0.00000000
internal addresses	m/49'/0'/2'/1	
Balance:	0.00000000
Balance for mixdepth 2:	0.00000000
mixdepth	3	xpub6Crt4fcfpnrP5B7ysPePnY98sKaLAdu9yCbHpkodb6evSKhr4BWvpB7nQquPdzncTuhMxmUhEcVNuYpXQf9i6VN9DFYu3PgPMckuu4P7EeQ
external addresses	m/49'/0'/3'/0	xpub6En2j7xGy2ihoYhpmTyDL1eER5B6rdas1HotoBiLbSXuXBMwZnjJTRefyJKVLUTfwDMgyATqZAwbZdKb8gQ8Fbno4XhUMPe6XBuN4LSsXN2
m/49'/0'/3'/0/0     	3LhThkjSvYmmXLNLMcXghbvaoGgDitwfmi	0.00000000	new
m/49'/0'/3'/0/1     	3LTwvukpZqsf9ghqnNQVu8szgScjoVnLdh	0.00000000	new
m/49'/0'/3'/0/2     	35FRiSaZ6Yotr3YB3yX9JgqAbsxCnuTBfm	0.00000000	new
m/49'/0'/3'/0/3     	3H7S5ZjYaWgSTXA1RFwGNytS2zsK1PfXoN	0.00000000	new
m/49'/0'/3'/0/4     	33b8j2nPCFCWXb7wDHPRggUFoPJMwGQYYt	0.00000000	new
m/49'/0'/3'/0/5     	3PE7fen989oPZn7XaRSAu3fvGN1P57SB9W	0.00000000	new
Balance:	0.00000000
internal addresses	m/49'/0'/3'/1	
Balance:	0.00000000
Balance for mixdepth 3:	0.00000000
mixdepth	4	xpub6Crt4fcfpnrP9pZBowaYjC7595HXETHFw2YnqtukLnqpfb4PWbhWwt5jPdskLo8ZZbHBnccexTJUArt4V8C7592K3LvsrYkrvsQMJFiPx8z
external addresses	m/49'/0'/4'/0	xpub6E37s5W8C63FxsgcpMbH43ssUi8CQzfo3PrfSWfn9jKTYZgR4QZBCymJ8TPw3Vx5zoQ7aSgkqrEKr1NEerZuN8okV7w1JhNg2hoYEWohtT4
m/49'/0'/4'/0/0     	39n1tYKnPQ47bgCmsPWDHxuk2Mxo6GE4LZ	0.00000000	new
m/49'/0'/4'/0/1     	3BoLqHDSHdMHyrSEAP31bBzzw45bFwZhy7	0.00000000	new
m/49'/0'/4'/0/2     	31mo7D9UDmoStafYcyHpwV9sWY7oP9jUVQ	0.00000000	new
m/49'/0'/4'/0/3     	3JMVGEyZ5nyJR9NVsfNY93c34xx9rEtzmq	0.00000000	new
m/49'/0'/4'/0/4     	3AdD86dw59Q5EGHVupkHzR8pM4sW45bKqX	0.00000000	new
m/49'/0'/4'/0/5     	3Gu7jTxcmh5dHJXgCE7Z5fdMgUWuenE2GE	0.00000000	new
Balance:	0.00000000
internal addresses	m/49'/0'/4'/1	
Balance:	0.00000000
Balance for mixdepth 4:	0.00000000
Total balance:	0.00000000

```

The [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) xpub keys of each external branch are shown in case that is needed.
The BIP32 derivation paths are also shown; for Joinmarket they are defined by [BIP49](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki); for more on this see [below](#structure).

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
It is possible to recover a Joinmarket wallet in Trezor, Electrum or a number of other wallets, because it uses BIP49. But note that this is not ideal for privacy reasons (if you contact a server with your addresses), and also that because Joinmarket uses multiple accounts (=mixdepths), it may be more difficult than expected.

In difficult recovery situations, the `-p` command line flag can be used to print out private keys. Be very careful and consider this advanced usage:

```
   ...
   JM wallet
   mixdepth	0	xpub6Crt4fcfpnrNxW45MzuV626z4fjddsuFGwRn1DXdpwnDkBMR12GKdBzW8euDqLSqRRv2eZmcJy8FSQLWEosC6wFZAZEv3FJMtvZ7W1CkQDi
   external addresses	m/49'/0'/0'/0	xpub6FQFAscJgwd8MXCcAT8A1hgx9vigrgVoXVNTAKHj2aK3NR2Zf1CbFNXD8G8X9dspGXLY9eiEzBWaypr24owJ8r1aTKgMbUZoTnQ36bBwQB3
   m/49'/0'/0'/0/0     	35SrGbUt9FpfA6xqKMpNaiTNyeuXagBi7Y	0.00000000	new	L4TDPLYgd77GcHWdLTCEhqqd3GM15Wp7PX7dw1YeyCeRb326hM8K
   m/49'/0'/0'/0/1     	39hc2xfA6i9kWZdXMwH4Pd9dWUvDKocGd3	0.00000000	new	L26Y8v6fU3Nx8yaRhnkKAq3wi4TkaR5BgEXuDQNmR2nv2v7kVCd9
   m/49'/0'/0'/0/2     	371MJcjFG4cEpz8RVdYb1L8PkA9tZYySGZ	0.00000000	new	KyLza1kdozCyGwt6rkwkhshaBHS8hhciB6mnneczrxtFYXTNeyYV
   m/49'/0'/0'/0/3     	39eTy635wLCyBbphUTNnSB2V9LnvgdndNo	0.00000000	new	KyKugtGLD1RpA8ZURCPqJ74kWyh26JBnfPG1TtjzmBoS5E3wzWJK
   m/49'/0'/0'/0/4     	33T8eNr54maWNZYQjoZwpLA2HN4UJB2Gk7RJaLVb	0.00000000	new	L3yjfeVyBCwTgUXpdPNKPK7RBQ6Xvc17LThvF3zKM2pQkWpEEcbo
   m/49'/0'/0'/0/5     	35kJoTSxHtQbKUg2jvjDVqcY9iXoH2cTqD	0.00000000	new	L1QXi1KjVyTFQZGWeybjnnSN3sieYGeTQtTiYrwLJmJvhQ7EBzVL
   Balance:	0.00000000
   internal addresses	m/49'/0'/0'/1	
   Balance:	0.00000000
   Balance for mixdepth 0:	0.00000000
   mixdepth	1	xpub6Crt4fcfpnrP2GZnVuT1qi9aw9cpCuXcnGEjAKhaoWAHq5M4pWX64DNio3XHirY5uTCZCi6vTmaLjU5YQXbVsTjyEdCE2zn3S2fzBNFjxs8
   external addresses	m/49'/0'/1'/0	xpub6E2EnYy6yBXvE9U1nR5sSH58YiwbsKFZzaMkgMY5jrt2XFe4D5HVwikeTWyjuoczjQhJNezkwxrKAbUPMEDYHmbiaaiEAeXcL1yAcEAqtd7
   m/49'/0'/1'/0/0     	3DdhEr9GCoMDVRLNGAwi9rb8F4HQX8newY	0.00000000	new	KzNosXo1sDfSJr7JcyqwYqGzTKTgAeQ9iEfiWA5YVE3Y6Tn3iCJs
   .... etc
 ```

The above method (`-p`) still requires synchronizing the JoinMarket wallet. In the case where this isn't possible, individual private keys can still be exported:

        (jmvenv)$python wallet-tool.py -H "m/49'/0'/4'/0/0" wallet.jmdat dumpprivkey
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

        (jmvenv)$ python wallet-tool.py -M 0 example.jmdat importprivkey
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
m/49' - purpose: this is specified by [BIP49](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki) for P2SH-wrapped segwit P2WPKH addresses
m/49'/0' - coin type 0 : see [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) which specifies this as the coin type for Bitcoin mainnet
m/49'/0'/n' - nth mixing depth (nth account) (as per BIP44)
m/49'/0'/n'/0/k - kth external address, for mixing depth n
m/49'/0'/n'/1/k - kth internal address, for mixing depth n

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

This is controlled using the setting of `tx_fees` in the `[POLICY]` section in your `joinmarket.cfg` file in the current directory. If you set it to a number between 1 and 1000 it is treated as the targeted number of blocks for confirmation; e.g. if you set it to 20 you are asking to use whatever Bitcoin Core things is a realistic fee to get confirmation within the next 20 blocks. By default it is 3. If you set it to a number > 1000, don't set it lower than about 1200, it will be interpreted as "number of satoshis per kilobyte for the transaction fee". 1000 equates to 1 satoshi per byte (ignoring technical details of vbyte), which is usually the minimum fee that nodes on the network will relay. Note that Joinmarket will deliberately vary your choice randomly, in this case, by 20% either side, to avoid you watermarking all your transactions with the exact same fee rate. As an example, if you prefer to use an approximate rate of 20 sats/byte rather than rely on Bitcoin Core's estimated target for 3 or 6 blocks, then set `tx_fees` to 20000.
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
