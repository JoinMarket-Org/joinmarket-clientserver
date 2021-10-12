# HOW TO USE THE SNICKER FEATURES IN JOINMARKET

# Contents

1. [Basic concepts and definition](#basic)

   a. [Quick read: advice](#quick)

   b. [Slightly longer description](#longer)

   c. [Proof of work for anti-spam](#pow)

   d. [Servers](#servers)

   e. [New script tools](#scripts)

2. [Updating config](#configure)

3. [Alternative to mainnet usage](#network)

4. [Running SNICKER as a receiver](#receiver)

   a. [Manually running the receiver](#manually)

   b. [Running a yield-generator with SNICKER active](#yieldgen)

5. [Use of wallets](#wallets)

6. [Checking for SNICKER coinjoins](#checking)

7. [A testing workflow](#testing)

8. [Appendix: Example SNICKER transaction](#appendix1)

<a name="basic" />

## Basic concepts and definition

<a name="quick" />

### Quick read: advice

For the time constraints, consider these points:

* This is *somewhat* experimental; better run it on signet for now, mainnet is not advised.
* If you do run it on mainnet, make an effort to keep backups of your jmdat wallet file; recovery with seed only is possible (a tool is provided), but it's a pain.
* This basically allows coinjoins to be proposed and executed without any interaction by the participants, even over a message channel. You can run it passively in a yield generator, for example. You can even be paid some small amount of sats for that to happen. But the coinjoins are only 2-party.

<a name="longer" />

### Slightly longer read on what this is:

For formal specs as currently implemented, please use [this](https://gist.github.com/AdamISZ/2c13fb5819bd469ca318156e2cf25d79). Less technical description [here](https://joinmarket.me/blog/blog/snicker/).

Essentially, this is a two party but non-interactive protocol. The **proposer** will identify, on the blockchain, a candidate transaction where he has some confidence that one or more inputs are owned by the same party as one output, and that that party has SNICKER receiver functionality.
Given those conditions, he'll create one or more **proposals** which are of form `base64-encoded-ECIES-encrypted-PSBT,hex-encoded-pubkey` (the separator is literally a comma; this is ASCII encoded), and send them to a **snicker-server** which is hosted at an onion address (possibly TLS but let's stick with onion for now, it's easier). They could also be sent manually. We'll talk more about these two possibilities below.

To understand the step-by-step of how this is done "under the hood", you may find the [section on testing](#testing) a useful read. If you're only interested in "switching on this feature", notice this is not advised on mainnet (see the section on [alternatives to mainnet](#network)), but read more below about editing the config and switching it on in a yieldgenerator.

<a name="pow" />

### Proof of work for mild anti-spam

As implemented here, in fact, the proposer attaches a proof of work in the form of a 10-byte nonce appended to the end of the above string (hex encoded; so in fact: `base64-encoded-ECIES-encrypted-PSBT,hex-encoded-pubkey,hex-encoded-nonce` is what is sent over the wire). This nonce is grinded to get a 32-byte-truncated-hash512 of that string to be less than a target calculated by a request number of bits from the server. The target bits is requested by the proposer with a `GET /target` request to the server, before sending the proposals themselves with a `POST /` request with the proposals in the body. For the proof of work, see `jmbase/jmbase/proof_of_work.py`; it's pretty elementary. Note of course this is no defence against a serious attempt to jam the system, it's only a "script-kiddie-defence", so to speak.

<a name="servers" />

### Servers

The **snicker-server** just hosts the proposals and lets others read them. For the purpose of testing it's fine that we don't have a very sophisticated version of this, but for now note:
* You can run tests using the `-n` option of `create-snicker-proposal.py` to just output to terminal instead of uploading to server; this may be in particular more useful for local tests where it's only your own wallets involved.
* The server serves only over a Tor hidden service.
* It stores the accepted proposals in a sqlite3 database `proposals.db`. The table is `proposals` and has only two fields: `pubkey` and `proposal` (see above).
* Defends against spam with proof of work as per above (this is very limited but better than nothing).
* Currently has NO maintenance or performance feature such as flushing out proposals after a time limit, or allowing filtered queries. This seems the most obvious way to improve what exists, here.

<a name="scripts" />

### New script tools

The new tools for SNICKER are in the directory `scripts/snicker`, consisting of:
* `snicker-seed-tx.py` - create a fake SNICKER transaction in your own wallet.
* `snicker-finder.py` - scan recent blocks for Joinmarket or SNICKER candidate transactions.
* `create-snicker-proposal.py` - takes transactions found from the above and makes proposals, uploading them to a server or outputting to command line.
* `snicker-server.py` - implements a simple server serving over *.onion, with a sqlite database to store proposals, and defends against spam only mildly with a proof of work requirement (see below).
* `receive-snicker.py` - polls above server to read new proposals, parse them and broadcasts completed SNICKER coinjoins when found, storing the new keys as imports (see details on wallet handling below).
* `snicker-recovery.py` - can be used to recover a wallet from seedphrase which contains SNICKER utxos, though it needs (possibly multiple) rescanblockchain calls (and informs the user how to do this, including blockheights).

<a name="configure" />

## Updating config

Recreate your joinmarket.cfg in the usual way. You can then edit the new `[SNICKER]` section as desired:

```
[SNICKER]

# any other value than 'true' will be treated as False,
# and no SNICKER actions will be enabled in that case:
enabled = false

# in satoshis, we require any SNICKER to pay us at least
# this much (can be negative), otherwise we will refuse
# to sign it:
lowest_net_gain = 0

# comma separated list of servers (if port is omitted as :port, it
# is assumed to be 80) which we will poll against (all, in sequence); note
# that they are allowed to be *.onion or cleartext servers, and no
# scheme (http(s) etc) needs to be added to the start.
servers = cn5lfwvrswicuxn3gjsxoved6l2gu5hdvwy5l3ev7kg6j7lbji2k7hqd.onion,

# how many minutes between each polling event to each server above:
polling_interval_minutes = 60
```

Notice that it is of course *NOT* enabled by default, so switch that to `true`.

If you are running tests, a 60 minute polling interval is slow, feel free to cut it down to a minute or two.

The default server is currently running on a VPS. As mentioned above, you can easily run your own server with `snicker-server.py`. It is possible to poll multiple servers, comma separated in the list.

<a name="network" />

## Alternative to mainnet usage

Choosing the network for this function means editing the `[BLOCKCHAIN]` section in `joinmarket.cfg`, just as for other Joinmarket functionality.

**Regtest** is a good option if you are interested in testing functionality quickly, on your own. See [here](TESTING.md) for some info on regtest setup.

**Signet** (a new testnet) will be helpful especially if you intend to test with others. This can be done by simply sharing proposals as per the `-n` comments above, or by sharing proposal server locations as onion addresses, and possibly communicating with other testers to identify candidate transactions (obviously this strays far from the intended way SNICKER will be used, but it is convenient to test workflow).
For more information about using Joinmarket with signet, see the [0.8.1 release notes](release-notes/release-notes-0.8.1.md) and [this gist](https://gist.github.com/AdamISZ/325716a66c7be7dd3fc4acdfce449fb1).

**Testnet3** - it may be possible but it will be far less convenient than signet.

**Mainnet** - as of Feb 2021, this isn't recommended yet; it should in theory work no different, but any usage would be at your own risk.

<a name="receiver" />

## Running SNICKER as a receiver

The **receiver** (unless handling manually with `-n` as per above) polls this server (for testing, you can make the polling loop fast; in real usage it should be slow), reads all the existing proposals using a `GET /` request with no parameters, and if it can decrypt and sanity check the transaction OK, it co-signs it and broadcasts it. Note: *the receiver wallet will store its new coins output from the coinjoin, as imported keys; they are not part of the HD tree, although derivable from history*. See `use of wallets` below for important notes on this aspect.

<a name="manually" />

### Manually running the receiver

For this you can use the `receive-snicker.py` script as detailed above, passing the chosen wallet file as argument, and it will "one-shot" poll for proposals and process them, or, you can pass the base64 proposal manually instead.

<a name="yieldgen" />

### Running SNICKER in a yield generator.

This will presumably be the most normal way to be a SNICKER receiver over time; if `enabled=true` for SNICKER is in the above config settings, this will happen automatically, under the hood. Make sure the polling loop interval is not too fast if you leave this running longer term (even if a test bot). If valid proposals are found that follow our requirements, the transactions are broadcast.

<a name="wallets" />

## Use of wallets

**Wallet type** - please stick with native segwit (`native=true` in config *before* you generate), but you can also choose p2sh-p2wpkh, it should work. No other script type (including p2pkh) will work here. We don't want mixed script type SNICKER coinjoins.

**Persistence in the wallet** - this is very important and not at all obvious! But, on regtest and testnet *by default*, we use hex seeds instead of wallet files and `VolatileStorage` (wallet storage in memory; wiped on shutdown). This is fine and convenient for many tests, but will not work for a key part of SNICKER - imported keys.

The upshot - **make sure you actually generate wallet files for all wallets you're going to test SNICKER with**, otherwise you will not even see the created coins on the receiver side.

Additionally, when you view the wallet with wallet-tool, you need to use `--recoversync`, as the default fast sync won't see imported keys. If you took these two steps, your tests should correctly show the post-SNICKER created coins.

<a name="checking" />

## Checking for SNICKER coinjoins

SNICKER is logged to:

`~/.joinmarket/logs/SNICKER/SNICKER-joinmarket-wallet-xxxxxx.log`

i.e. there is one SNICKER log file for each wallet.
This should show all transactions that were detected and broadcast.

<a name="testing" />

## A testing workflow

This is a scenario for a single user, using either regtest or signet.

Generate a minimum of two joinmarket wallets with `python wallet-tool.py generate`, as noted above, native (or at least, both the same type).

Fund them both. The receiver needs at least two utxos to create the seed transaction.

Create a seed fake-SNICKER transaction in the receiver wallet, using the script `snicker-seed-tx.py`.

Start the test server. Navigate to `scripts/snicker` and run `python snicker-server.py` - no arguments should be needed, and this will generate an onion running serving on port 80; the onion hostname is displayed:

```
(jmvenv) waxwing@here~/testjminstall/joinmarket-clientserver/scripts/snicker$ python snicker-server.py 
User data location: 
Attempting to start onion service on port: 80 ...
Your hidden service is available: 
xpkqk2cy2h2ay5iecwcod5ka36nxj2tsiyczk2w5c6o7h5g57w3xg4id.onion
```

This is ephemeral, obviously we intend the real servers to be long-running. The one in the default config should exist and be long-running already, but of course your tests don't need to rely on this. Add:

```

[SNICKER]
enabled = true
servers= xpkqk2cy2h2ay5iecwcod5ka36nxj2tsiyczk2w5c6o7h5g57w3xg4id.onion,
```
... to a `joinmarket.cfg` that you add inside `scripts/snicker`, by copying it from `scripts/` or wherever you keep your testing `joinmarket.cfg` file. (This manual annoyance is part of testing, it won't be needed in mainnet usage of course ... alternatively just put a signet/regtest custom `joinmarket.cfg` in your `.joinmarket` folder, but this is hardly less annoying).

`servers=` requires a comma separated list.

You're now ready to do the two steps: (a) create a proposal and upload it, (b) download proposals (as the receiver identity/wallet) and complete coinjoins. It could be different people doing (a) and (b) of course but here we're assuming one tester doing everything (see two wallets above).

### Creating one or more proposals

Having done the above seed transaction, do a scan operation to find the candidate:

`cd script/snicker; python snicker-finder.py --datadir=. 330`

Here, 330 is the starting block number on my regtest blockchain; the ending block is the current block. On signet use a block explorer to find current height (or `bitcoin-cli getblockchaininfo`). It will look for all transactions with a SNICKER pattern and you should see returned something like this:

```
2020-12-28 16:09:04,329 [INFO]  Finished processing block: 790
2020-12-28 16:09:04,334 [INFO]  Found SNICKER transaction: 32f80807b3ba4ca477b25e8ab608a8a3134a34c8c3787cad95c653d1805d7533 in block: 791
2020-12-28 16:09:04,338 [INFO]  Finished processing block: 791
2020-12-28 16:09:04,340 [INFO]  Finished processing block: 792
done
```

Then look in `./candidates.txt` to find the details of the identified transaction, including its full hex, which you need to copy:

```
2020-12-16 11:13:01,708 [INFO]  {
    "hex": "0200000000010138e8a90b3df7740b9d5f5ae9af2cf6769f314d290b2e12bf25bfa4aae2c0cbe20000000000feffffff0280ba8c010000000016001471b09afbac6204627225c10f3a8d4a0749364fdb6d7c36220000000016001447ae59f32c504cbb56e18b77f7842fb58b55025b02473044022075354351ad4c619ba662f9abd25e8ee434f8381795001606a29fa959d36aeb7f022018f8bf1ec0407dad586baeb7e4d977aaacbd8fb15579293e6d739ad69ac3c6cf012103f8e827464fb83209c194376c53ae8f4e7ab5f1baf0948705fec6dd421f2b65c37a020000",
    "inputs": [
        .................
Full transaction hex for creating a proposal is found in the above.
The unspent indices are: 0 1 2
```

Copy that fully signed transaction hex, and note the unspent outputs. You're going to assume (in this case correctly of course) that all of the inputs are valid options for the SNICKER public key (why? because it was a *seed* transaction, it was a fake SNICKER, and so all the inputs belonged to the same wallet).

At this point you're ready to run the proposal creator:

```
python create-encrypted-proposal.py --datadir=. proposerwallet.jmdat "0200000000010138e8a90b3df7740b9d5f5ae9af2cf6769f314d290b2e12bf25bfa4aae2c0cbe20000000000feffffff0280ba8c010000000016001471b09afbac6204627225c10f3a8d4a0749364fdb6d7c36220000000016001447ae59f32c504cbb56e18b77f7842fb58b55025b02473044022075354351ad4c619ba662f9abd25e8ee434f8381795001606a29fa959d36aeb7f022018f8bf1ec0407dad586baeb7e4d977aaacbd8fb15579293e6d739ad69ac3c6cf012103f8e827464fb83209c194376c53ae8f4e7ab5f1baf0948705fec6dd421f2b65c37a020000" 0 1 100 -m1 -n
```
Obviously see the `--help` for details, but in this example we chose:

* input index 0 to source the pubkey for the encryption.
* output index 1 for the coin we want the receiver to spend with us in the coinjoin.
* 100 sats as the amount we will bump their output by as an incentive to do the coinjoin (you *can* make this number negative, to receive, instead - the proposer is paying the tx fee otherwise, note).
* mixdepth 1 as the mixdepth from which we source *our* coins for the coinjoin. Make sure of course that mixdepth 1 has at least a little bit more bitcoin than the size of that output at index 1 aforementioned.
* The `-n` option can be used to output the proposal to stdout (it is base64+hex so copy-pasteable).

If you choose not to use -n, but instead use a proposals server as above, then assuming it connects to the server OK, you will see:

```
Response from server: http://xpkqk2cy2h2ay5iecwcod5ka36nxj2tsiyczk2w5c6o7h5g57w3xg4id.onion was: 1 proposals-accepted
```

### Receiving the created proposals.

The last phase is pretty simple, if it works - just run the receiver script (from `scripts/snicker`) as follows:

```
python receive-snicker.py --datadir=. receiver.jmdat [proposal]
User data location: .
2020-12-16 11:43:03,779 [DEBUG]  rpc: getblockchaininfo []
2020-12-16 11:43:03,781 [DEBUG]  rpc: getnewaddress []
Enter passphrase to decrypt wallet: 
2020-12-16 11:43:07,501 [DEBUG]  rpc: listaddressgroupings []
2020-12-16 11:43:07,562 [DEBUG]  Fast sync in progress. Got this many used addresses: 3
2020-12-16 11:43:08,075 [DEBUG]  rpc: listunspent [0]
2020-12-16 11:43:08,216 [DEBUG]  bitcoind sync_unspent took 0.14214825630187988sec
2020-12-16 11:43:08,280 [WARNING]  Cannot listen on port 27183, trying next port
2020-12-16 11:43:08,281 [WARNING]  Cannot listen on port 27184, trying next port
2020-12-16 11:43:08,281 [WARNING]  Cannot listen on port 27185, trying next port
2020-12-16 11:43:08,281 [INFO]  Listening on port 27186
2020-12-16 11:43:08,282 [INFO]  (SNICKER) Listening on port 26186
2020-12-16 11:43:08,282 [INFO]  Starting transaction monitor in walletservice
2020-12-16 11:43:08,339 [INFO]  Starting SNICKER polling loop
2020-12-16 11:43:22,676 [DEBUG]  rpc: sendrawtransaction ['020000000001028ffa6a6f0184ed8123993273ecbb4af82d1b1c0963c815fec4e92525eaba56b30000000000ffffffffa5015509e0e241ef25ee7ccc1936295c908e572cb222105e16c197d66f0599640000000000ffffffff03e4ba8c0100000000160014190ec76b7843f47bc367b65119b98c32074536255dfd5e0a00000000160014d38fa4a6ac8db7495e5e2b5d219dccd412dd9baee4ba8c01000000001600147b4676f859b993257bc8d5880650fcab470db8a1024830450221008480d553177a020f58ca0e45b9e20aa027305a279a3de1014f55ff22909b89b1022054e848285ee60c169b5de19bb4d3637b606ff14bc4cca4506ad05a42fff6af400121029a82a00f05d023f188dfd1db82ef8ec136b0500bbd33bb1f65930c5b74e3199802463043021f01d3f4567c32fc0c5c0cd33db233a3c74100a36940d743b72042b55e60b89d022073ab203ad0fee389f2a2c9e62197244cea95b07ae78a5516ca9f866a8e348d2c01210245d8623c4b06505dffd21bdd314a84b73afe2b9d49a93fe89397b48a85b718bd00000000']
2020-12-16 11:43:22,678 [INFO]  Successfully broadcast SNICKER coinjoin: 33ec857df09030140391529295412434cced8191626024f937426b7859a21947
2020-12-16 11:43:23,359 [INFO]  Removed utxos=
b356baea2525e9c4fe15c863091c1b2df84abbec7332992381ed84016f6afa8f:0 - path: m/84'/1'/4'/0/0, address: bcrt1qwxcf47avvgzxyu39cy8n4r22qaynvn7mc359ap, value: 26000000
2020-12-16 11:43:23,360 [INFO]  Added utxos=
33ec857df09030140391529295412434cced8191626024f937426b7859a21947:0 - path: imported/1/0, address: bcrt1qry8vw6mcg068hsm8keg3nwvvxgr52d3923gg45, value: 26000100
```

Obviously this is the ideal case: if no errors occur. If invalid proposals, or proposals on coins that no longer exist because you already spent them, are encountered, logging messages are displayed to that effect.

If you did choose the `-n` option then you can pass the copy-pasted proposal on the command line and it will just process that instead of polling.

### Other kinds of testing

The above is the baseline workflow. Additionally, you can test:

#### Wallet recovery from seed

This case is already somewhat tricky in Joinmarket, but for the worst possible scenario of only having a seedphrase and no address imports in the wallet and no Joinmarket jmdat file, and having used SNICKER recently and not spent those coins, recovery is particularly tricky (which is why users who enable this feature must be warned that it's very important not to lose the jmdat file). However even in this case full recovery is possible, using the script `snicker-recovery.py`. To fully test this try making multiple SNICKER transactions in a wallet, then deleting the jmdat and creating a new Core wallet (on the same regtest instance of course!), enabling it in joinmarket.cfg, then running `wallet-tool.py recover` with the seedphrase, then running the aforementioned snicker recovery script; it will prompt you to `rescanblockchain` from certain heights, potentially more than once; the reason for this is that Core cannot find arbitrarily the transactions which spend custom keys which we discover during wallet recovery, we need to import and rescan before going to the next step, although this will only be an edge case.

<a name="appendix1" />

## Appendix: Example SNICKER transaction

This is what is produced by `print(jmbitcoin.human_readable_transaction(jmbitcoin.CTransaction.deserialize(jmbase.hextobin('020000000001028ffa6a6f0184ed8123993273ecbb4af82d1b1c0963c815fec4e92525eaba56b30000000000ffffffffa5015509e0e241ef25ee7ccc1936295c908e572cb222105e16c197d66f0599640000000000ffffffff03e4ba8c0100000000160014190ec76b7843f47bc367b65119b98c32074536255dfd5e0a00000000160014d38fa4a6ac8db7495e5e2b5d219dccd412dd9baee4ba8c01000000001600147b4676f859b993257bc8d5880650fcab470db8a1024830450221008480d553177a020f58ca0e45b9e20aa027305a279a3de1014f55ff22909b89b1022054e848285ee60c169b5de19bb4d3637b606ff14bc4cca4506ad05a42fff6af400121029a82a00f05d023f188dfd1db82ef8ec136b0500bbd33bb1f65930c5b74e3199802463043021f01d3f4567c32fc0c5c0cd33db233a3c74100a36940d743b72042b55e60b89d022073ab203ad0fee389f2a2c9e62197244cea95b07ae78a5516ca9f866a8e348d2c01210245d8623c4b06505dffd21bdd314a84b73afe2b9d49a93fe89397b48a85b718bd00000000'))))`:

```
{
    "hex": "02000000000102578770b2732aed421ffe62d54fd695cf281ca336e4f686d2adbb2e8c3bedb2570000000000ffffffff4719a259786b4237f92460629181edcc3424419592529103143090f07d85ec330100000000ffffffff0324fd9b0100000000160014d38fa4a6ac8db7495e5e2b5d219dccd412dd9bae24fd9b0100000000160014564aead56de8f4d445fc5b74a61793b5c8a819667af6c208000000001600146ec55c2e1d1a7a868b5ec91822bf40bba842bac502473044022078f8106a5645cc4afeef36d4addec391a5b058cc51053b42c89fcedf92f4db1002200cdf1b66a922863fba8dc1b1b1a0dce043d952fa14dcbe86c427fda25e930a53012102f1f750bfb73dbe4c7faec2c9c301ad0e02176cd47bcc909ff0a117e95b2aad7b02483045022100b9a6c2295a1b0f7605381d416f6ed8da763bd7c20f2402dd36b62dd9dd07375002207d40eaff4fc6ee219a7498abfab6bdc54b7ce006ac4b978b64bff960fbf5f31e012103c2a7d6e44acdbd503c578ec7d1741a44864780be0186e555e853eee86e06f11f00000000",
    "inputs": [
        {
            "outpoint": "57b2ed3b8c2ebbadd286f6e436a31c28cf95d64fd562fe1f42ed2a73b2708757:0",
            "scriptSig": "",
            "nSequence": 4294967295,
            "witness": "02473044022078f8106a5645cc4afeef36d4addec391a5b058cc51053b42c89fcedf92f4db1002200cdf1b66a922863fba8dc1b1b1a0dce043d952fa14dcbe86c427fda25e930a53012102f1f750bfb73dbe4c7faec2c9c301ad0e02176cd47bcc909ff0a117e95b2aad7b"
            },
        {
            "outpoint": "33ec857df09030140391529295412434cced8191626024f937426b7859a21947:1",
            "scriptSig": "",
            "nSequence": 4294967295,
            "witness": "02483045022100b9a6c2295a1b0f7605381d416f6ed8da763bd7c20f2402dd36b62dd9dd07375002207d40eaff4fc6ee219a7498abfab6bdc54b7ce006ac4b978b64bff960fbf5f31e012103c2a7d6e44acdbd503c578ec7d1741a44864780be0186e555e853eee86e06f11f"
        }
        ],
    "outputs": [
        {
            "value_sats": 27000100,
            "scriptPubKey": "0014d38fa4a6ac8db7495e5e2b5d219dccd412dd9bae",
            "address": "bc1q6w86ff4v3km5jhj79dwjr8wv6sfdmxaw2dytjc"
            },
        {
            "value_sats": 27000100,
            "scriptPubKey": "0014564aead56de8f4d445fc5b74a61793b5c8a81966",
            "address": "bc1q2e9w44tdar6dg30utd62v9unkhy2sxtxtqrthh"
            },
        {
            "value_sats": 146994810,
            "scriptPubKey": "00146ec55c2e1d1a7a868b5ec91822bf40bba842bac5",
            "address": "bc1qdmz4ctsarfagdz67eyvz906qhw5y9wk9dqpuea"
        }
        ],
    "txid": "ca606efc5ba8f6669ba15e9262e5d38e745345ea96106d5a919688d1ff0da0cc",
    "nLockTime": 0,
    "nVersion": 2
}
```

