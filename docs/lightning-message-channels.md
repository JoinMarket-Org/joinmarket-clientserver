# HOW TO SETUP LIGHTNING MESSAGE CHANNELS IN JOINMARKET

### Contents

1. [Purpose](#purpose)

2. [Installing c-lightning bundled, or using your pre-existing c-lightning.](#install)

   i. [Choice B: bundled](#choiceb)

   ii. [Choice A: non-bundled](#choicea)

3. [Configure for signet](#signet)

4. [Directory nodes](#directory)

<a name="purpose" />

## Purpose

You can skip this whole section if you just want to install the software and run it.

The discussion of "more decentralized than just using IRC servers", for Joinmarket, has been ongoing for years and in particular the most recent extended discussion is to be found in [this issue thread](https://github.com/JoinMarket-Org/joinmarket-clientserver/issues/415).

Why Lightning and not just Tor? We gain a few things:

* We can make connections between messaging and payments, or between actual coinjoins and Lightning payments. Neither of these probably works in the *simplest* way imaginable, but with a little sophistication this could be *tremendously* powerful (an obvious example: directory nodes could charge for their service on a per-message basis, not using Lightning payments inside the message flow, which is too slow, but based on Chaumian token issuance against earlier Lightning payments).
* By using a plugin to a c-lightning node, we leverage the high quality, high performance of their C code to do a lot of heavy lifting. Passing messages over hops, using onion routing, is intrinsic to what their codebase has to provide (including, over Tor), so if in future we use the `sendonionmessage` between our nodes, we make use of that benefit. For now we use the `sendcustommsg` feature which allows individual maker/taker bots to communicate directly, improving both the scalability and privacy of the coinjoin negotiations (though this is done opportunistically - falling back to E2E encrypted communications via the directory server, where the direct communication isn't possible).
* There is an overlap in concept between *coinjoins* and *dual funding* in Lightning, since technically the latter *is* a class of the former. A natural question arises, hopefully one that can be answered over time: can we integrate Joinmarket style coinjoins into the dual funding process, or perhaps also single funding (some of this interacts with taproot, of course, so it's not a simple matter). Also related is recent work by @niftynei on "liquidity advertising", see e.g. [here](https://medium.com/blockstream/setting-up-liquidity-ads-in-c-lightning-54e4c59c091d).

(c-lightning's [plugin architecture](https://lightning.readthedocs.io/PLUGINS.html) is a big part of what makes this relatively easy to implement; it means we have a very loose coupling via a simple plugin that forwards messages and notifications from the c-lightning node to joinmarket's jmdaemon, which is able to use it as "just another way of passing messages", basically).


<a name="install" />

## Installing c-lightning bundled, or using your pre-existing c-lightning.

If you are an existing user of Joinmarket, your choice here is:

A. Use a c-lightning separately installed (which could be in use for payments, already, i.e. an active Lightning node), or:

B. to let Joinmarket compile, build and install a "bundled" instance of c-lightning, inside Joinmarket itself (which will therefore be a pure networking/messaging component, not doing any payments, at least for now).

Choice A is probably more flexible and "cleaner", over the long term, assuming you actually use Lightning for anything, or will do in future.

Choice B is easier and requires less setup.

<a name="choiceb" />

### Choice B: bundled

(B is first because it's easier!).

If you are running this for the first time you need to go through a full install of Joinmarket using:

```
a@b:/path/to/joinmarket-clientserver$ ./install.sh --with-ln-messaging
```

and then follow the installation process as normal; note that it warns you that the c-lightning bundling isn't necessary, but go ahead and accept, because that's your choice here. As usual with this install process, don't forget the final step of activating the virtualenv. To be absolutely clear: the `--with-ln-messaging` flag will *compile* and install an instance of [c-lightning](https://github.com/ElementsProject/lightning), locally (see below for where).

Before starting up a coinjoin bot, examine the new config section which can be created by running `python wallet-tool.py somewallet.jmdat` as usual with your current `joinmarket.cfg` backed up to a different file name. You should see this new section:

```
[MESSAGING:lightning1]
type = ln-onion
# Setting this .. <snipped comments>
clightning-location = bundled
# or (check your user has access rights):
# clightning-location = /home/username/.lightning/bitcoin/lightning-rpc
# This is a comma separated list (comma can be omitted if only one item).
# Each item has format pubkey@host:port ; all are required. Host can be
# a *.onion address (tor v3 only).
directory-nodes = 033e65b76c4a3c0b907fddbc57822dbff1cf7ce48d341b8cfaf11bd324ea2d433d@45ojrjlrl2wh6yrnihlb2kl6    k752sonptt2rpuv4shbob7ubxkdcmdqd.onion:9736
passthrough-port = 49101
lightning-port = 9735
```

Notice that the `clightning-location = bundled` line is active (not commented out).

The section name "lightning1" is not important, as this MESSAGING section is identified by its type `ln-onion`; there should be **only one such** (see below on directory-nodes - that's how we configure redundancy here, if desired). Apart from setting the directory nodes, there is usually no need to change the port settings, unless you are testing and want multiple bots running simultaneously; then, just make sure that `passthrough-port` values do not conflict.

#### Tor setup.

Read through the introductory section on setting up c-lightning for Tor hidden/onion services [here](https://lightning.readthedocs.io/TOR.html#quick-start-on-linux); from the start of that subsection to the paragraph "If the above prints nothing and returns, then C-Lightning “should” work with your Tor." These steps will serve to ensure that your Tor is configured to allow c-lightning to use it. The rest of that document is not needed as it's handled by Joinmarket automatically.

#### OK, c-lightning is setup automatically, when 'bundled'; that's great, but where?

First, the compiled binaries are in `joinmarket-clientserver/jmvenv/{bin,libexec}`. Second, the `lightning-dir` is set to `<jmdatadir>/lightning`, so that you will find it by default in `~/.joinmarket/lightning/config`. Given this consideration you might, in certain use cases, prefer to use a manually set separate joinmarket datadir, e.g. `python yg-privacyenhanced.py --datadir=/some/custom/location mywallet.jmdat`; remember this changes the location of all Joinmarket data too, including `joinmarket.cfg` and `wallets/`.

<a name="choicea" />

### Choice A: non-bundled

This section won't explain how to [install c-lightning](https://github.com/ElementsProject/lightning). The current supported version is 0.10.2. Earlier versions may work but are not tested. Please use their existing excellent [documentation](https://github.com/ElementsProject/lightning/blob/master/doc/INSTALL.md) on how to install it, if necessary, before continuing.

#### Config specific for Joinmarket.

Lightning's own config by default is in `~/.lightning/config`. If you haven't already set one, do so now and here is an example that works fine for Joinmarket, on signet:

```
bitcoin-rpcconnect=127.0.0.1
bitcoin-rpcport=38332
bitcoin-rpcuser=bitcoinrpc
bitcoin-rpcpassword=123456abcdef
signet
proxy=127.0.0.1:9050
bind-addr=127.0.0.1:9736
addr=statictor:127.0.0.1:9051/torport=9736
always-use-proxy=true
```

The first part is orthogonal to JM, since you always need to configure your Bitcoin Core RPC to run anyway. The last 4 lines are how to set up the config to serve via an onion service on Tor, with default Tor control port, and in this case, specifying your Lightning-serving port as `9736`.

In Joinmarket's config file, though, you must specify:

```
clightning-location = /home/username/.lightning/bitcoin/lightning-rpc
```

instead of the default value `bundled`; this tells Joinmarket how it can connect to Lightning's socket rpc file. Here `bitcoin` would be replaced with `signet` if you wanted to match the above example.

You must also make sure the ports match: the `lightning-port` field in the `joinmarket.cfg` must correspond to your own c-lightning node, and the `passthrough-port` must be set as per the below subsection:

#### Running lightningd with the jmcl.py plugin

You must start or restart c-lightning with the following command line arguments (or dynamically load; see the [docs](https://lightning.readthedocs.io/PLUGINS.html#)):

```
lightningd --plugin=/path/to/joinmarket-clientserver/jmdaemon/jmdaemon/jmcl.py --jmport=49100
```

Other arguments are not specified here; either not needed because in the `config` file, or they are specific to your use case. Most important: the value specified here as `jmport` is exactly the port specified in `joinmarket.cfg` as `passthrough-port`. That's what allows c-lightning to talk to our Joinmarket messaging daemon.

<a name="signet" />

## Configure for signet.

There is no separate/special configuration for signet other than the configuration that is already needed for running Joinmarket against a signet backend (so e.g. RPC port of 38332). The correct configuration will automatically be ported into your embedded c-lightning instance. If you want to help with testing, please setup either regtest or signet.

<a name="directory" />

## Directory nodes

### As a non-directory nodes

Enter the directory nodes you want to use in `joinmarket.cfg` as per above, comma separated. They must always be pubkey@host:port, whether onion or not. Or just keep the defaults you are given. The default currently as of Oct 2021 is a signet serving directory node (see above default config).

### As a directory node.

**This last section is for people with a lot of technical knowledge in this area, who would like to help by running a directory node. You can ignore it if that does not apply.**.

This requires a long running bot. It should be on a server you can keep running permanently, so perhaps a VPS, but in any case, very high uptime. For reliability it also makes sense to configure to run as a systemd service.

A note: in this early stage, the usage of Lightning is only really network-layer stuff, and the usage of bitcoin, is none; feel free to add elements that remove any need for a backend bitcoin blockchain, but beware: future upgrades *could* mean that the directory node really does need the bitcoin backend.

#### Joinmarket-specific configuration

There is one change required: in `jmclient.configure.start_ln`, where the `lnconfiglines` are written, change from `autotor` to `statictor` (you can keep the entire rest of the configuration the same. This means that every time you restart you will use the same `.onion` address, which is of course necessary here. Further, make this `.onion` (in the correct pubkey@host:port format) be the only entry in `directory-nodes` in your Joinmarket.cfg. When you start up you will see a message `this is the genesis node` which will confirm to you that you are running as a directory. (Note, this will change to be more flexible shortly, probably with a specific config flag).

##### Question: How to configure the `directory-nodes` list in our `joinmarket.cfg` for this directory node bot?

Answer: **you must only enter your own node in this list!** (otherwise you may find your bot infinitely rebroadcasting messages).

#### Question: Bundled or not?

(See above in this document for what 'bundled' means here and how to configure). Answer: It should work both ways.

#### Suggested setup of a service:

You will need three components: bitcoind, lightningd (i.e. c-lightning) and Joinmarket itself. Since this task is going to be attempted by someone with significant technical knowledge, only an outline is provided here; several details will need to be filled in. Here is a sketch of how the systemd service files can be set up for signet:

If someone wants to put together a docker setup of this for a more "one-click install", that would be great.

1. bitcoin-signet.service

```
[Unit]
Description=bitcoind signet
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/bitcoind -signet
User=user

[Install]
WantedBy=multi-user.target
```

This is deliberately a super-basic setup (see above). Don't forget to setup your `bitcoin.conf` as usual, for the bitcoin user, and make it match (specifically in terms of RPC) what you set up for Lightning below.

2. ln-signet.service

```
[Unit]
Description=c-lightning on signet daemon with joinmarket plugin
Requires=bitcoin-signet.service
After=bitcoin-signet.service

[Service]
ExecStart=/usr/local/bin/lightningd --conf=/home/user/.lightning/config --plugin=/path/to/joinmarket-clientserver/jmdaemon/jmdaemon/jmcl.py --jmport=49100
Type=simple
User=user

[Install]
WantedBy=multi-user.target
```

The above is for a non-bundled c-lightning. Make sure to populate `/home/user/.lightning/config` appropriately in this case (see above in this doc for what it should contain).

3.

```
[Unit]
Description=joinmarket directory node on signet
Requires=ln-signet.service
After=ln-signet.service

[Service]
Type=simple
ExecStart=/bin/bash -c 'cd /path/to/joinmarket-clientserver && source jmvenv/bin/activate && cd scripts && echo -n "password" | python yg-privacyenhanced.py --wallet-password-stdin --datadir=/custom/joinmarket-datadir some-signet-wallet.jmdat'
User=user

[Install]
WantedBy=multi-user.target
```

To state the obvious, the idea here is that this last service will run the JM directory node and have a dependency on the previous two, to ensure they start up in the correct order.

Re: password echo, obviously this kind of password entry is bad; for now we needn't worry as these nodes don't need to carry any real coins (and it's better they don't!). Later we may need to change that (though of course you can use standard measures to protect the box).

TODO: add some material on network hardening/firewalls here, I guess.
