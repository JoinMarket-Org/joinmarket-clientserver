# HOW TO SETUP LIGHTNING MESSAGE CHANNELS IN JOINMARKET

### Contents

1. [Purpose](#purpose)

2. [Installing; checking your config and Tor setup](#config)

3. [Configure for signet](#signet)

4. [Directory nodes](#directory)

<a name="purpose" />

## Purpose

You can skip this whole section if you just want to install the software and run it.

The discussion of "more decentralized than just using IRC servers", for Joinmarket, has been ongoing for years and in particular the most recent extended discussion is to be found in [this issue thread](https://github.com/JoinMarket-Org/joinmarket-clientserver/issues/415).

Why Lightning and not just Tor? We gain a few things:

* We can make connections between messaging and payments, or between actual coinjoins and Lightning payments. Neither of these probably works in the *simplest* way imaginable, but with a little sophistication this could be *tremendously* powerful (an obvious example: directory nodes could charge for their service on a per-message basis, not using Lightning payments inside the message flow, which is too slow, but based on Chaumian token issuance against earlier Lightning payments).
* By using a plugin to a c-lightning node, we leverage the high quality, high performance of their C code to do a lot of heavy lifting. Passing messages over hops, using onion routing, is intrinsic to what their codebase has to provide (including, over Tor), so if we use the `sendonionmessage` between our nodes, we make use of that benefit.
* There is an overlap in concept between *coinjoins* and *dual funding* in Lightning, since technically the latter *is* a class of the former. A natural question arises, hopefully one that can be answered over time: can we integrate Joinmarket style coinjoins into the dual funding process, or perhaps also single funding (some of this interacts with taproot, of course, so it's not a simple matter). Also related is recent work by @niftynei on "liquidity advertising", see e.g. [here](https://medium.com/blockstream/setting-up-liquidity-ads-in-c-lightning-54e4c59c091d).

(c-lightning's [plugin architecture](https://lightning.readthedocs.io/PLUGINS.html) is a big part of what makes this relatively easy to implement; it means we have a very loose coupling via a simple plugin that forwards messages and notifications from the c-lightning node to joinmarket's jmdaemon, which is able to use it as "just another way of passing messages", basically).


<a name="config" />

## Installing; checking your config and Tor setup.

If you are running this for the first time you need to go through a full install of Joinmarket using:

```
a@b:/path/to/joinmarket-clientserver$ ./install.sh --with-ln-messaging
```

and then follow the installation process as normal, including the final activation of the virtualenv. The `with-ln-messaging` flag will *compile* and install an instance of [c-lightning](https://github.com/ElementsProject/lightning) (the reason it must be compiled is that we use a currently experimental feature (onion messaging) not enabled in the release).

Before starting up a coinjoin bot, examine the new config section which can be created by running `python wallet-tool.py somewallet.jmdat` as usual with your current `joinmarket.cfg` backed up to a different file name. You should see this new section:

```
[MESSAGING:lightning1]
type = ln-onion
# This is a comma separated list (comma can be omitted if only one item).
# Each item has format pubkey@host:port ; all are required. Host can be
# a *.onion address (tor v3 only).
directory-nodes = 0344bc51c0b0cf58ebfee222bdd8ff4855ac3becd7a9c8bff8ff08100771179047@mvm5ffyipzf4tis2g753w7q25evcqmvj6qnnwgr3dkpyukomykzvwuad.onion:9736
passthrough-port = 49101
lightning-port = 9735
```

The section name "lightning1" is not important, as this MESSAGING section is identified by its type `ln-onion`; there should be only one such (see below on directory-nodes - that's how we configure redundancy here, if desired). Apart from setting the directory nodes, there is usually no need to change the port settings, unless you are testing and want multiple bots running simultaneously; then, just make sure that `passthrough-port` values do not conflict.

### Tor setup.

Read through the introductory section on setting up c-lightning for Tor hidden/onion services [here](https://lightning.readthedocs.io/TOR.html#quick-start-on-linux); from the start of that subsection to the paragraph "If the above prints nothing and returns, then C-Lightning “should” work with your Tor." These steps will serve to ensure that your Tor is configured to allow c-lightning to use it. The rest of that document is not needed as it's handled by Joinmarket automatically.

### OK, c-lightning is setup automatically; that's great, but where?

First, the compiled binaries are in `joinmarket-clientserver/jmvenv/{bin,libexec}`. Second, the `lightning-dir` is set to `<jmdatadir>/lightning`, so that you will find it by default in `~/.joinmarket/lightning/config`. Given this consideration you might, in certain use cases, prefer to use a manually set separate joinmarket datadir, e.g. `python yg-privacyenhanced.py --datadir=/some/custom/location mywallet.jmdat`; remember this changes the location of all Joinmarket data too, including `joinmarket.cfg` and `wallets/`.

<a name="signet" />

## Configure for signet.

There is no separate/special configuration for signet other than the configuration that is already needed for running Joinmarket against a signet backend (so e.g. RPC port of 38332). The correct configuration will automatically be ported into your embedded c-lightning instance.

<a name="directory" />

## Directory nodes

### As a non-directory nodes

Enter the directory nodes you want to use in `joinmarket.cfg` as per above, comma separated. They must always be pubkey@host:port, whether onion or not. Or just keep the defaults you are given. The default currently as of Oct 2021 is a signet serving directory node.

### As a directory node.

This requires a long running bot, best on some VPS or other reliable setup. There is one change required: in `jmclient.configure.start_ln`, where the `lnconfiglines` are written, change from `autotor` to `statictor` (you can keep the entire rest of the configuration the same. This means that every time you restart you will use the same `.onion` address, which is of course necessary here. Further, make this `.onion` (in the correct pubkey@host:port format) be the only entry in `directory-nodes` in your Joinmarket.cfg. When you start up you will see a message `this is the genesis node` which will confirm to you that you are running as a directory. (Note, this will change to be more flexible shortly, probably with a specific config flag).
