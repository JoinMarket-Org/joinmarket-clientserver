# HOW TO SETUP ONION MESSAGE CHANNELS IN JOINMARKET

1. [Overview](#overview)

2. [Testing, configuring for signet](#testing-and-configuring-for-signet)

3. [Directory nodes](#directory-nodes)

## Overview

This is a new way for Joinmarket bots to communicate, namely by serving and connecting to Tor onion services.

The purpose of this new type of message channel is as follows:

* less reliance on any service external to Joinmarket
* most of the transaction negotiation will be happening directly peer to peer, not passed over a central server (
albeit it was and remains E2E encrypted data, in either case)
* the above can lead to better scalability at large numbers
* a substantial increase in the speed of transaction negotiation; this is mostly related to the throttling of high bursts of traffic on IRC

### Tor

As of Joinmarket 0.9.6, which introduces this feature, **Tor is now a requirement to run Joinmarket** (except in testing, which will not be explained here). See [here](./tor.md) for more information about this).

(Note however that taker bots will *not* be required to serve onions; they will only make outbound SOCKS connections, as they currently do on IRC).

The configuration for a user is simple; in their `joinmarket.cfg` they will get a new `[MESSAGING]` section like this, if they start from scratch:

```ini
[MESSAGING:onion]
# onion based message channels must have the exact type 'onion'
# (while the section name above can be MESSAGING:whatever), and there must
# be only ONE such message channel configured (note the directory servers
# can be multiple, below):
type = onion

socks5_host = localhost
socks5_port = 9050

# the tor control configuration.
# for most people running the tor daemon
# on Linux, no changes are required here:
tor_control_host = localhost
# or, to use a UNIX socket
# tor_control_host = unix:/var/run/tor/control
# note: port needs to be provided (but is ignored for UNIX socket)
tor_control_port = 9051

# the host/port actually serving the hidden service
# (note the *virtual port*, that the client uses,
# is hardcoded to as per below 'directory node configuration'.
onion_serving_host = 127.0.0.1
onion_serving_port = 8080

# directory node configuration
#
# This is mandatory for directory nodes (who must also set their
# own *.onion:port as the only directory in directory_nodes, below),
# but NOT TO BE USED by non-directory nodes (which is you, unless
# you know otherwise!), as it will greatly degrade your privacy.
# (note the default is no value, don't replace it with "").
hidden_service_dir =
#
# This is a comma separated list (comma can be omitted if only one item).
# Each item has format host:port ; both are required, though port will
# be 5222 if created in this code.
# for MAINNET:
directory_nodes = 3kxw6lf5vf6y26emzwgibzhrzhmhqiw6ekrek3nqfjjmhwznb2moonad.onion:5222,qqd22cwgygaxcy6vdw6mzwkyaxg5urb4ptbc5d74nrj25phspajxjbqd.onion:5222

# for SIGNET (testing network):
# directory_nodes = rr6f6qtleiiwic45bby4zwmiwjrj3jsbmcvutwpqxjziaydjydkk5iad.onion:5222,k74oyetjqgcamsyhlym2vgbjtvhcrbxr4iowd4nv4zk5sehw4v665jad.onion:5222

# This setting is ONLY for developer regtest setups,
# running multiple bots at once. Don't alter it otherwise
regtest_count = 0,0

```

All of these can be left as default for most users - but most importantly, pay attention to:

* The list of `directory_nodes`, which will be comma separated if multiple directory nodes are configured (we expect there will be 2 or 3 as a normal situation). Make sure to choose the ones for your network (mainnet by default, or signet or otherwise); if it's wrong your bot will just get auto-disconnected.
* The `onion_serving_port` is the port on the local machine on which the onion service is served; you won't usually need to use it, but it mustn't conflict with some other usage (so if you have something running on port 8080, change it).
The `type` field must always be `onion` in this case, and distinguishes it from IRC message channels and others.

### Can/should I still run IRC message channels?

In short, yes, at least for now, though you are free to disable any message channel you like.

### Do I need to configure Tor, and if so, how?

To make outbound Tor connections to other onions in the network, you will need to configure the
SOCKS5 proxy settings (so, only directory nodes may *not* need this; everyone else does).
This is identical to what we already do for IRC, except that in this case, we disallow clearnet connections.

#### Running/testing as a maker

A maker will additionally allow *inbound* connections to an onion service.
This onion service will be ephemeral, that is, it will have a different onion address every time
you restart. This should work automatically, using your existing Tor daemon (here, we are using
the same code as we use when running the `receive-payjoin` script, essentially).

#### Running/testing as other bots (taker, ob-watcher)

A taker will not attempt to serve an onion; it will only use outbound connections, first to directory
nodes and then, as according to need, to individual makers, also.

As previously mentioned, both of these features - inbound and outbound, to onion, Tor connections - were already in use in Joinmarket. If you want to run/test as a maker bot, but never served an onion service before, it should work fine as long as you have the Tor service running in the background,
and the default control port 9051 (if not, change that value in the `joinmarket.cfg`, see above).

### Why not use Lightning based onions?

(*Feel free to skip this section if you don't know what "Lightning based onions" refers to!*). The reason this architecture is
proposed as an alternative to the previously suggested Lightning-node-based network (see
[this PR](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/1000)), is mostly that:

* the latter has a bunch of extra installation and maintenance dependencies (just one example: pyln-client requires coincurve, which we just
removed)
* the latter requires establishing a new node "identity" which can be refreshed, but that creates more concern
* longer term ideas to integrate Lightning payments to the coinjoin workflow (and vice versa!) are not realizable yet
* using multi-hop onion messaging in the LN network itself is also a way off, and a bit problematic

So the short version is: the Lightning based alternative is certainly feasible, but has a lot more baggage that can't really be justified
unless we're actually using it for something.

## Testing and configuring for signet

This testing section focuses on signet since that will be the less troublesome way of getting involved in tests for
the non-hardcore JM developer :)

(For the latter, please use the regtest setup by running `test/e2e-coinjoin-test.py` under `pytest`,
and pay attention to the settings in `regtest_joinmarket.cfg`.)

There is no separate/special configuration for signet other than the configuration that is already needed for running
Joinmarket against a signet backend (so e.g. RPC port of 38332).

You can just uncomment the `directory_nodes` entry listed as SIGNET, and comment out the one for MAINNET.

Then just make sure your bot has some signet coins and try running as maker or taker or both.

## Directory nodes

**This last section is for people with a lot of technical knowledge in this area,
who would like to help by running a directory node. You can ignore it if that does not apply.**.

This requires a long running bot. It should be on a server you can keep running permanently, so perhaps a VPS,
but in any case, very high uptime. For reliability it also makes sense to configure to run as a systemd service.

The currently suggested way to run a directory node is to use the [`start-dn.py` script](https://github.com/JoinMarket-Org/custom-scripts/blob/master/start-dn.py); you can place it in your `joinmarket-clientserver/scripts` directory and run it with a message argument to be sent as part of the connection handshake, for example: 'Greetings from Directory Node' and one option flag: `--datadir=/your/chosen/datadir` (as you'll see below).

This slightly unobvious approach is based on the following ideas: we run a Joinmarket script, with a Joinmarket python virtual environment, so that we are able to parse messages; this means that the directory node *can* be a bot, e.g. a maker bot, but need not be - and here it is basically a "crippled" maker bot that cannot do anything. This 'crippling' is actually very useful because (a) we use the `no-blockchain` argument (it is forced in-code; you don't need to set it) so we don't need a running Bitcoin node (of whatever flavour), and (b) we don't need a wallet either.

### Joinmarket-specific configuration

Add a non-empty `hidden_service_dir` entry to your `[MESSAGING:onion]` with a directory accessible to your user, with permissions set to `700` on Unix-like OS. Be careful changing permissions from what is created by the script, because Tor is very finicky about this.

The hostname for your onion service will not change and will be stored permanently in that directory.

The point to understand is: Joinmarket's `jmbase.JMHiddenService` will, if configured with a non-empty `hidden_service_dir`
field, actually start an *independent* instance of Tor specifically for serving this, under the current user.
(our Tor interface library `txtorcon` needs read access to the Tor HS dir, so it's troublesome to do this another way).

#### Question: How to configure the `directory-nodes` list in our `joinmarket.cfg` for this directory node bot?

Answer: **you must only enter your own node in this list!**. This way your bot will recognize that it is a directory node and it avoids weird edge case behaviour (so don't add *other* known directory nodes; you won't be talking to them).

A natural retort is: but I don't know my own node's onion service hostname before I start it the first time. Indeed. So, just run it once with the default `directory_nodes` entries, then note down the new onion service hostname you created, and insert that as the only entry in the list.

### Suggested setup of a systemd service

The most basic bare-bones service seems to work fine here:

```ini
[Unit]
Description=My JM signet directory node
Requires=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'cd /path/to/joinmarket-clientserver && source jmvenv/bin/activate && cd scripts && python start-dn.py 'Greetings from Directory Node' --datadir=/path/to/chosen/datadir'
User=user
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

... however, you need to kind of 'bootstrap' it the first time. For example:

* run once with systemctl start

* look at log with `journalctl`, service fails due to default `joinmarket.cfg` and quit.
* go to that cfg file. Remove the IRC settings, they serve no purpose here. Change the `hidden_service_dir` to `/yourlocation/hidserv` (the actual directory need not exist, it's better if it doesn't, this first time). Edit the `network` field in `BLOCKCHAIN` to whatever network (mainnet, signet) you intend to support - it can be only one for one directory node, for now.

* `systemctl start` again, now note the onion hostname created from the log or the directory

* set that hostname in `directory_nodes` in `joinmarket.cfg`

* now the service should start correctly

## TODO

- add some material on network hardening/firewalls here, I guess.
