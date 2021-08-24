# HOW TO SETUP ONION MESSAGE CHANNELS IN JOINMARKET

### Contents

1. [Overview](#overview)

2. [Testing, configuring for signet](#testing)

4. [Directory nodes](#directory)

<a name="overview" />

## Overview

This is a new way for Joinmarket bots to communicate, namely by serving and connecting to Tor onion services. This does not
introduce any new requirements to your Joinmarket installation, technically, because the use of Payjoin already required the need
to service such onion services, and connecting to IRC used a SOCKS5 proxy (by default, and used by almost all users) over Tor to
a remote onion service.

The purpose of this new type of message channel is as follows:

* less reliance on any service external to Joinmarket
* most of the transaction negotiation will be happening directly peer to peer, not passed over a central server (
albeit it was and remains E2E encrypted data, in either case)
* the above can lead to better scalability at large numbers
* a substantial increase in the speed of transaction negotiation; this is mostly related to the throttling of high bursts of traffic on IRC

The configuration for a user is simple; in their `joinmarket.cfg` they will add a messaging section like this:

```
[MESSAGING:onion1]
type = onion
onion_serving_port = 8082 
# This is a comma separated list (comma can be omitted if only one item).
# Each item has format host:port
directory_nodes = rr6f6qtleiiwic45bby4zwmiwjrj3jsbmcvutwpqxjziaydjydkk5iad.onion:80
```

Here, I have deliberately omitted the several other settings in this section which will almost always be fine as default;
see `jmclient/jmclient/configure.py` for what those defaults are, and the extensive comments explaining.

The main point is the list of **directory nodes** (the one shown here is one being run on signet, right now), which will
be comma separated if multiple directory nodes are configured (we expect there will be 2 or 3 as a normal situation).
The `onion_serving_port` is on which port on the local machine the onion service is served.
The `type` field must always be `onion` in this case, and distinguishes it from IRC message channels and others.

### Can/should I still run IRC message channels?

In short, yes.

### Do I need to configure Tor, and if so, how?

These message channels use both outbound and inbound connections to onion services (or "hidden services").

As previously mentioned, both of these features were already in use in Joinmarket. If you never served an
onion service before, it should work fine as long as you have the Tor service running in the background,
and the default control port 9051 (if not, change that value in the `joinmarket.cfg`, see above.

#### Why not use Lightning based onions?

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


<a name="testing" />

## Testing, and configuring for signet.

This testing section focuses on signet since that will be the less troublesome way of getting involved in tests for
the non-hardcore JM developer :)

(For the latter, please use the regtest setup by running `test/e2e-coinjoin-test.py` under `pytest`,
and pay attention to the settings in `regtest_joinmarket.cfg`.)

There is no separate/special configuration for signet other than the configuration that is already needed for running
Joinmarket against a signet backend (so e.g. RPC port of 38332).

Add the `[MESSAGING:onion1]` message channel section to your `joinmarket.cfg`, as listed above, including the
signet directory node listed above (rr6f6qtleiiwic45bby4zwmiwjrj3jsbmcvutwpqxjziaydjydkk5iad.onion:80), and,
for the simplest test, remove the other `[MESSAGING:*]` sections that you have.

Then just make sure your bot has some signet coins and try running as maker or taker or both.

<a name="directory" />

## Directory nodes

**This last section is for people with a lot of technical knowledge in this area,
who would like to help by running a directory node. You can ignore it if that does not apply.**.

This requires a long running bot. It should be on a server you can keep running permanently, so perhaps a VPS,
but in any case, very high uptime. For reliability it also makes sense to configure to run as a systemd service.

A note: in this early stage, the usage of Lightning is only really network-layer stuff, and the usage of bitcoin, is none; feel free to add elements that remove any need for a backend bitcoin blockchain, but beware: future upgrades *could* mean that the directory node really does need the bitcoin backend.

#### Joinmarket-specific configuration

Add `hidden_service_dir` to your `[MESSAGING:onion1]` with a directory accessible to your user. You may want to lock this down
a bit!
The point to understand is: Joinmarket's `jmbase.JMHiddenService` will, if configured with a non-empty `hidden_service_dir`
field, actually start an *independent* instance of Tor specifically for serving this, under the current user.
(our tor interface library `txtorcon` needs read access to the Tor HS dir, so it's troublesome to do this another way).

##### Question: How to configure the `directory-nodes` list in our `joinmarket.cfg` for this directory node bot?

Answer: **you must only enter your own node in this list!** (otherwise you may find your bot infinitely rebroadcasting messages).


#### Suggested setup of a service:

You will need two components: bitcoind, and Joinmarket itself, which you can run as a yg.
Since this task is going to be attempted by someone with significant technical knowledge,
only an outline is provided here; several details will need to be filled in.
Here is a sketch of how the systemd service files can be set up for signet:

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

This is deliberately a super-basic setup (see above). Don't forget to setup your `bitcoin.conf` as usual,
for the bitcoin user, and make it match (specifically in terms of RPC) what you set up for Lightning below.


2.

```
[Unit]
Description=joinmarket directory node on signet
Requires=bitcoin-signet.service
After=bitcoin-signet.service

[Service]
Type=simple
ExecStart=/bin/bash -c 'cd /path/to/joinmarket-clientserver && source jmvenv/bin/activate && cd scripts && echo -n "password" | python yg-privacyenhanced.py --wallet-password-stdin --datadir=/custom/joinmarket-datadir some-signet-wallet.jmdat'
User=user

[Install]
WantedBy=multi-user.target
```

To state the obvious, the idea here is that this second service will run the JM directory node and have a dependency on the previous one,
to ensure they start up in the correct order.

Re: password echo, obviously this kind of password entry is bad;
for now we needn't worry as these nodes don't need to carry any real coins (and it's better they don't!).
Later we may need to change that (though of course you can use standard measures to protect the box).

TODO: add some material on network hardening/firewalls here, I guess.
