# HOW TO SETUP ONION MESSAGE CHANNELS IN JOINMARKET

### Contents

1. [Overview](#overview)

2. [Testing, configuring for signet](#testing)

4. [Directory nodes](#directory)

<a name="overview" />

## Overview

This is a new way for Joinmarket bots to communicate, namely by serving and connecting to Tor onion services. This does not
introduce any new requirements to your Joinmarket installation, technically, because the use of Payjoin already required the need
to run such onion services, and connecting to IRC used a SOCKS5 proxy (used by almost all users) over Tor to
a remote onion service.

The purpose of this new type of message channel is as follows:

* less reliance on any service external to Joinmarket
* most of the transaction negotiation will be happening directly peer to peer, not passed over a central server (
albeit it was and remains E2E encrypted data, in either case)
* the above can lead to better scalability at large numbers
* a substantial increase in the speed of transaction negotiation; this is mostly related to the throttling of high bursts of traffic on IRC

The configuration for a user is simple; in their `joinmarket.cfg` they will get a messaging section like this, if they start from scratch:

```
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
tor_control_port = 9051

# the host/port actually serving the hidden service
# (note the *virtual port*, that the client uses,
# is hardcoded to 80):
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
# be 80 if created in this code.
directory_nodes = rr6f6qtleiiwic45bby4zwmiwjrj3jsbmcvutwpqxjziaydjydkk5iad.onion:80

# This setting is ONLY for developer regtest setups,
# running multiple bots at once. Don't alter it otherwise
regtest_count = 0,0
```

All of these can be left as default for most users, except the field `directory_nodes`.

The list of **directory nodes** (the one shown here is one being run on signet, right now), which will
be comma separated if multiple directory nodes are configured (we expect there will be 2 or 3 as a normal situation).
The `onion_serving_port` is on which port on the local machine the onion service is served; you won't usually need to use it, but it mustn't conflict with some other usage (so if you have something running on port 8080, change it).
The `type` field must always be `onion` in this case, and distinguishes it from IRC message channels and others.

### Can/should I still run IRC message channels?

In short, yes.

### Do I need to configure Tor, and if so, how?

To make outbound Tor connections to other onions in the network, you will need to configure the
SOCKS5 proxy settings (so, only directory nodes may *not* need this; everyone else does).
This is identical to what we already do for IRC, except that in this case, we disallow clearnet connections.

#### Running/testing as a maker

A maker will additionally allow *inbound* connections to an onion service.
This onion service will be ephemeral, that is, it will have a different onion address every time
you restart. This should work automatically, using your existing Tor daemon (here, we are using
the same code as we use when running the `receive-payjoin` script, essentially).

#### Running/testing as other bots (taker)

A taker will not attempt to serve an onion; it will only use outbound connections, first to directory
nodes and then, as according to need, to individual makers, also.

As previously mentioned, both of these features - inbound and outbound, to onion, Tor connections - were already in use in Joinmarket. If you want to run/test as a maker bot, but never served an onion service before, it should work fine as long as you have the Tor service running in the background,
and the default control port 9051 (if not, change that value in the `joinmarket.cfg`, see above).

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

Add the `[MESSAGING:onion]` message channel section to your `joinmarket.cfg`, as listed above, including the
signet directory node listed above (rr6f6qtleiiwic45bby4zwmiwjrj3jsbmcvutwpqxjziaydjydkk5iad.onion:80), and,
for the simplest test, remove the other `[MESSAGING:*]` sections that you have.

Then just make sure your bot has some signet coins and try running as maker or taker or both.

<a name="directory" />

## Directory nodes

**This last section is for people with a lot of technical knowledge in this area,
who would like to help by running a directory node. You can ignore it if that does not apply.**.

This requires a long running bot. It should be on a server you can keep running permanently, so perhaps a VPS,
but in any case, very high uptime. For reliability it also makes sense to configure to run as a systemd service.

A note: the most natural way to run the directory is as a Joinmarket *maker* bot, i.e. run `yg-privacyenhanced.py`, with configuration as described below. For now it will actually offer to do coinjoins - we will want to fix this in future so no coins are needed (but it can just be a trivial size).

#### Joinmarket-specific configuration

Add `hidden_service_dir` to your `[MESSAGING:onion]` with a directory accessible to your user. You may want to lock this down
a bit!
The point to understand is: Joinmarket's `jmbase.JMHiddenService` will, if configured with a non-empty `hidden_service_dir`
field, actually start an *independent* instance of Tor specifically for serving this, under the current user.
(our Tor interface library `txtorcon` needs read access to the Tor HS dir, so it's troublesome to do this another way).

##### Question: How to configure the `directory-nodes` list in our `joinmarket.cfg` for this directory node bot?

Answer: **you must only enter your own node in this list!**. This way your bot will recognize that it is a directory node and it avoids weird edge case behaviour (so don't add *other* known directory nodes; you won't be talking to them).


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
for the bitcoin user, and make it match (specifically in terms of RPC) what you set up for Joinmarket below.


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
for now we needn't worry as these nodes don't need to carry significant coins (and it's much better they don't!).

TODO: add some material on network hardening/firewalls here, I guess.
