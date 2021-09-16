## JSON-RPC API for Joinmarket using jmwalletd.py

### Introduction - how to start the server

Create an ssl certificate and store it in `<datadir>/ssl/{key,cert}.pem`; the `datadir` is set by `--datadir` in scripts or is `~/.joinmarket` by default, or `.` by default in testing.

After installing Joinmarket as per the [INSTALL GUIDE](INSTALL.md), navigate to the `scripts/` directory as usual and start the server with:

```
(jmvenv) $python jmwalletd.py
```

which with defaults will start serving the RPC over `https://` on port 28183, and a (secure) websocket server (`wss://`) on port 28283.

Documentation of the websocket functionality [below](#websocket).

This HTTP server does *NOT* currently support multiple sessions; it is intended as a manager/daemon for all the Joinmarket services for a single user. Note that in particular it allows only control of *one wallet at a time*.

#### Rules about making requests

Authentication is with the [JSON Web Token](https://jwt.io/) scheme, provided using the Python package [PyJWT](https://pypi.org/project/PyJWT/).

Note that for some methods, it's particularly important to deal with the HTTP response asynchronously, since it can take some time for wallet synchronization, service startup etc. to occur; in these cases a HTTP return code of 202 is sent.

### API documentation

Current API version: v1.

The [OpenAPI](https://github.com/OAI/OpenAPI-Specification) spec is given in [this yaml file](../jmclient/jmclient/wallet-rpc-api.yaml). Human readable documentation of the API is provided in [this document](../jmclient/jmclient/wallet-rpc-api.md), which is auto-generated with the node utility [swagger-markdown](https://www.npmjs.com/package/swagger-markdown).

Those wishing to write client code should adhere to that specification.

#### What is and is not provided in the current version of the API.

As a brief summary, the functionality currently available is:

* list existing wallets
* create a wallet
* unlock (decrypt) a wallet
* lock a wallet
* display contents of a wallet
* list the utxos in the wallet
* get a new address for deposit in a given account
* send a payment without coinjoin
* send a payment with coinjoin
* start the yield generator
* stop the yield generator
* get the value of a specific config variable
* set the value of a specific config variable (only in memory)
* a 'heartbeat' check that also reports whether a wallet is loaded, whether the maker is running, whether a coinjoin is in process.

Clearly there are several further functionalities currently available in the CLI and Qt versions of Joinmarket which are not yet supported. It is likely that several or all of these will be added in future (e.g.: payjoin, utxo freezing).

In addition to the above, a websocket service currently allowing subscription only to transaction events, and coinjoining state, is provided, see next.

<a name="websocket" />

### Websocket

When a wallet service is started via a call to `create` or `unlock` (see above), the websocket automatically starts to serve notifications to any connected client. The client must send the authentication token it has received in the create/unlock call, over the websocket, when it connects, otherwise it will not receive any notifications.

Any authenticated connection is currently automatically subscribed to both of the following events:

#### Coinjoin state change event

When the backend switches from doing nothing, to running a coinjoin as taker over the messaging channels, or to running as a yield generator, or stopping either of these, an event is sent on the websocket noting the new current state. The message is json encoded as:

```
{"coinjoin_state": 1}
```

where the values are:

0 - Taker running  
1 - Maker running  
2 - Neither are running

#### Transaction event

When a transaction is seen for the first time in the Joinmarket wallet, a notification is sent to the client over the websocket as encoded json, containing the txid and a detailed human-readable deserialization of the transaction details. See this example:

```
{"txid": "ca606efc5ba8f6669ba15e9262e5d38e745345ea96106d5a919688d1ff0da0cc", 
 "txdetails": {
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
            "address": "bcrt1q6w86ff4v3km5jhj79dwjr8wv6sfdmxawzzx47z"
        },
        {
            "value_sats": 27000100,
            "scriptPubKey": "0014564aead56de8f4d445fc5b74a61793b5c8a81966",
            "address": "bcrt1q2e9w44tdar6dg30utd62v9unkhy2sxtxr0p4md"
        },
        {
            "value_sats": 146994810,
            "scriptPubKey": "00146ec55c2e1d1a7a868b5ec91822bf40bba842bac5",
            "address": "bcrt1qdmz4ctsarfagdz67eyvz906qhw5y9wk990rz48"
        }
    ],
    "txid": "ca606efc5ba8f6669ba15e9262e5d38e745345ea96106d5a919688d1ff0da0cc",
    "nLockTime": 0,
    "nVersion": 2
}}
 ```
