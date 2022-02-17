Joinmarket-clientserver 0.9.5:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.9.5>

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>


Upgrading
=========

To upgrade:

*Reminder: always back up and recreate your joinmarket.cfg file when doing the upgrade; this is to make sure you have the new default settings.*

(If you are upgrading from a version pre-0.7.0 please read the "Upgrading" section in [the 0.7.0 release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.7.0.md).)

(If you are upgrading from a version pre-0.9.0 please read the [release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.9.0.md) to find out how about [fidelity bonds](../fidelity-bonds.md) are relevant to your use-case).

First run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.

Note that `./install.sh -?` will show the options for installation.

Notable changes
===============

### Support sending to taproot

This is mostly (though not 100%) a change to the backend bitcoin library python-bitcointx, which has been upgraded to [v1.1.3](https://github.com/Simplexum/python-bitcointx/releases/tag/python-bitcointx-v1.1.3) and in this version, includes the validation of bech32m as taproot addresses.
(Note that the master branch of python-bitcointx now has full taproot support, i.e. constructing and spending taproot outputs, also; but we don't yet have a use case for that, anyway).
Users can now send to taproot addresses via any of the user interfaces (CLI, Qt GUI, web UI).

`b700f37` Add send-to-P2TR

`a467ec4` upgrade to python-bitcointx 1.1.3

### Extensive updates to the JSON RPC-API (jmwalletd.py); first fully working version

After a lot of testing and bugfixing, the following commits were added to patch up the JSON RPC-API feature that was added in [0.9.3](https://github.com/JoinMarket-Org/joinmarket-clientserver/releases/tag/v0.9.3). The new [webUI project](https://github.com/joinmarket-webui/joinmarket-webui) is using this and is now functional (alpha release coming shortly).

For those not familiar, the RPC API can be served by running the script `jmwalletd.py` and note that unlike other Joinmarket scripts, a wallet need not be specified, since it will allow the unlocking of any wallet (or creation of a new one) from a calling RPC client. See the [user docs](https://joinmarket-org.github.io/joinmarket-clientserver/JSON-RPC-API-using-jmwalletd.html) and [API docs](https://joinmarket-org.github.io/joinmarket-clientserver/api/) for details.

There are several commits, broken into two groups here:

#### New endpoints/functionality

* `29b459a` Add freeze method to RPC-API
* `89896e0` Add yieldgen report endpoint to API
* `6e07e4f` Add /taker/stop endpoint to RPC
* `28fdaa1` Allow re-unlock of wallets via /unlock
* `3939714` Add status, label and extradata to RPC display
* `e598b35` Add RPC API endpoint for showseed

#### Fixes to bugs in logic, improvements

* `a0b7b38` Return TransactionFailed when insufficient funds
* `30e96f8` Do not call stopService at exit in RPC daemon
* `7b822a4` Do not update coinjoin state if maker cannot start
* `d493343` Ensure coinjoin state is reset if wallet switches.
* `4389338` Make unconf unspent display default in jmwalletd
* `ed7b4e1` Fix bugs in unlock-lock logic
* `beaa8b0` fixes to API and return format
* `d4d3157` Unlock does not block waiting for sync
* `bd33b6d` RPC maker/start returns 409 error if no coins
* `e6ea9d0` Update HTTP status codes returned by RPC-API
* `fe46b7e` Allow RPC coinjoin taker_finished to accept unconf
* `66d7e46` Fix RPC timelockaddress call.


### Changes to dependencies

Since the introduction of the use of python-bitcointx in 0.7.0, we have effectively been using two different bindings to `libsecp256k1`, i.e. there was still a dependency on coincurve even though we only used it for one or two minor things. This was obviously very suboptimal, and it has now been removed. We also remove a dependency on `libgmp` because `libsecp256k1` itself removed this dependency. Note that `68a426a` was effectively overriden by the taproot update in `a467ec4` but this has no functional effect.

`537e317` Remove coincurve dependency, use python-bitcointx

`68a426a` Update secp256k1 to latest upstream version.

`5f942d5` remove all libgmp dependency references

`c59dcd3` Remove libgmp-dev dependency

The QR code dependency is one of the more security sensitive ones, so the version was pinnned:

`f054921` Pin python-qrcode to a specific version

### Installation script improvements

You can now pass a flag to the `install.sh` script which makes the installation suitable for deployment with Docker:

`c28bfd5` Add support for `--docker-install` with an example Dockerfile and some docs on how to use it.

Also, to aid compilation on constrained devices:

`c0d6610` Limit number of parallel builds to CPU core count

### Bugfix: Ensure displayed addresses are imported always in Qt

See #1147 and [this explanatory comment](https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/1147#issuecomment-1012268971) for extra detail. In an unusual, but by no means unthinkable circumstance - a user deposits to multiple addresses in the Qt app, new addresses were being generated and displayed without being imported, meaning if they were paid to in the same Qt run, a rescan would be needed afterwards to pick them up. This is fixed.

`ac8b173` Ensure all displayed addresses are imported

### UI improvements

Improvement to the Qt app itself:

`c706c6e` Improve the UX of open wallet dialog.
`f899daa` Do not auto generate the QT UI code in setup.py, + `9834d73` Fix linter error

All user interfaces can make use of this extra utxo information:

`1cc677a` Add derivation path to output of wallet_showutxos

This change (see #1111) corrects the outdated 'used' field to 'status' (since it is multivalued):

`d110101` Rename `WalletViewEntry.used` to `WalletViewEntry.status`

### Documentation

A big change is that we now have a github pages site with the Joinmarket user documentation in `/docs` mirrored, [here](https://joinmarket-org.github.io/joinmarket-clientserver/), including specifically for the RPC API, [here](https://joinmarket-org.github.io/joinmarket-clientserver/api/). This requires a default `index.md` in `/docs`:

`bf6c064` Update index.md
`bd18048` add index.md for docs site contents
`fcd0d91` Add simple index file

`16cc17c` address linting complaints of openapi for RPC spec file

`1acadb7` Self-host redoc js

`44ae9f2` Set theme jekyll-theme-minimal

`91c2c48` API documentation via ReDoc

Corrections to units and notation in the config file:

`1e95618` Improve examples

A clarification on the `rpc_` related settings in the Joinmarket config (this is the Bitcoin Core RPC, not the RPC for Joinmarket as above):

`b953d7e` Document rpc_cookie_file and rpc_wallet_file in default config

### Minor changes

Minor feature improvements:

`f5c7f33` Allow signmessage to work with any index

`c957c8c` Read only single line with `--wallet-password-stdin`

Minor bugfixes:

We now only query scripts, not addresses from the RPC utxoset query; see #1124.

`fb4644e` Allow utxo address validation with script

`9ebd538` Removed Unicode dash.

Fixing warnings related to custom change in a coinjoin (we warn differently if you also use a different script type):

`c5456e4` Don't show nonwallet_custom_change_warning in Qt GUI for non-cj sends
`f741fdd` Use get_txtype() / get_outtype() for address type detection

Corrects error in placement of tumbler log files, if custom data directory:

`a1bcac9` Fix tumble log dir after load_program_config

`ca85ac6` Don't throw when disabled socks config missing

`cf37639` Make Qt shutdown gracefully on reactor stop.

Credits
=======

Thanks to everyone who directly contributed to this release -

- @abhishek0405
- @dennisreimann
- @manasgandy
- @Silvenga
- @wukong1971 
- @sangaman
- @jameshilliard
- @kristapsk
- @AdamISZ
- @theborakompanioni
- @5F43CCDF
- @dmp1ce

And thanks also to those who submitted bug reports, tested, reviewed and otherwise helped out.
