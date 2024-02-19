Joinmarket-clientserver 0.9.11:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.9.11>

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading
=========

To upgrade:

*Reminder: always back up and recreate your joinmarket.cfg file when doing the upgrade; this is to make sure you have the new default settings. In order to recreate it, rename the old joinmarket.cfg and run 'python3 wallet-tool.py generate' from the scripts folder.*

(If you are upgrading from a version pre-0.7.0 please read the "Upgrading" section in [the 0.7.0 release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.7.0.md).)

(If you are upgrading from a version pre-0.9.0 please read the [release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.9.0.md) to find out how about [fidelity bonds](../fidelity-bonds.md) are relevant to your use-case).

First run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.

Note that `./install.sh -?` will show the options for installation.

Changes
===============

### Removal of Python 3.7 support, 3.8 or newer is required now

Python 3.7 has been end of-life since June 2023 and it was a blocker for some necessary dependency updates.

Note that currently only Python 3.8, 3.9, 3.10 and 3.11 are supported, not Python 3.12 and newer.

* `7e045c9` Requires Python <3.12
* `3d56837` Remove unnecessary check for Python 3.7+
* `204f117` Drop Python 3.7 support

### Move to modern packaging and source layout

- Migrate to src-layout following https://setuptools.pypa.io/en/latest/userguide/package_discovery.html#src-layout to facilitate automatic package discovery and editable installs.
- Create `joinmarket` namespace distribution package in line with https://packaging.python.org/en/latest/guides/packaging-namespace-packages/
- Migrate to `pyproject.toml` file for project configuration instead of legacy `setup.py`

* `c8eef50` Migrate to modern packaging and src layout

### Performance improvements

Lots of performance improvements made in wallet code that makes big impact especially with old wallets, with a lots of transaction history (in extreme cases, the time needed for some operations was improved from 40+ minutes to around 10 seconds). When syncing a heavily used wallet from a seed phrase on a new Bitcoin Core instance, now larger gap limit (`-g`) can be used and it will take far less time than it did before.

This involves caching some computed data in the wallet, in case a bug is discovered with this, a new configuration option `wallet_caching_disabled` is added to `joinmarket.cfg`, which allows to disable it when syncing the wallet.

As part of performance improvements are done by caching some data in wallet file (still encrypted), `*.jmdat` files will grow larger than before.

* `48aec83` wallet: remove a dead store in get_index_cache_and_increment
* `8245271` wallet: avoid IndexError in _is_my_bip32_path
* `574c29e` wallet: hoist get_script_from_path default impl into BaseWallet
* `2c38a81` wallet: delete redundant get_script and get_addr methods
* `b58ac67` wallet: drop _get_addr_int_ext; replace with calls to get_new_addr
* `fc1e000` wallet_showutxos: use O(1) check for frozen instead of O(n)
* `184d76f` wallet: add get_{balance,utxos}_at_mixdepth methods
* `77f0194` wallet_utils: use new get_utxos_at_mixdepth method
* `64f18bc` get_imported_privkey_branch: use O(m+n) algorithm instead of O(m*n)
* `01ec2a4` wallet: add _addr_map, paralleling _script_map
* `5bc7eb4` wallet: add persistent cache, mapping path->(priv, pub, script, addr)
* `c3c10f1` wallet: implement optional cache validation
* `ef1d76e` Allow cache purging at wallet initialization
* `f2ae8ab` Don't validate cache during initial sync.
* `8491431` cache deserialized form of txs in history method
* `fab97a0` Use get_deser_from_gettransaction() everywhere

### Drop official support for 32-bit platforms

It should still work, but you might need Rust compiler installed for `install.sh` to succeed. It was necessary for newer versions of `cryptography` Python package. See https://github.com/JoinMarket-Org/joinmarket-clientserver/issues/1454 and https://github.com/JoinMarket-Org/joinmarket-clientserver/pull/1579.

### Wallet RPC API improvements and fixes

* `a847df9` Patch #1480: call get_POST_body once
* `af9f462` fix(docs): remove duplicate keys in wallet-rpc.md
* `ef29982` remove bearer authentication errors
* `c88429d` JWT authority fixes
* `638200d` feat(rpc): add block height to session response
* `d8f1fc4` Add optional txfee property for direct-send wallet RPC
* `ab1481d` RPC API: Add optional txfee property for single joins

### Removal of `convert_old_wallet.py` script

It was broken and old format wallets for conversion of which it was used aren't created by JoinMarket since v0.4.0 six years ago. If anybody still needs to do that conversion, some older JoinMarket release can be used.

* `d89dcde` Remove convert_old_wallet.py script

### Code quality improvements

* `3fc74fb` Refactor and cleanup of blockchaininterface and related
* `3e71df5` Fix ShellCheck warnings
* `7ebbacf` Add type hints
* `2978b18` De-duplicate and change dict_factory
* `d9fee29` Fix get_tx_info() type hint and doc
* `c4414e8` Minor quality improvements in wallet code

### Bugfixes and other minor changes

* `47bc77f` Fix some internal dependencies
* `83d7ebb` Log in case JM loads RPC wallet at startup
* `438cb41` Replace readfp()
* `4486b10` Transaction virtual size must be rounded upwards
* `c990a4d` Allow fee bump tx not signalling BIP125 if mempoolfullrbf is enabled
* `bfc618a` Fix OrderbookWatch.on_order_seen() exception debug messages
* `6ec6308` Deduplicate wallet error messages
* `1822279` Warn user if higher priority confirmation target than requested is provided by blockchain source
* `196a097` Allow absurd fee override when setting tx fee manually
* `9c13180` Raise fallback fee rate from 10 sat/vB to 20 sat/vB
* `0a225c1` Payjoin: log full proposed PSBT from sender if it fails sanity checks
* `cde6b4c` Fix no amount entered message (can be sats too, not only BTC)

### Documentation

Most important - Bitcoin Core v26 has dropped legacy wallet support by default, but JoinMarket still doesn't support new descriptor wallets. So documentation was changed to note users that Core should be started with `deprecatedrpc=create_bdb` configuration parameter for JM to work.

* `c9c4648` Update release-notes-0.9.10.md
* `1a8d0ea` Correct help description for --develop
* `c2a6b3d` Rephrase hidden service dir config, lint
* `8555a8b` Removed donation link
* `79e5c3d` Document Core wallet creation for v26
* `13661f5` Docs: Fix links in Docker install section
* `cb60774` Qt: Remove donation link from "About" dialog
* `9ab8ad6` Remove mention of donations from JoinMarketQt guide
* `a5a5132` update payjoin doc

### Installation and dependencies

* `c08e824` build(deps): update tor from v0.4.7.13 to v0.4.8.7
* `1ebb68f` Update txtorcon to 23.0.0
* `7181512` Upgrade setuptools also with --docker-install
* `91dacf6` Rewrite AES code with cryptography
* `70366ff` Bump cryptography to 41.0.4 for all platforms
* `b2c5603` Bump twisted from 22.4.0 to 23.8.0
* `30d9715` Update Dockerfile
* `f40bd64` Bump cryptography from 41.0.4 to 41.0.6
* `9410b9c` Update libsecp256k1 and python-bitcointx
* `47acf6a` Update libsecp256k1 to v0.4.1
* `8254a67` Update secp256k1 lib deps for pythonbitcointx1.1.5
* `ca33eca` Bump txtorcon from 23.0.0 to 23.11.0
* `66fcf38` Bump twisted from 23.8.0 to 23.10.0
* `8846c4d` Remove --disable-jni from libsecp256k1_build

### Testing

* `bfd5b21` fix linting
* `906eb71` CI: Update Bitcoin Core from 25.0 to 25.1
* `d25457b` CI: Disable venv caching
* `4f4945e` Test min and latest Python version only
* `027682a` CI: Add ShellCheck
* `1cb20d5` Do not reinstall on test
* `8684853` Support Bitcoin Core v26 for tests
* `d234731` Add -allowignoredconf=1 for Bitcoin Core v26+
* `935a734` Fix tests for Core v26 when user has no access to ~/.bitcoin/settings.json
* `8f382d0` Add test for dict_factory()
* `4d15a2c` CI: Add OpenAPI Diff action
* `fe9ec99` When looking for a free TCP ports, bind only to localhost
* `8e6eca8` Add CodeQL code scanning

Credits
=======

Thanks to everyone who directly contributed to this release -

- @AdamISZ
- @BTCBellyButton (new contributor)
- @dennisreimann
- @dependabot[bot] :)
- @kristapsk
- @MarnixCroes (new contributor)
- @roshii
- @st3b1t (new contributor)
- @theborakompanioni
- @whitslack (special shout out for extremely significant contribution to improve wallet performance)

And thanks also to those who submitted bug reports, tested, reviewed and otherwise helped out.
