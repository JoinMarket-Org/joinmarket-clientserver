Joinmarket-clientserver 0.9.12:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.9.12>

**This is probably the final release of this implementation of Joinmarket**. The repo will now be archived, meaning there will be no plans for more updates; the releases will be left here for download in case that's useful.

We would advise users of the software to examine the reimplementation at https://github.com/joinmarket-ng/joinmarket-ng. This is **not** a recommendation; use of this or any similar software is your own responsibility.

Upgrading
=========

To upgrade:

*Reminder: always back up and recreate your joinmarket.cfg file when doing the upgrade; this is to make sure you have the new default settings. In order to recreate it, rename the old joinmarket.cfg and run 'python3 wallet-tool.py generate' from the scripts folder.*

(If you are upgrading from a version pre-0.7.0 please read the "Upgrading" section in [the 0.7.0 release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.7.0.md).)

(If you are upgrading from a version pre-0.9.0 please read the [release notes](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.9.0.md) to find out how [fidelity bonds](../fidelity-bonds.md) are relevant to your use-case).

First run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.

Note that `./install.sh -?` will show the options for installation.

Changes
===============

### Fix of DOS vector from commitment checking failure

Commitments are supposed to be one-use only but we were not checking
the format correctly, leading to the possibility of ~ continuous reuse.
Worse, a motivated attacker that uses this aggressively could retrieve
lots of utxo information from makers over a long period, which degrades
Joinmarket's functionality. This was exactly the attack that the taker
commitments were supposed to thwart.

Shoutout to @m0wer for reporting this one:

* `092b480` Checks case of inbound commitments before comparison.

### Descriptor wallet support

This change is needed to run the software with the most recent
versions of Bitcoin Core (>= 30.0) that disable old non-descriptor wallets.
(Remember, we don't use Bitcoin's wallet for keys/signing, only for
watch-only; but we do still use it).

* `f3630dc` Support Bitcoin Core descriptor wallets (quick and dirty way)

### General refactoring and minor functionality improvements

* `6e5cdc8` Refactor: move bitcoin unit conversion functions from ob-watcher to jmbitcoin
* `395050c` Use coins_to_satoshi() and satoshi_to_coins() from bitcointx everywhere
* `d117791` yieldgenerator: allow change address to be overridden (note that despite the worrying description, it literally just refactors the change address sourcing; by default zero functional change)
* `f3f4f0a` Multiple (batch) payment support in `direct_send()` (this doesn't actually implement batch payments, but refactors to allow it as a possibility)
* `904b780` Unify cli user input code where limited range of answers are allowed
* `861c790` maker: allow receiving more money than promised
* `865247c` Support payjoin PSBT with multiple sender inputs (Joinmarket's implementation of payjoin did support multiple sender inputs before this, but was not following the BIP78 spec properly for this case, thankfully @spacebear21 identified and fixed this)
* `f0b0e55` Cache None in tx_cache for non-wallet transactions


### Minor bugfixes

* `8eb55be` Handle None enter_seed_callback() response
* `8798b8b` Redirect back to / after /refreshorderbook and /rotateOb
* `3317b0b` Fix jm_single().bc_interface.get_deser_from_gettransaction call
* `100da5e` Handle JsonRpcError in _estimate_fee_basic
* `053d8a1` Implement mixdepth filtering for showutxos

### RPC-API

* `6469991` RPC-API: Implement message signing
* `5b47d1c` RPC API endpoint to get wallet rescan status
* `d615688` Update GetAddressResponse schema to return an object with address property

### Configuration

* `d87e7cb` Replace default directory nodes with currently working ones
* `b03c5ef` Mark my previous signing key as lost  (my == @AdamISZ)
* `c416a94` Remove DarkScience IRC network from default config
* `954dc36` Remove Ilita IRC, re-enable hackint

### Dependencies

* `14a7b7e` Update libsodium from 1.0.18 to 1.0.20
* `c54c11c` Bump twisted from 23.10.0 to 24.7.0
* `b4e3fdd` `b456968` `f952d7d` `ee4a3fa` `6baf4a5` Bump minimum required Bitcoin Core version from 0.18 to 29.0
* `53d89ec` Bump libsecp256k1 from v0.4.1 to v0.5.0
* `12d6b5a` Bump compatible Python version to 3.12
* `cbd8868` Bump libffi from 3.2.1 to latest 3.4.6
* `bd22dd0` Bump pyopenssl from 23.2.0 to 24.0.0
* `b9cfd89` `1144233` Bump built-in Tor from 0.4.8.7 to 0.4.8.13
* `07bad14` Bump cryptography from 41.0.6 to 42.0.4
* `ea9557b` chore(deps): bump python upper version (to < 3.14)
* `091ce51` fix(deps): bencode library

### Testing and installation

* `9eaca78` ci: no fail-fast for unittests
* `8675a29` install.sh: use debian dist libffi
* `8992e36` Fix Debian dependency check for non-English locales
* `cf5184f` test(ci): build docker image in github workflow
* `9d8988a` build(docker): update to debian bookworm
* `398f1c0` `d9da8bd` `30557a4` `4e75f6e` `67da009`  CI: Bump Bitcoin Core from 26.0 to 29.0
* `719f242` Fix run_tests.sh for Bitcoin Core v27
* `39720a8` CI: Use x64 not arm64 macOS
* `669839e` Remove test that assumes mempoolfullrbf=0
* `da5603a` CI: Run bash scripts with -x
* `6e33686` update Installation on Linux
* `bbc2150` Tell libsodium not to download code from savannah.gnu.org in autogen.sh
* `508b4ee` fix-debian

### Documentation

* `6de1bab` doc: small install doc updates
* `d53b902` doc: Tor control auth cookie file must be group readable
* `4040ace` update sourcing commitments link
* `26c157d` small fixes/updates in tumblerguide doc
* `fd96f96` Fix docstring
* `24feda7` Fix / remove broken links

Credits
=======

Thanks to everyone who directly contributed to this release -

- @spacebear21
- @kristapsk
- @st3b1t
- @theborakompanioni
- 3np
- @AdamISZ
- dependabot[bot]
- @MarnixCroes
- @whitslack
- @nischal-shetty2
- @roshii

And thanks also to those who submitted bug reports, tested, reviewed and otherwise helped out.
