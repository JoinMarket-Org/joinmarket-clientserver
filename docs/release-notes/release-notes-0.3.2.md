Joinmarket-clientserver 0.3.2:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.3.2>

Minor release with important bugfixes, especially for Makers (yield-generators).

Due to the security implications of the first bugfix described below, upgrade immediately.

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading 
=========

To upgrade: run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.


Notable changes
===============

### Prevent daemon listening on all interfaces

`b5db28e`

This fixes an important privacy weakness - in case you are not behind NAT/firewall, the previous version
accepted connections to the daemon port (default 27183) from other machines. This did not represent
a funds loss risk (the daemon has no access to Bitcoin/wallet, only does message passing), but could have
allowed at least disruption of processing, and probably leak information. Many thanks to @undeath for
noticing this, and apologies from me for not testing/checking it when I first wrote it.

### Add correct transaction timeout watchers to Core blockchain interface

`3aab8b9`

For the case of transactions which were negotiated but not broadcast on the network (e.g. if the
Taker's pushtx() operation failed for some reason), the transaction watching loop did not stop,
which is a problem for a long-running Maker (it will eventually start to use more and more resources
by constantly polling Core, if such failed tx negotations occur).
Now timeouts as specified in `[TIMEOUT]`, `unconfirm_timeout_sec` and `confirm_timeout_hours`
as set in the config (defaults 90, 6 respectively) are respected.

Other changes are minor: improvements to wallethistory feature, improvements to `install.sh` (including `--develop` flag for developers),
and some improvements to the testing and docs.

Credits
=======

Thanks to everyone who directly contributed to this release -

- @adlai
- @undeath
- @fivepiece
- @AdamISZ
- @mecampbellsoup
- @sangaman

And thanks also to those who submitted bug reports, tested and otherwise helped out.
