Joinmarket-clientserver 0.3.5:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.3.5>

This is a very minor bugfix release, necessary because bugs in the previous release led to crashes in certain edge cases;
the most important one(s) being crashes that made the tumbler prematurely stop when it needed to try a join again.

It is not security-critical however (those bugs were functional failures but had no security implication).

If you have not updated for some time, be sure to read the previous release notes for what has changed.

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading 
=========

To upgrade: run the `install.sh` script as mentioned in the README. When prompted to overwrite the directory `jmvenv`, accept.


Notable changes
===============

As noted above, there is only one (set of) significant changes; as usual, changes with the testing setup are
not included/out of scope.

### Fix bugs in restart-with-subset

`f1e3476a64cadc0bf9fe9f3c90ff97fd7bb7d5ca` `4a15cbd3c7c16a7377cc475330484f8a2a1bf48f`

Explained above.


Credits
=======

Thanks to everyone who directly contributed to this release -

- @fivepiece
- @AdamISZ

And thanks also to those who submitted bug reports, tested and otherwise helped out.
