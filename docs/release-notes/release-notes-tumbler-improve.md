copypaste this into "release-notes" when the time comes to make a new release, then delete this file

Notable changes
===============

### Tumbler privacy improvements

The tumbler algorithm has been improved with the aim to increase privacy. This affects the `tumbler.py` script and `joinmarket-qt.py` GUI.

* At the start of the run, tumbler will now fully spend all mixdepths with coinjoin with no change address (also known as a sweep transaction) back to its own internal wallet. After these initial sweeps are done tumbler will continue with the already-existing algorithm of sending coinjoins with randomly-generated amounts.

* Tumbler will now occasionally send a round number of bitcoins, for example `0.20000000` or `0.15000000` instead of `0.24159873`. The default probability of this happening is 25% per coinjoin.

* The default wait time between coinjoins is increased from 30 minutes to 60 minutes.

* The default number of coinjoin counterparties is increased from 6 to 9.

* The default number of coinjoins per mixdepth is decreased from 4 to 2.

For a full discription and reasoning behind the changes see: [Plan to improve the privacy of JoinMarket's tumbler script](https://gist.github.com/chris-belcher/7e92810f07328fdfdef2ce444aad0968)
