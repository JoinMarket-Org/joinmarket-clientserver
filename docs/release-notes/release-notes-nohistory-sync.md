Notable changes
===============

### No-history wallet synchronization

The no-history synchronization method is enabled by setting `blockchain_source = bitcoin-rpc-no-history` in the `joinmarket.cfg` file.

The method can be used to import a seed phrase to see whether it has any money on it within just 5-10 minutes. No-history sync doesn't require a long blockchain rescan, although it needs a full node which can be pruned.

No-history sync works by scanning the full node's UTXO set. The downside is that it cannot find the history but only the current unspent balance, so it cannot avoid address reuse. Therefore when using no-history synchronization the wallet cannot generate new addresses. Any found money can only be spent by fully-sweeping the funds but not partially spending them which requires a change address. When using the method make sure to increase the gap limit to a large amount to cover all the possible bitcoin addresses where coins might be.

The mode does not work with the Joinmarket-Qt GUI application but might do in future.
