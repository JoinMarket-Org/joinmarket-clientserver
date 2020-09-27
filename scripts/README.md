# Command line scripts for Joinmarket

(If upgrading to version 0.3.0+, don't forget to read [this](../docs/SEGWIT-UPGRADE.md) on upgrading the wallet.)

All user level scripts here.

(The phrase "normal Joinmarket" in the below refers to the [existing repo](https://github.com/Joinmarket-Org/joinmarket).

The subdirectories `logs` and `wallets` have the same role as in normal Joinmarket.
The subdirectory `cmtdata` contains only your `commitments.json` storage of your used
commitments (ignored by github of course!). The filename is set in joinmarket.cfg.

The `joinmarket.cfg` will be created and maintained in this directory.

Brief explanation of the function of each of the scripts:

### sendpayment.py

Either use the same syntax as for normal Joinmarket:

    `python sendpayment.py --fast -N 3 -m 1 -P wallet.jmdat 50000000 <address>`

or use the new schedule approach. For an example, see the [sample schedule file](https://github.com/AdamISZ/joinmarket-clientserver/blob/master/scripts/sample-schedule-for-testnet).
Do:

    `python sendpayment.py --fast -S sample-schedule-for-testnet wallet.jmdat`

Note that the magic string `INTERNAL` in the file creates a payment to a new address
in the next mixdepth (wrapping around to zero if you reach the maximum mixdepth).

To pay a fraction of the total in a mixdepth you can simply make the amount field
in the schedule a decimal instead of an integer (0.0 < amt < 1.0 of course).

The schedule file can have any name, and is a comma separated value file, the lists
must follow that format; see the comment in the sample file above (each list is length 5 items).

*This part can be ignored for a first run:

Additional fields in config: in the config section `[DAEMON]` you can specify whether
to run the daemon as a separate process or not. By default, the daemon will run in the
same Python process, for maximum convenience, so you needn't separately start `joinmarketd.py` (see below).

You can run the daemon separately by setting `nodaemon=0` in `[DAEMON]`. You can choose to use ssl within this single-process configuration with `use_ssl=true` (again, see below for more on this).*

### tumbler.py

This is an extension of the functionality of `sendpayment.py` in that it auto-generates
a schedule of payments to internal and external addresses, following the same algo
as in normal Joinmarket and described [here](https://github.com/JoinMarket-Org/joinmarket/wiki/Step-by-step-running-the-tumbler).

For detailed information on how to use this, please read [this](https://github.com/AdamISZ/joinmarket-clientserver/tree/master/docs/tumblerguide.md).

### wallet-tool.py

This is the same as in normal Joinmarket.

### joinmarketd.py

This file is to be considered experimental for now. It only
takes two arguments, the port it serves on (default 27183), and whether to use TLS for
client-server communication (default 0=no tls, 1=tls):

    `python joinmarketd.py [port number] [1/0]`

To use tls you must create a `key.pem` and `cert.pem` in a subdirectory `/ssl`, representing
a self-signed certificate. This needs some work to be cleaned up, but does work already.

### add-utxo.py

This works exactly as in normal Joinmarket, with the exception of the location
of the `commitments.json` file, explained above.

### sendtomany.py

As above.

### genwallet.py

Non-interactively generate a wallet, giving only wallet name and password. Returns wallet seed as `recovery_seed:`. Useful for automating JoinMarket deployments.
