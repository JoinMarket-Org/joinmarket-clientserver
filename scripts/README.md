# Command line scripts for Joinmarket


All user level scripts here.

(The phrase "normal Joinmarket" in the below refers to the [existing repo](https://github.com/Joinmarket-Org/joinmarket).

The subdirectories `logs` and `wallets` have the same role as in normal Joinmarket.
The subdirectory `cmtdata` contains only your `commitments.json` storage of your used
commitments (ignored by github of course!). The filename is set in joinmarket.cfg.

The `joinmarket.cfg` will be created and maintained in this directory.

Brief explanation of the function of each of the scripts:

###sendpayment.py

Either use the same syntax as for normal Joinmarket:

    `python sendpayment.py --fast -N 3 -m 1 -P wallet.json 50000000 <address>`

or use the new schedule approach. For an example, see the [sample schedule file](https://github.com/AdamISZ/joinmarket-clientserver/blob/master/scripts/sample-schedule-for-testnet).
Do:

    `python sendpayment.py --fast -S sample-schedule-for-testnet wallet.json`

Note that the magic string `INTERNAL` in the file creates a payment to a new address
in the next mixdepth (wrapping around to zero if you reach the maximum mixdepth).

The schedule file can have any name, and is a comma separated value file, the lists
must follow that format (length 4 items).

###wallet-tool.py

This is the same as in normal Joinmarket.

###joinmarketd.py

This file's role is explained in the main README in the top level directory. It only
takes one argument, the port it serves on (default 27183):

    `python joinmarketd.py 27183`

###add-utxo.py

This works exactly as in normal Joinmarket, with the exception of the location
of the `commitments.json` file, explained above.

###sendtomany.py

As above.

More details above, and probably more scripts, will be added later.