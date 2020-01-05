### Test instructions (for developers):

This is a rough sketch, some more background is found in [JM wiki](https://github.com/Joinmarket-Org/joinmarket/wiki/Testing)

Make sure to have [bitcoind](https://bitcoin.org/en/full-node) 0.17 or newer installed. Also need miniircd installed to the root (i.e. in your `joinmarket-clientserver` directory):

    cd ~/joinmarket-clientserver
    git clone https://github.com/Joinmarket-Org/miniircd

Install the test requirements (still in your virtualenv as mentioned above):

    pip install -r requirements/testing.txt

Running the test suite should be done something like (advisable to wipe ~/.bitcoin/regtest first):

    pytest --btcconf=/path/to/bitcoin.conf --btcroot=/path/to/bitcoin/bin/ --btcpwd=whatever --nirc=2 --ignore test/test_full_coinjoin.py -p no:warnings
    
(you'll first want to copy the regtest_joinmarket.cfg file from the test/ directory to the root directory,
this file will need minor edits for your btc configuration).

### Running tests of sendpayment and tumbler (including with malicious makers)

(As well as the below, there is a rudimentary "single, automatic, end-to-end coinjoin test" in the file test/test_full_coinjoin.py. Recommended to run it
with -s to see log output; what's "rudimentary" here is that errors may simply result in the process hanging, so you'll want to investigate in that case.
Use command line:

    pytest --btcconf=/path/to/bitcoin.conf --btcroot=/path/to/bitcoin/bin/ --btcpwd=whatever --nirc=2 test/test_full_coinjoin.py -s

)

The file `test/ygrunner.py` provides the ability to spin up a set of yieldgenerator
bots against the local IRC instance with the local regtest blockchain. It can be
started with

    pytest --btcroot=/path/to/bitcoin/bin/ --btcpwd=123456abcdef --nirc=2 test/ygrunner.py -s

Here the `-s` flag is useful because it prints log output to the console. If you
keep the logging level at the default `INFO` only a minimum amount will come out, if
you want more then enter this into the `joinmarket.cfg` in the root directory:

    [LOGGING]
    console_log_level = DEBUG

It will print out a hex seed for a wallet you can use for tumble/sendpayment. Next,
go into the `scripts/` directory and make sure you have copied the `regtest_joinmarket.cfg`
file into that directory also, make any changes needed (like the LOGGING one above),
and run either sendpayment or tumbler with whatever parameters you choose.

To change the parameters of the yieldgenerators you can edit the parametrization of
the function `test_start_ygs` in [this file](https://github.com/AdamISZ/joinmarket-clientserver/blob/master/test/ygrunner.py).

There are two changes that may be of special interest:
* to change the number of yg
bots from e.g. 3 to 4, edit the first number in the parameter list entry to 3 and the
third entry to 4 (4 means three ygs plus one taker bot). 

* More advanced case: To make the yg bots selectively (randomly) malicious, edit the last entry from 0 to some non-zero
integer representing a percentage chance of rejection, both at the receive-auth
stage and the receive-tx stage. So if you set this to 20, it means there will be
a 20% chance of *each* yg bot rejecting the auth message and the tx message (both
20%). If you are running tumbler in adversarial conditions like that, consider
changing things like the taker_utxo_retries or adding external commitments with
the add-utxo tool so external commitments usage can be tested.

### Testing Joinmarket-Qt with regtest

You can follow the process above using `test/ygrunner.py` to set up the environment, and then just run `python joinmarket-qt.py` from within the `scripts` directory.
Note that you can load a random/empty wallet with a 32 char hex string, or more usefully,
use the provided wallet with coins in it, as described above.

The 'generate' and 'recover' functions will not work like this on regtest, but you can generate a file-based wallet on regtest from the command line,
and then load it with a one line hack to the joinmarket-qt.py file (I'll let you work that out, if you got this far :) ).
You can also do full tumbler tests, on regtest, using the GUI, using this setup. Spin up ygrunner.py as described above, then start the tumbler wizard
in the 'CoinJoin' tab, and the multi- subtab, and choose Generate Tumbler Schedule. There are 3 default destination addresses provided although
you may want to change them, depending on the test.
