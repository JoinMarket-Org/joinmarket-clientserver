### Test instructions (for developers):

This is a rough sketch, some more background is found in [JM wiki](https://github.com/Joinmarket-Org/joinmarket/wiki/Testing)

Make sure to have bitcoind installed. Also need miniircd installed to the root dir:

    git clone https://github.com/Joinmarket-Org/miniircd

Install the test requirements (still in your virtualenv as mentioned above):

    pip install -r requirements-dev.txt

Curl is also needed:

    sudo apt-get install curl

Running the test suite should be done like:

    python -m py.test --cov=jmclient --cov=jmbitcoin --cov=jmbase --cov=jmdaemon --cov-report html --btcroot=/path/to/bitcoin/bin/ --btcpwd=123456abcdef --btcconf=/path/to/bitcoin.conf --nirc=2
    
(you'll first want to copy bitcoin.conf in the test/ directory to a place you choose, and
copy the regtest_joinmarket.cfg file from the test/ directory to the root directory,
both files will need minor edits for your btc configuration).

### Running tests of sendpayment and tumbler (including with malicious makers)

The file `test/ygrunner.py` provides the ability to spin up a set of yieldgenerator
bots against the local IRC instance with the local regtest blockchain. It can be
started with

    py.test --btcroot=/path/to/bitcoin/bin/ --btcpwd=123456abcdef --btcconf=/path/to/bitcoin.conf --nirc=2 test/ygrunner.py -s

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
