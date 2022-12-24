### Test instructions (for developers):

Work in your `jmvenv` virtual environment as for all Joinmarket work. Make sure to have [bitcoind](https://bitcoin.org/en/full-node) 0.18 or newer installed. Also need miniircd installed to the root (i.e. in your `joinmarket-clientserver` directory):

    (jmvenv)$ cd /path/to/joinmarket-clientserver
    (jmvenv)$ git clone https://github.com/Joinmarket-Org/miniircd

Install the test requirements:

    (jmvenv)$ pip install -r requirements/testing.txt

#### Running the test suite.

Have a `bitcoin.conf` ready in some location, whose contents only need to be:

```
rpcuser=bitcoinrpc
rpcpassword=123456abcdef
fallbackfee=0.0002
```

(any random password is fine of course). It is also advisable to wipe ~/.bitcoin/regtest first, in case it gets large and slow to process.

Then copy the `regtest_joinmarket.cfg` file from the `test/` directory to the `joinmarket-clientserver/` directory and rename it to `joinmarket.cfg`; you probably won't need to change anything in the file except perhaps the above password, and the `native` setting if you're doing bech32 wallet tests.

Run the test suite via pytest:

    (jmvenv)$ pytest --btcconf=/path/to/bitcoin.conf --btcroot=/path/to/bitcoin/bin/ --btcpwd=123456abcdef --nirc=2 -p no:warnings

#### Running tests of sendpayment and tumbler (including with malicious makers)

The file `test/ygrunner.py` provides the ability to spin up a set of yieldgenerator
bots against the local IRC instance with the local regtest blockchain. It can be
started with

    (jmvenv)$ pytest --btcconf=/path/to/bitcoin.conf --btcroot=/path/to/bitcoin/bin/ --btcpwd=123456abcdef --nirc=2 test/ygrunner.py -s

Here the `-s` flag is necessary because it prints log output to the console. If you
keep the logging level at the default `INFO` only a minimum amount will come out, if
you want more then enter this into the `joinmarket.cfg` in the `joinmarket-clientserver/` directory:

    [LOGGING]
    console_log_level = DEBUG

It will print out a hex seed for a wallet you can use for tumble/sendpayment (just set the walletname to that hex value).
Next, go into the `scripts/` directory and make sure you have copied the `joinmarket.cfg` (from `test/regtest_joinmarket.cfg`, as above)
file into that directory also, make any changes needed (like the LOGGING one above),
and run either sendpayment or tumbler with whatever parameters you choose, BUT: remember to add the `--datadir=.` argument so that your test `joinmarket.cfg` file gets picked up, not the one in `~/.joinmarket`.

So for example:

```
(jmvenv)$ python sendpayment.py -N2 -m1 5c88acf2546bd7b083b9cfb2e0af7f2d --datadir=. 30000000 2Address
```

To change the parameters of the yieldgenerators you can edit the parametrization of
the function `test_start_ygs` in [this file](https://github.com/Joinmarket-Org/joinmarket-clientserver/blob/master/test/ygrunner.py).

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

You can follow the process above using `test/ygrunner.py` to set up the environment, and then just run:

```
(jmvenv)$ python joinmarket-qt.py --datadir=.
```

When loading a wallet here, regtest will be detected and will request a hex seed as described above.

The 'generate' and 'recover' functions will not work like this on regtest, but you can generate a file-based wallet on regtest from the command line,
and then load it with a one line hack to the joinmarket-qt.py file (I'll let you work that out, if you got this far :) ).
You can also do full tumbler tests, on regtest, using the GUI, using this setup. Spin up ygrunner.py as described above, then start the tumbler wizard
in the 'CoinJoin' tab, and the multi- subtab, and choose Generate Tumbler Schedule. There are 3 default destination addresses provided although
you may want to change them, depending on the test.
