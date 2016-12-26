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
