# joinmarket-clientserver
Joinmarket refactored to separate client and backend operations

Use `virtualenv` to manage dependencies, e.g. follow this workflow:

    git clone https://github.com/AdamISZ/joinmarket-clientserver
    cd joinmarket-clientserver
    virtualenv .
    source bin/activate
    
Next, you can install in 3 different modes:

1. For the "backend", a daemon, install:

    `python setup.py --backend install`

 Then, you can run the daemon with `cd scripts; python joinmarketd.py <port number>`
 
2. For the client code, using joinmarket's own bitcoin library on the command line:
 
    `python setup.py --client-bitcoin install`

 Then, once the daemon is up, you can run sendpayment (e.g. against regtest):

     `cd scripts; python sendpayment.py -p <port number> <other params> ..` 
 
 with similar parameters as for normal Joinmarket, see the notes at the top of the file.
 This is currently only for testing, but is nearly in a real-world usable state, and is
 working OK on regtest.

3. For the client code, using another bitcoin backend library (currently only Electrum
supported, see https://github.com/AdamISZ/electrum-joinmarket-plugin for details):

    `python setup.py --client-only install`

 You can then access the library via `import jmclient`. In particular the
 jmclient.Taker class must be instantiated.

Test instructions and test scripts: todo.