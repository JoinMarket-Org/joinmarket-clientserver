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

 Then, you can run the daemon with `python joinmarketd.py <port number>`
 
2. For the client code, using joinmarket's own bitcoin library on the command line:
 
    `python setup.py --client-bitcoin install`

 Then, once the daemon is up, you can run sendpayment (e.g. against regtest) with
 exactly the same parameters as for normal Joinmarket, refer to the main joinmarket
 repo for details, with one addition: use the flag `-p` to specify the daemon port.

3. For the client code, using another bitcoin backend library (currently only Electrum
supported, see https://github.com/AdamISZ/electrum-joinmarket-plugin for details):

    `python setup.py --client-only install`
