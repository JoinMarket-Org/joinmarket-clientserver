# joinmarket-clientserver
Joinmarket refactored to separate client and backend operations

Motivation: By separating the code which manages conversation with other
Joinmarket participants from the code which manages this participant's Bitcoin
wallet actions, we get a considerable gain at a minor cost of an additional layer:
code dependencies for each part are much reduced, security requirements of the 
server/daemon layer are massively reduced (which can have several advantages such as
it being more acceptable to distribute this layer as a binary), and client code
can be written, implementing application-level logic (do join with coins X under condition X)
using other Bitcoin libraries, or wallets, without knowing anything about
Joinmarket's inter-participant protocol. An example is my work on the Joinmarket
electrum [plugin](https://github.com/AdamISZ/electrum-joinmarket-plugin).

It also
means that updates to the Bitcoin element of Joinmarket, such as P2SH and segwit, should
have extremely minimal to no impact on the backend code, since the latter just implements
communication of a set of formatted messages, and allows the client to decide on
their validity beyond simply syntax.

Joinmarket's own [messaging protocol] is thus enforced *only* in the server/daemon.

The client and server currently communicate using twisted.protocol.amp, see
[AMP](https://amp-protocol.net/) which is a very clean asynchronous messaging protocol,
and the specification of the communication between the client and server is isolated to
[this](https://github.com/AdamISZ/joinmarket-clientserver/blob/master/jmbase/commands.py) module.

The server is currently implemented as a daemon (see `scripts/joinmarketd.py`), in future
it may be convenient to create the option to run it within the same process as the client.

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