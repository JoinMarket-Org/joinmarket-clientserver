#!/usr/bin/env python3

"""
A rudimentary implementation of a server, allowing POST of proposals
in base64 format, with POW attached required,
and GET of all current proposals, for SNICKER.
Serves only over Tor onion service.
For persistent onion services, specify public port, local port and
hidden service directory:

`python snicker-server.py 80 7080 /my/hiddenservicedir`

... and (a) make sure these settings match those in your Tor config,
and also (b) note that the hidden service hostname may not be displayed
if the running user, understandably, do not have permissions to read that
directory.

If you only want an ephemeral onion service, for testing, just run without
arguments:

`python snicker-server.py`

"""

from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.web.server import Site
from twisted.web.resource import Resource
from twisted.internet.endpoints import TCP4ClientEndpoint, UNIXClientEndpoint, serverFromString
import txtorcon
import sys
import base64
import json
import sqlite3
import threading
from io import BytesIO
from jmbase import jmprint, hextobin, verify_pow
from jmclient import process_shutdown, jm_single, load_program_config
from jmclient.configure import get_log

# Note: this is actually a duplication of the
# string in jmbitcoin.secp256k1_ecies, but this is deliberate,
# as we want this tool to have no dependency on jmbitcoin.
ECIES_MAGIC_BYTES = b'BIE1'

log = get_log()

database_file_name = "proposals.db"
database_table_name = "proposals"

class SNICKERServer(Resource):
    # rudimentary: flat file, TODO location of file
    DATABASE = "snicker-proposals.txt"

    def __init__(self):
        self.dblock = threading.Lock()
        self.conn = sqlite3.connect(database_file_name, check_same_thread=False)
        # TODO: ?
        #con.row_factory = dict_factory

        self.cursor = self.conn.cursor()
        try:
            self.dblock.acquire(True)
            # note the pubkey is *NOT* a primary key, by
            # design; we need to be able to create multiple
            # proposals against one key.
            self.cursor.execute("CREATE TABLE IF NOT EXISTS {}("
                "pubkey TEXT NOT NULL, proposal TEXT NOT NULL, "
                "unique (pubkey, proposal));".format(database_table_name))
        finally:
            self.dblock.release()

        # initial PoW setting; todo, change this:
        self.set_pow_target_bits(8)
        self.nonce_length = 10
        super().__init__()

    isLeaf = True

    def set_pow_target_bits(self, nbits):
        self.nbits = nbits

    def get_pow_target_bits(self):
        return self.nbits

    def return_error(self, request, error_meaning,
                    error_code="unavailable", http_code=400):
        """
        We return, to the sender, stringified json in the body as per the above.
        """
        request.setResponseCode(http_code)
        request.setHeader(b"content-type", b"text/html; charset=utf-8")
        log.debug("Returning an error: " + str(
            error_code) + ": " + str(error_meaning))
        return json.dumps({"errorCode": error_code,
                           "message": error_meaning}).encode("utf-8")

    def render_GET(self, request):
        """GET request to "/" retrieves the entire current data set.
        GET "/target" retrieves the current nbits target for PoW.
        It's intended that proposers request the target in real time
        before each submission, so that the server can dynamically update
        it at any time.
        """
        log.debug("GET request, path: {}".format(request.path))
        if request.path == b"/target":
            return self.serve_pow_target(request)
        if request.path != b"/":
            return self.return_error(request, "Invalid request path",
                                     "invalid-request-path")
        proposals = self.get_all_current_proposals()
        request.setHeader(b"content-length",
                          ("%d" % len(proposals)).encode("ascii"))
        return proposals.encode("ascii")

    def serve_pow_target(self, request):
        targetbits = ("%d" % self.nbits).encode("ascii")
        request.setHeader(b"content-length",
                          ("%d" % len(targetbits)).encode("ascii"))
        return targetbits

    def render_POST(self, request):
        """ An individual proposal may be submitted in base64, with key
        appended after newline separator in hex.
        """
        log.debug("The server got this POST request: ")
        # unfortunately the twisted Request object is not
        # easily serialized:
        log.debug(request)
        log.debug(request.method)
        log.debug(request.uri)
        log.debug(request.args)
        sender_parameters = request.args
        log.debug(request.path)
        # defer logging of raw request content:
        proposals = request.content
        if not isinstance(proposals, BytesIO):
            return self.return_error(request, "Invalid request format",
                                         "invalid-request-format")
        proposals = proposals.read()
        # for now, only allowing proposals of form "base64ciphertext,hexkey",
        #newline separated:
        proposals = proposals.split(b"\n")
        log.debug("Client send proposal list of length: " + str(
            len(proposals)))
        accepted_proposals = []
        for proposal in proposals:
            if len(proposal) == 0:
                continue
            try:
                encryptedtx, key, nonce = proposal.split(b",")
                bin_key = hextobin(key.decode('utf-8'))
                bin_nonce = hextobin(nonce.decode('utf-8'))
                base64.b64decode(encryptedtx)
            except:
                log.warn("This proposal was not accepted: " + proposal.decode(
                    "utf-8"))
                # give up immediately in case of format error:
                return self.return_error(request, "Invalid request format",
                                         "invalid-request-format")
            if not verify_pow(proposal, nbits=self.nbits, truncate=32):
                return self.return_error(request, "Insufficient PoW",
                                         "insufficient proof of work")
            accepted_proposals.append((key, encryptedtx))

        # the proposals are valid format-wise; add them to the database
        for p in accepted_proposals:
            # note we will ignore errors here and continue;
            # warning will be shown in logs from called fn.
            self.add_proposal(p)
        content = "{} proposals accepted".format(len(accepted_proposals))
        request.setHeader(b"content-length", ("%d" % len(content)).encode(
            "ascii"))
        return content.encode("ascii")

    def add_proposal(self, p):
        proposal_to_add = tuple(x.decode("utf-8") for x in p)
        try:
            self.cursor.execute('INSERT INTO {} VALUES(?, ?);'.format(
            database_table_name),proposal_to_add)
        except sqlite3.Error as e:
            log.warn("Error inserting data into table: {}".format(
                " ".join(e.args)))
            return False
        self.conn.commit()
        return True

    def dbquery(self, querystr, params, return_results=False):
        try:
            self.dblock.acquire(True)
            if return_results:
                return self.cursor.execute(
                    querystr, params).fetchall()
            self.cursor.execute(querystr, params)
        finally:
            self.dblock.release()

    def get_all_keys(self):
        rows = self.dbquery('SELECT DISTINCT pubkey FROM {};'.format(
                database_table_name), (), True)
        if not rows:
            return []
        return list([x[0] for x in rows])

    @classmethod
    def db_row_to_proposal_string(cls, row):
        assert len(row) == 2
        key, proposal = row
        return proposal + "," + key

    def get_all_current_proposals(self):
        rows = self.dbquery('SELECT * from {};'.format(
            database_table_name), (), True)
        return "\n".join([self.db_row_to_proposal_string(x) for x in rows])

    def get_proposals_for_key(self, key):
        rows = self.dbquery('SELECT proposal FROM {} WHERE pubkey=?'.format(
                        database_table_name), (key,), True)
        if not rows:
            return []
        return rows

class SNICKERServerManager(object):

    def __init__(self, port, local_port=None,
                 hsdir=None,
                 control_port=9051,
                 uri_created_callback=None,
                 info_callback=None,
                 shutdown_callback=None):
        # port is the *public* port, default 80
        # if local_port is None, we follow the process
        # to create an ephemeral hidden service.
        # if local_port is a valid port, we start the
        # hidden service configured at directory hsdir.
        # In the latter case, note the patch described at
        # https://github.com/meejah/txtorcon/issues/347 is required.
        self.port = port
        self.local_port = local_port
        if self.local_port is not None:
            assert hsdir is not None
            self.hsdir = hsdir
            self.control_port = control_port
        if not uri_created_callback:
            self.uri_created_callback = self.default_info_callback
        else:
            self.uri_created_callback = uri_created_callback
        if not info_callback:
            self.info_callback = self.default_info_callback
        else:
            self.info_callback = info_callback

        self.shutdown_callback =shutdown_callback

    def default_info_callback(self, msg):
        jmprint(msg)

    def start_snicker_server_and_tor(self):
        """ Packages the startup of the receiver side.
        """
        self.server = SNICKERServer()
        self.site = Site(self.server)
        self.site.displayTracebacks = False
        jmprint("Attempting to start onion service on port: " + str(
            self.port) + " ...")
        self.start_tor()

    def setup_failed(self, arg):
        errmsg = "Setup failed: " + str(arg)
        log.error(errmsg)
        self.info_callback(errmsg)
        process_shutdown()

    def create_onion_ep(self, t):
        if self.local_port:
            endpointString = "onion:{}:controlPort={}:localPort={}:hiddenServiceDir={}".format(
                self.port, self.control_port,self.local_port, self.hsdir)
            return serverFromString(reactor, endpointString)
        else:
            # ephemeral onion:
            self.tor_connection = t
            return t.create_onion_endpoint(self.port, version=3)

    def onion_listen(self, onion_ep):
        return onion_ep.listen(self.site)

    def print_host(self, ep):
        """ Callback fired once the HS is available;
        receiver user needs a BIP21 URI to pass to
        the sender:
        """
        self.info_callback("Your hidden service is available: ")
        # Note that ep,getHost().onion_port must return the same
        # port as we chose in self.port; if not there is an error.
        assert ep.getHost().onion_port == self.port
        self.uri_created_callback(str(ep.getHost().onion_uri))

    def start_tor(self):
        """ This function executes the workflow
        of starting the hidden service.
        """
        if not self.local_port:
            control_host = jm_single().config.get("PAYJOIN", "tor_control_host")
            control_port = int(jm_single().config.get("PAYJOIN", "tor_control_port"))
            if str(control_host).startswith('unix:'):
                control_endpoint = UNIXClientEndpoint(reactor, control_host[5:])
            else:
                control_endpoint = TCP4ClientEndpoint(reactor, control_host, control_port)
            d = txtorcon.connect(reactor, control_endpoint)
            d.addCallback(self.create_onion_ep)
            d.addErrback(self.setup_failed)
        else:
            d = Deferred()
            d.callback(None)
            d.addCallback(self.create_onion_ep)
        # TODO: add errbacks to the next two calls in
        # the chain:
        d.addCallback(self.onion_listen)
        d.addCallback(self.print_host)

    def shutdown(self):
        self.tor_connection.protocol.transport.loseConnection()
        process_shutdown(self.mode)
        self.info_callback("Hidden service shutdown complete")
        if self.shutdown_callback:
            self.shutdown_callback()

def snicker_server_start(port, local_port=None, hsdir=None):
    ssm = SNICKERServerManager(port, local_port=local_port, hsdir=hsdir)
    ssm.start_snicker_server_and_tor()

if __name__ == "__main__":
    load_program_config(bs="no-blockchain")
    # in testing, we can optionally use ephemeral;
    # in testing or prod we can use persistent:
    if len(sys.argv) < 2:
        snicker_server_start(80)
    else:
        port = int(sys.argv[1])
        local_port = int(sys.argv[2])
        hsdir = sys.argv[3]
        snicker_server_start(port, local_port, hsdir)
    reactor.run()
