from __future__ import absolute_import, print_function
# Copyright (C) 2013,2015 by Daniel Kraft <d@domob.eu>
# Copyright (C) 2014 by phelix / blockchained.com
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import base64
import httplib
import json


class JsonRpcError(Exception):
    """
  The called method returned an error in the JSON-RPC response.
  """

    def __init__(self, obj):
        self.code = obj["code"]
        self.message = obj["message"]


class JsonRpcConnectionError(Exception):
    """
  Error thrown when the RPC connection itself failed.  This means
  that the server is either down or the connection settings
  are wrong.
  """

    pass


class JsonRpc(object):
    """
  Simple implementation of a JSON-RPC client that is used
  to connect to Bitcoin.
  """

    def __init__(self, host, port, user, password):
        self.host = host
        self.port = port
        self.conn = httplib.HTTPConnection(self.host, self.port)
        self.authstr = "%s:%s" % (user, password)

        self.queryId = 1

    def queryHTTP(self, obj):
        """
    Send an appropriate HTTP query to the server.  The JSON-RPC
    request should be (as object) in 'obj'.  If the call succeeds,
    the resulting JSON object is returned.  In case of an error
    with the connection (not JSON-RPC itself), an exception is raised.
    """

        headers = {"User-Agent": "joinmarket",
                   "Content-Type": "application/json",
                   "Accept": "application/json"}
        headers["Authorization"] = "Basic %s" % base64.b64encode(self.authstr)

        body = json.dumps(obj)

        while True:
            try:
                self.conn.request("POST", "", body, headers)
                response = self.conn.getresponse()

                if response.status == 401:
                    self.conn.close()
                    raise JsonRpcConnectionError(
                            "authentication for JSON-RPC failed")

                # All of the codes below are 'fine' from a JSON-RPC point of view.
                if response.status not in [200, 404, 500]:
                    self.conn.close()
                    raise JsonRpcConnectionError("unknown error in JSON-RPC")

                data = response.read()

                return json.loads(data)

            except JsonRpcConnectionError as exc:
                raise exc
            except httplib.BadStatusLine:
                return "CONNFAILURE"
            except Exception as exc:
                if str(exc) == "Connection reset by peer":
                    self.conn.connect()
                    continue
                else:
                    raise JsonRpcConnectionError("JSON-RPC connection failed. Err:" +
                                                 repr(exc))
            break

    def call(self, method, params):
        """
    Call a method over JSON-RPC.
    """

        currentId = self.queryId
        self.queryId += 1

        request = {"method": method, "params": params, "id": currentId}
        #query can fail from keepalive timeout; keep retrying if it does, up
        #to a reasonable limit, then raise (failure to access blockchain
        #is a critical failure). Note that a real failure to connect (e.g.
        #wrong port) is raised in queryHTTP directly.
        response_received = False
        for i in range(100):
            response = self.queryHTTP(request)
            if response != "CONNFAILURE":
                response_received = True
                break
            #Failure means keepalive timed out, just make a new one
            self.conn = httplib.HTTPConnection(self.host, self.port)
        if not response_received:
            raise JsonRpcConnectionError("Unable to connect over RPC")
        if response["id"] != currentId:
            raise JsonRpcConnectionError("invalid id returned by query")

        if response["error"] is not None:
            raise JsonRpcError(response["error"])
        return response["result"]
