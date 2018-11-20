#! /usr/bin/env python
from __future__ import print_function
from jmbase.support import debug_dump_object, joinmarket_alert

def test_debug_dump_object():
    joinmarket_alert[0] = "dummy jm alert"
    class TestObj(object):
        def __init__(self):
            self.x = "foo"
            self.password = "bar"
            self.y = "baz"
    to = TestObj()
    debug_dump_object(to)
    to.given_password = "baa"
    debug_dump_object(to)
    to.extradict = {1:2, 3:4}
    debug_dump_object(to)
    to.extralist = ["dummy", "list"]
    debug_dump_object(to)
    to.extradata = 100
    debug_dump_object(to, skip_fields="y")




