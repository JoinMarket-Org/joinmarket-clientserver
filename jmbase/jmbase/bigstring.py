try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
from itertools import count
from twisted.protocols import amp

CHUNK_MAX = 0xffff

class BigString(amp.Argument):
    """
    A byte-string amp.Argument with no 65,535 length limit.

    Each value for a key/value pair in an AMP box may not
    exceed 65,535 bytes in length. So if we *really* want to
    send potentially larger values, this class will implicitly
    encode/decode them to/from an arbitrary additional
    number of key/value pairs that are given automatic key
    names by prefixing this Argument's key name to a counter.
    """
    def fromBox(self, name, strings, objects, proto):
        value = StringIO()
        value.write(strings.get(name))
        for counter in count(2):
            chunk = strings.get("%s.%d" % (name, counter))
            if chunk is None:
                break
            value.write(chunk)
        objects[name] = self.buildvalue(value.getvalue())

    def buildvalue(self, value):
        return value

    def toBox(self, name, strings, objects, proto):
        value = StringIO(self.fromvalue(objects[name]))
        firstChunk = value.read(CHUNK_MAX)
        strings[name] = firstChunk
        counter = 2
        while True:
            nextChunk = value.read(CHUNK_MAX)
            if not nextChunk:
                break
            strings["%s.%d" % (name, counter)] = nextChunk
            counter += 1

    def fromvalue(self, value):
        return value
