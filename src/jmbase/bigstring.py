import itertools
from twisted.protocols import amp


def split_string(x, size):
    return list(x[i*size:(i+1)*size] for i in range((len(x)+size-1)//size))

class StringList(amp.Argument):
    def fromBox(self, name, strings, objects, proto):
        nk = amp._wireNameToPythonIdentifier(name)
        objects[nk] = list(itertools.takewhile(bool, (strings.pop(b'%s.%d' % (name, i), None) for i in itertools.count())))

    def toBox(self, name, strings, objects, proto):
        for i, elem in enumerate(objects.pop(name)):
            strings[b'%s.%d' % (name, i)] = elem

class BigString(StringList):
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
        nk = amp._wireNameToPythonIdentifier(name)
        StringList.fromBox(self, name, strings, objects, proto)
        objects[nk] = b''.join((elem) for elem in objects[nk]).decode('utf-8')

    def toBox(self, name, strings, objects, proto):
        obj = self.retrieve(objects, amp._wireNameToPythonIdentifier(name), proto).encode('utf-8')
        objects[name] = split_string(obj, amp.MAX_VALUE_LENGTH)
        StringList.toBox(self, name, strings, objects, proto)

class BigUnicode(BigString):
    def toString(self, inObject):
        return BigString.toString(self, inObject.encode('utf-8'))

    def fromString(self, inString):
        return BigString.fromString(self, inString).decode('utf-8')
