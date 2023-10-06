import json
from twisted.protocols.amp import String


class JsonEncodable(String):
    def toString(self, inObject):
        return super().toString(json.dumps(inObject).encode('ascii'))

    def fromString(self, inString):
        return super().fromString(json.loads(inString))
