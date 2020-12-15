import hashlib
from .support import bintohex

def get_pow(data, noncelen=10, hashfn=hashlib.sha512,
            hashlen=64, nbits=1, truncate=0, maxiterations=10**8):
    """ Arguments:
    data - a string of bytes.
    noncelen - an int, the number of additional bytes to be appended
    to the bytestring `data` which will be used for grinding.
    hashfn - a function that outputs a finalized hash state that can
    be converted to a bytestring with .digest() (see hashlib).
    hashlen - the length of the bytestring created with the .digest()
    call just mentioned.
    nbits - an integer, the number of bits of proof of work required.
    truncate - an integer number of bytes to be truncated from the end
    of the hash digest created.
    maxiterations - an integer, how many grinding attempts maximum allowed
    to attempt to reach the target, before giving up.
    Returns:
    (nonceval, pow-preimage, niterations)
    where pow-preimage is data+nonce-in-bytes
    or
    (None, failure-reason, None)
    """
    maxbits = (hashlen-truncate)*8
    pow_target = 2 ** (maxbits - nbits)
    # note since we are using a trivial counter, two
    # elements of returned tuple are the same, this needn't be the case.
    for nonceval in range(maxiterations):
        x = data + bintohex(nonceval.to_bytes(noncelen, "big")).encode(
            "utf-8")
        pow_candidate = hashfn(x).digest()[:truncate]
        if int.from_bytes(pow_candidate, "big") < pow_target:
            return (nonceval, x, nonceval)
    return (None, "exceeded max-iterations: {}".format(maxiterations), None)

def verify_pow(data, hashfn=hashlib.sha512, hashlen=64, nbits=1, truncate=0):
    return int.from_bytes(hashfn(data).digest()[:truncate],
                          "big") < 2 ** ((hashlen - truncate) * 8 - nbits)
        
            