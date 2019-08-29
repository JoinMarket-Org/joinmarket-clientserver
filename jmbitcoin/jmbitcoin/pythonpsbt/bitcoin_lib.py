'''
Credit for this libary goes to Jimmy Song and the efforts of his Programming Blockchain course
'''

from binascii import hexlify, unhexlify
from io import BytesIO

import hmac
import hashlib

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
BASE58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def hash160(s):
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()


def double_sha256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def encode_base58(s):
    # determine how many 0 bytes (b'\x00') s starts with
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    prefix = b'1' * count
    # convert from binary to hex, then hex to integer
    num = int.from_bytes(s, 'big')
    result = bytearray()
    while num > 0:
        num, mod = divmod(num, 58)
        result.insert(0, BASE58_ALPHABET[mod])

    return prefix + bytes(result)


def encode_base58_checksum(s):
    return encode_base58(s + double_sha256(s)[:4]).decode('ascii')


def decode_base58(s, num_bytes=25, strip_leading_zeros=False):
    num = 0
    for c in s.encode('ascii'):
        num *= 58
        num += BASE58_ALPHABET.index(c)
    combined = num.to_bytes(num_bytes, byteorder='big')
    if strip_leading_zeros:
        while combined[0] == 0:
            combined = combined[1:]
    payload, checksum = combined[:-4], combined[-4:]
    if double_sha256(payload)[:4] != checksum:
        raise ValueError('bad address: {} {}'.format(
            checksum, double_sha256(combined)[:4]))
    return payload


def p2pkh_script(h160):
    '''Takes a hash160 and returns the scriptPubKey'''
    return b'\x76\xa9\x14' + h160 + b'\x88\xac'


def p2sh_script(h160):
    '''Takes a hash160 and returns the scriptPubKey'''
    return b'\xa9\x14' + h160 + b'\x87'


def read_varint(s):
    '''read_varint reads a variable integer from a stream'''
    i = s.read(1)[0]
    if i == 0xfd:
        # 0xfd means the next two bytes are the number
        return little_endian_to_int(s.read(2))
    elif i == 0xfe:
        # 0xfe means the next four bytes are the number
        return little_endian_to_int(s.read(4))
    elif i == 0xff:
        # 0xff means the next eight bytes are the number
        return little_endian_to_int(s.read(8))
    else:
        # anything else is just the integer
        return i


def encode_varint(i):
    '''encodes an integer as a varint'''
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + int_to_little_endian(i, 8)
    else:
        raise ValueError('integer too large: {}'.format(i))


def flip_endian(h):
    '''flip_endian takes a hex string and flips the endianness
    Returns a hexadecimal string
    '''
    # convert hex to binary (use unhexlify)
    b = unhexlify(h)
    # reverse the binary (use [::-1])
    b_rev = b[::-1]
    # convert binary to hex (use hexlify and then .decode('ascii'))
    return hexlify(b_rev).decode('ascii')


def little_endian_to_int(b):
    '''little_endian_to_int takes byte sequence as a little-endian number.
    Returns an integer'''
    # use the from_bytes method of int
    return int.from_bytes(b, 'little')


def int_to_little_endian(n, length):
    '''endian_to_little_endian takes an integer and returns the little-endian
    byte sequence of length'''
    # use the to_bytes method of n
    return n.to_bytes(length, 'little')


def h160_to_p2pkh_address(h160, prefix=b'\x00'):
    '''Takes a byte sequence hash160 and returns a p2pkh address string'''
    # p2pkh has a prefix of b'\x00' for mainnet, b'\x6f' for testnet
    return encode_base58_checksum(prefix + h160)


def h160_to_p2sh_address(h160, prefix=b'\x05'):
    '''Takes a byte sequence hash160 and returns a p2sh address string'''
    # p2sh has a prefix of b'\x05' for mainnet, b'\xc0' for testnet
    return encode_base58_checksum(prefix + h160)

class FieldElement:

    def __init__(self, num, prime):
        self.num = num
        self.prime = prime
        if self.num >= self.prime or self.num < 0:
            error = 'Num {} not in field range 0 to {}'.format(
                self.num, self.prime-1)
            raise RuntimeError(error)

    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime

    def __ne__(self, other):
        if other is None:
            return True
        return self.num != other.num or self.prime != other.prime

    def __repr__(self):
        return 'FieldElement_{}({})'.format(self.prime, self.num)

    def __add__(self, other):
        if self.prime != other.prime:
            raise RuntimeError('Primes must be the same')
        # self.num and other.num are the actual values
        num = (self.num + other.num) % self.prime
        # self.prime is what you'll need to mod against
        prime = self.prime
        # You need to return an element of the same class
        # use: self.__class__(num, prime)
        return self.__class__(num, prime)

    def __sub__(self, other):
        if self.prime != other.prime:
            raise RuntimeError('Primes must be the same')
        # self.num and other.num are the actual values
        num = (self.num - other.num) % self.prime
        # self.prime is what you'll need to mod against
        prime = self.prime
        # You need to return an element of the same class
        # use: self.__class__(num, prime)
        return self.__class__(num, prime)

    def __mul__(self, other):
        if self.prime != other.prime:
            raise RuntimeError('Primes must be the same')
        # self.num and other.num are the actual values
        num = (self.num * other.num) % self.prime
        # self.prime is what you'll need to mod against
        prime = self.prime
        # You need to return an element of the same class
        # use: self.__class__(num, prime)
        return self.__class__(num, prime)

    def __rmul__(self, coefficient):
        num = (self.num * coefficient) % self.prime
        return self.__class__(num=num, prime=self.prime)

    def __pow__(self, n):
        # remember fermat's little theorem:
        # self.num**(p-1) % p == 1
        # you might want to use % operator on n
        prime = self.prime
        num = pow(self.num, n % (prime-1), prime)
        return self.__class__(num, prime)

    def __truediv__(self, other):
        if self.prime != other.prime:
            raise RuntimeError('Primes must be the same')
        # self.num and other.num are the actual values
        other_inv = pow(other.num, self.prime - 2, self.prime)
        num = (self.num * other_inv) % self.prime
        # self.prime is what you'll need to mod against
        prime = self.prime
        # use fermat's little theorem:
        # self.num**(p-1) % p == 1
        # this means:
        # 1/n == pow(n, p-2, p)
        # You need to return an element of the same class
        # use: self.__class__(num, prime)
        return self.__class__(num, prime)


class Point:

    def __init__(self, x, y, a, b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        # x being None and y being None represents the point at infinity
        # Check for that here since the equation below won't make sense
        # with None values for both.
        if self.x is None and self.y is None:
            return
        # make sure that the elliptic curve equation is satisfied
        # y**2 == x**3 + a*x + b
        if self.y**2 != self.x**3 + a*x + b:
            # if not, throw a RuntimeError
            raise RuntimeError('({}, {}) is not on the curve'.format(
                self.x, self.y))

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y \
            and self.a == other.a and self.b == other.b

    def __ne__(self, other):
        return self.x != other.x or self.y != other.y \
            or self.a != other.a or self.b != other.b

    def __repr__(self):
        if self.x is None:
            return 'Point(infinity)'
        else:
            return 'Point({},{})'.format(self.x, self.y)

    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise RuntimeError(
                'Points {}, {} are not on the same curve'.format(self, other))
        # Case 0.0: self is the point at infinity, return other
        if self.x is None:
            return other
        # Case 0.1: other is the point at infinity, return self
        if other.x is None:
            return self
        # Case 1: self.x == other.x, self.y != other.y
        # Result is point at infinity
        if self.x == other.x and self.y != other.y:
            # Remember to return an instance of this class:
            # self.__class__(x, y, a, b)
            return self.__class__(None, None, self.a, self.b)
        # Case 2: self.x != other.x
        if self.x != other.x:
            # Formula (x3,y3)==(x1,y1)+(x2,y2)
            # s=(y2-y1)/(x2-x1)
            s = (other.y - self.y) / (other.x - self.x)
            # x3=s**2-x1-x2
            x = s**2 - self.x - other.x
            # y3=s*(x1-x3)-y1
            y = s*(self.x-x) - self.y
            # Remember to return an instance of this class:
            # self.__class__(x, y, a, b)
            return self.__class__(x, y, self.a, self.b)
        # Case 3: self.x == other.x, self.y == other.y
        else:
            # Formula (x3,y3)=(x1,y1)+(x1,y1)
            # s=(3*x1**2+a)/(2*y1)
            s = (3*self.x**2 + self.a) / (2*self.y)
            # x3=s**2-2*x1
            x = s**2 - 2*self.x
            # y3=s*(x1-x3)-y1
            y = s*(self.x-x) - self.y
            # Remember to return an instance of this class:
            # self.__class__(x, y, a, b)
            return self.__class__(x, y, self.a, self.b)

    def __rmul__(self, coefficient):
        # rmul calculates coefficient * self
        # implement the naive way:
        # start product from 0 (point at infinity)
        # use: self.__class__(None, None, a, b)
        product = self.__class__(None, None, self.a, self.b)
        # loop coefficient times
        # use: for _ in range(coefficient):
        for _ in range(coefficient):
            # keep adding self over and over
            product += self
        # return the product
        return product
        # Extra Credit:
        # a more advanced technique uses point doubling
        # find the binary representation of coefficient
        # keep doubling the point and if the bit is there for coefficient
        # add the current.
        # remember to return an instance of the class


A = 0
B = 7
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class S256Field(FieldElement):

    def __init__(self, num, prime=None):
        super().__init__(num=num, prime=P)

    def hex(self):
        return '{:x}'.format(self.num).zfill(64)

    def __repr__(self):
        return self.hex()

    def sqrt(self):
        return self**((P+1)//4)


class S256Point(Point):
    bits = 256

    def __init__(self, x, y, a=None, b=None):
        a, b = S256Field(A), S256Field(B)
        if x is None:
            super().__init__(x=None, y=None, a=a, b=b)
        elif type(x) == int:
            super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
        else:
            super().__init__(x=x, y=y, a=a, b=b)

    def __repr__(self):
        if self.x is None:
            return 'Point(infinity)'
        else:
            return 'Point({},{})'.format(self.x, self.y)

    def __rmul__(self, coefficient):
        # current will undergo binary expansion
        current = self
        # result is what we return, starts at 0
        result = S256Point(None, None)
        # we double 256 times and add where there is a 1 in the binary
        # representation of coefficient
        for _ in range(self.bits):
            if coefficient & 1:
                result += current
            current += current
            # we shift the coefficient to the right
            coefficient >>= 1
        return result

    def sec(self, compressed=True):
        # returns the binary version of the sec format, NOT hex
        # if compressed, starts with b'\x02' if self.y.num is even,
        # b'\x03' if self.y is odd then self.x.num
        # remember, you have to convert self.x.num/self.y.num to binary
        # (some_integer.to_bytes(32, 'big'))
        if compressed:
            if self.y.num % 2 == 0:
                return b'\x02' + self.x.num.to_bytes(32, 'big')
            else:
                return b'\x03' + self.x.num.to_bytes(32, 'big')
        else:
            # if non-compressed, starts with b'\x04' followod by self.x
            # and then self.y
            return b'\x04' + self.x.num.to_bytes(32, 'big') \
                + self.y.num.to_bytes(32, 'big')

    def h160(self, compressed=True):
        return hash160(self.sec(compressed))

    def p2pkh_script(self, compressed=True):
        h160 = self.h160(compressed)
        return p2pkh_script(h160)

    def address(self, compressed=True, prefix=b'\x00'):
        '''Returns the address string'''
        h160 = self.h160(compressed)
        return encode_base58_checksum(prefix + h160)

    def segwit_redeem_script(self):
        return b'\x16\x00\x14' + self.h160(True)

    def segwit_address(self, prefix=b'\x05'):
        address_bytes = hash160(self.segwit_redeem_script()[1:])
        return encode_base58_checksum(prefix + address_bytes)

    def verify(self, z, sig):
        # remember sig.r and sig.s are the main things we're checking
        # remember 1/s = pow(s, N-2, N)
        s_inv = pow(sig.s, N-2, N)
        # u = z / s
        u = z * s_inv % N
        # v = r / s
        v = sig.r * s_inv % N
        # u*G + v*P should have as the x coordinate, r
        total = u*G + v*self
        return total.x.num == sig.r

    @classmethod
    def parse(self, sec_bin):
        '''returns a Point object from a compressed sec binary (not hex)
        '''
        if sec_bin[0] == 4:
            x = int(hexlify(sec_bin[1:33]), 16)
            y = int(hexlify(sec_bin[33:65]), 16)
            return S256Point(x=x, y=y)
        is_even = sec_bin[0] == 2
        x = S256Field(int(hexlify(sec_bin[1:]), 16))
        # right side of the equation y^2 = x^3 + 7
        alpha = x**3 + S256Field(B)
        # solve for left side
        beta = alpha.sqrt()
        if beta.num % 2 == 0:
            even_beta = beta
            odd_beta = S256Field(P - beta.num)
        else:
            even_beta = S256Field(P - beta.num)
            odd_beta = beta
        if is_even:
            return S256Point(x, even_beta)
        else:
            return S256Point(x, odd_beta)


G = S256Point(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)


class Signature:

    def __init__(self, r, s):
        self.r = r
        self.s = s

    def __repr__(self):
        return 'Signature({:x},{:x})'.format(self.r, self.s)

    def der(self):
        rbin = self.r.to_bytes(32, byteorder='big')
        # remove all null bytes at the beginning
        rbin = rbin.lstrip(b'\x00')
        # if rbin has a high bit, add a 00
        if rbin[0] & 0x80:
            rbin = b'\x00' + rbin
        result = bytes([2, len(rbin)]) + rbin
        sbin = self.s.to_bytes(32, byteorder='big')
        # remove all null bytes at the beginning
        sbin = sbin.lstrip(b'\x00')
        # if sbin has a high bit, add a 00
        if sbin[0] & 0x80:
            sbin = b'\x00' + sbin
        result += bytes([2, len(sbin)]) + sbin
        return bytes([0x30, len(result)]) + result

    @classmethod
    def parse(cls, signature_bin):
        s = BytesIO(signature_bin)
        compound = s.read(1)[0]
        if compound != 0x30:
            raise RuntimeError("Bad Signature")
        length = s.read(1)[0]
        if length + 2 != len(signature_bin):
            raise RuntimeError("Bad Signature Length")
        marker = s.read(1)[0]
        if marker != 0x02:
            raise RuntimeError("Bad Signature")
        rlength = s.read(1)[0]
        r = int(hexlify(s.read(rlength)), 16)
        marker = s.read(1)[0]
        if marker != 0x02:
            raise RuntimeError("Bad Signature")
        slength = s.read(1)[0]
        s = int(hexlify(s.read(slength)), 16)
        if len(signature_bin) != 6 + rlength + slength:
            raise RuntimeError("Signature too long")
        return cls(r, s)


class PrivateKey:

    def __init__(self, secret, compressed=False, testnet=False):
        self.secret = secret
        self.point = secret*G
        self.compressed = compressed
        self.testnet = testnet

    def hex(self):
        return '{:x}'.format(self.secret).zfill(64)

    def deterministic_k(self, z):
        # RFC6979, optimized for secp256k1
        k = b'\x00' * 32
        v = b'\x01' * 32
        if z > N:
            z -= N
        z_bytes = z.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, 'big')
        s256 = hashlib.sha256
        k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        while 1:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, 'big')
            if candidate >= 1 and candidate < N:
                return candidate
            k = hmac.new(k, v + b'\x00', s256).digest()
            v = hmac.new(k, v, s256).digest()

    def sign(self, z):
        # use deterministic signatures
        k = self.deterministic_k(z)
        # r is the x coordinate of the resulting point k*G
        r = (k*G).x.num
        # remember 1/k = pow(k, N-2, N)
        k_inv = pow(k, N-2, N)
        # s = (z+r*secret) / k
        s = (z + r*self.secret) * k_inv % N
        if s > N/2:
            s = N - s
        # return an instance of Signature:
        # Signature(r, s)
        return Signature(r, s)

    def wif(self, prefix=None):
        if prefix is None:
            if self.testnet:
                prefix = b'\xef'
            else:
                prefix = b'\x80'
        # convert the secret from integer to a 32-bytes in big endian using
        # num.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, 'big')
        # append b'\x01' if compressed
        if self.compressed:
            suffix = b'\x01'
        else:
            suffix = b''
        # encode_base58_checksum the whole thing
        return encode_base58_checksum(prefix + secret_bytes + suffix)

    def h160(self):
        return self.point.h160(compressed=self.compressed)

    def address(self, prefix=None):
        if prefix is None:
            if self.testnet:
                prefix = b'\x6f'
            else:
                prefix = b'\x00'
        return self.point.address(compressed=self.compressed, prefix=prefix)

    def segwit_redeem_script(self):
        return self.point.segwit_redeem_script()

    def segwit_address(self, prefix=None):
        if prefix is None:
            if self.testnet:
                prefix = b'\xc4'
            else:
                prefix = b'\x05'
        return self.point.segwit_address(prefix=prefix)

    @classmethod
    def parse(cls, wif):
        secret_bytes = decode_base58(
            wif,
            num_bytes=40,
            strip_leading_zeros=True,
        )
        # remove the first and last if we have 34, only the first if we have 33
        testnet = secret_bytes[0] == 0xef
        if len(secret_bytes) == 34:
            secret_bytes = secret_bytes[1:-1]
            compressed = True
        elif len(secret_bytes) == 33:
            secret_bytes = secret_bytes[1:]
            compressed = False
        else:
            raise RuntimeError('not valid WIF')
        secret = int.from_bytes(secret_bytes, 'big')
        return cls(secret, compressed=compressed, testnet=testnet)


class Script:

    def __init__(self, elements):
        self.elements = elements

    def __repr__(self):
        result = ''
        for element in self.elements:
            if type(element) == int:
                result += '{} '.format(OP_CODES[element])
            else:
                result += '{} '.format(hexlify(element))
        return result

    @classmethod
    def parse(cls, binary):
        s = BytesIO(binary)
        elements = []
        current = s.read(1)
        while current != b'':
            op_code = current[0]
            if op_code > 0 and op_code <= 75:
                # we have an element
                elements.append(s.read(op_code))
            else:
                elements.append(op_code)
            current = s.read(1)
        return cls(elements)

    def type(self):
        '''Some standard pay-to type scripts.'''
        if len(self.elements) == 0:
            return 'blank'
        elif self.elements[0] == 0x76 \
            and self.elements[1] == 0xa9 \
            and type(self.elements[2]) == bytes \
            and len(self.elements[2]) == 0x14 \
            and self.elements[3] == 0x88 \
            and self.elements[4] == 0xac:
            # p2pkh:
            # OP_DUP OP_HASH160 <20-byte hash> <OP_EQUALVERIFY> <OP_CHECKSIG>
            return 'p2pkh'
        elif self.elements[0] == 0xa9 \
            and type(self.elements[1]) == bytes \
            and len(self.elements[1]) == 0x14 \
            and self.elements[-1] == 0x87:
            # p2sh:
            # OP_HASH160 <20-byte hash> <OP_EQUAL>
            return 'p2sh'
        elif type(self.elements[0]) == bytes \
            and len(self.elements[0]) in range(0x40, 0x50) \
            and type(self.elements[1]) == bytes \
            and len(self.elements[1]) in (0x21, 0x41):
            # p2pkh scriptSig:
            # <signature> <pubkey>
            return 'p2pkh sig'
        elif len(self.elements) == 2 \
            and self.elements[0] == 0 \
            and len(self.elements[-1]) == 20 \
            and type(self.elements[-1]) == bytes :
            return 'p2wpkh'
        elif len(self.elements) == 2 \
            and self.elements[0] == 0 \
            and len(self.elements[-1]) == 32 \
            and type(self.elements[-1]) == bytes :
            return 'p2wsh'   
        elif len(self.elements) > 1 \
            and type(self.elements[1]) == bytes \
            and len(self.elements[1]) in range(0x40, 0x50) \
            and type(self.elements[-1]) == bytes \
            and self.elements[-1][-1] == 0xae:
            # HACK: assumes p2sh is a multisig
            # p2sh multisig:
            # <x> <sig1> ... <sigm> <redeemscript ends with OP_CHECKMULTISIG>
            return 'p2sh sig'
        elif len(self.elements) == 1 \
            and type(self.elements[0]) == bytes \
            and len(self.elements[0]) == 0x16:
            # HACK: assumes p2sh can be p2sh-p2pkh
            return 'p2sh sig'
        elif len(self.elements) > 1 \
            and type(self.elements[1]) == bytes \
            and len(self.elements[1]) == 0x21 \
            and self.elements[-1] == 0xae:
            # HACK: Assumes script with 2nd element length of a SEC compressed pubkey
            # and ending with OP_CHECKMULTISG is a multisig redeemScript
            return 'multisig redeem'
        else:
            return 'unknown: {}'.format(self)

    def serialize(self):
        result = b''
        for element in self.elements:
            if type(element) == int:
                result += bytes([element])
            else:
                result += bytes([len(element)]) + element
        return result

    def hash160(self):
        return hash160(self.serialize())

    def der_signature(self, index=0):
        '''index isn't used for p2pkh, for p2sh, means one of m sigs'''
        sig_type = self.type()
        if sig_type == 'p2pkh sig':
            return self.elements[0]
        elif sig_type == 'p2sh sig':
            return self.elements[index+1]
        else:
            raise RuntimeError('script type needs to be p2pkh sig or p2sh sig')

    def sec_pubkey(self, index=0):
        '''index isn't used for p2pkh, for p2sh, means one of n pubkeys'''
        sig_type = self.type()
        if sig_type == 'p2pkh sig':
            return self.elements[1]
        elif sig_type == 'p2sh sig':
            if len(self.elements) > 2:
                # HACK: assumes p2sh is a multisig
                redeem_script = Script.parse(self.elements[-1])
                return redeem_script.elements[index+1]
            else:
                return None
        # Understand multisg redeem scripts
        elif sig_type == 'multisig redeem':
            return self.elements[index+1]

    def num_sigs_required(self):
        '''Returns the number of sigs required. For p2pkh, it's always 1,
        For p2sh multisig, it's the m in the m of n'''
        sig_type = self.type()
        if sig_type == 'p2pkh sig':
            return 1
        elif sig_type == 'p2sh sig':
            if len(self.elements) > 2:
                op_code = OP_CODES[self.elements[-1][0]]
                return int(op_code[3:])
            else:
                return 1
        else:
            raise RuntimeError('script type needs to be p2pkh sig or p2sh sig')

    def redeem_script(self):
        sig_type = self.type()
        if sig_type == 'p2sh sig':
            return self.elements[-1]
        else:
            return

    def address(self, prefix=b'\x00'):
        '''Returns the address corresponding to the script'''
        sig_type = self.type()
        if sig_type == 'p2pkh':
            # hash160 is the 3rd element
            h160 = self.elements[2]
            # convert to p2pkh address using h160_to_p2pkh_address
            # (remember testnet)
            return h160_to_p2pkh_address(h160, prefix)
        elif sig_type == 'p2sh':
            # hash160 is the 2nd element
            h160 = self.elements[1]
            # convert to p2sh address using h160_to_p2sh_address
            # (remember testnet)
            return h160_to_p2sh_address(h160, prefix)
        elif sig_type == 'multisig redeem':
            # Convert multisig redeemscript to p2sh address
            return h160_to_p2sh_address(hash160(self.serialize()), prefix)
            


OP_CODES = {
  0: 'OP_0',
  76: 'OP_PUSHDATA1',
  77: 'OP_PUSHDATA2',
  78: 'OP_PUSHDATA4',
  79: 'OP_1NEGATE',
  80: 'OP_RESERVED',
  81: 'OP_1',
  82: 'OP_2',
  83: 'OP_3',
  84: 'OP_4',
  85: 'OP_5',
  86: 'OP_6',
  87: 'OP_7',
  88: 'OP_8',
  89: 'OP_9',
  90: 'OP_10',
  91: 'OP_11',
  92: 'OP_12',
  93: 'OP_13',
  94: 'OP_14',
  95: 'OP_15',
  96: 'OP_16',
  97: 'OP_NOP',
  98: 'OP_VER',
  99: 'OP_IF',
  100: 'OP_NOTIF',
  101: 'OP_VERIF',
  102: 'OP_VERNOTIF',
  103: 'OP_ELSE',
  104: 'OP_ENDIF',
  105: 'OP_VERIFY',
  106: 'OP_RETURN',
  107: 'OP_TOALTSTACK',
  108: 'OP_FROMALTSTACK',
  109: 'OP_2DROP',
  110: 'OP_2DUP',
  111: 'OP_3DUP',
  112: 'OP_2OVER',
  113: 'OP_2ROT',
  114: 'OP_2SWAP',
  115: 'OP_IFDUP',
  116: 'OP_DEPTH',
  117: 'OP_DROP',
  118: 'OP_DUP',
  119: 'OP_NIP',
  120: 'OP_OVER',
  121: 'OP_PICK',
  122: 'OP_ROLL',
  123: 'OP_ROT',
  124: 'OP_SWAP',
  125: 'OP_TUCK',
  126: 'OP_CAT',
  127: 'OP_SUBSTR',
  128: 'OP_LEFT',
  129: 'OP_RIGHT',
  130: 'OP_SIZE',
  131: 'OP_INVERT',
  132: 'OP_AND',
  133: 'OP_OR',
  134: 'OP_XOR',
  135: 'OP_EQUAL',
  136: 'OP_EQUALVERIFY',
  137: 'OP_RESERVED1',
  138: 'OP_RESERVED2',
  139: 'OP_1ADD',
  140: 'OP_1SUB',
  141: 'OP_2MUL',
  142: 'OP_2DIV',
  143: 'OP_NEGATE',
  144: 'OP_ABS',
  145: 'OP_NOT',
  146: 'OP_0NOTEQUAL',
  147: 'OP_ADD',
  148: 'OP_SUB',
  149: 'OP_MUL',
  150: 'OP_DIV',
  151: 'OP_MOD',
  152: 'OP_LSHIFT',
  153: 'OP_RSHIFT',
  154: 'OP_BOOLAND',
  155: 'OP_BOOLOR',
  156: 'OP_NUMEQUAL',
  157: 'OP_NUMEQUALVERIFY',
  158: 'OP_NUMNOTEQUAL',
  159: 'OP_LESSTHAN',
  160: 'OP_GREATERTHAN',
  161: 'OP_LESSTHANOREQUAL',
  162: 'OP_GREATERTHANOREQUAL',
  163: 'OP_MIN',
  164: 'OP_MAX',
  165: 'OP_WITHIN',
  166: 'OP_RIPEMD160',
  167: 'OP_SHA1',
  168: 'OP_SHA256',
  169: 'OP_HASH160',
  170: 'OP_HASH256',
  171: 'OP_CODESEPARATOR',
  172: 'OP_CHECKSIG',
  173: 'OP_CHECKSIGVERIFY',
  174: 'OP_CHECKMULTISIG',
  175: 'OP_CHECKMULTISIGVERIFY',
  176: 'OP_NOP1',
  177: 'OP_CHECKLOCKTIMEVERIFY',
  178: 'OP_CHECKSEQUENCEVERIFY',
  179: 'OP_NOP4',
  180: 'OP_NOP5',
  181: 'OP_NOP6',
  182: 'OP_NOP7',
  183: 'OP_NOP8',
  184: 'OP_NOP9',
  185: 'OP_NOP10',
  252: 'OP_NULLDATA',
  253: 'OP_PUBKEYHASH',
  254: 'OP_PUBKEY',
  255: 'OP_INVALIDOPCODE',
}


class Tx():

    default_version = 1
    default_hash_type = 1
    cache = {}
    p2pkh_prefixes = (b'\x00', b'\x6f')
    p2sh_prefixes = (b'\x05', b'\xc4')
    testnet_prefixes = (b'\x6f', b'\xc4')
    scale = 100000000
    num_bytes = 25
    fee = 2500
    insight = 'https://btc-bitcore6.trezor.io/api'
    seeds = None

    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet
        self._hash_prevouts = None
        self._hash_sequence = None
        self._hash_outputs = None

    def __repr__(self):
        tx_ins = ''
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + '\n'
        tx_outs = ''
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + '\n'
        return '{}\nversion: {}\ntx_ins:\n{}\ntx_outs:\n{}\nlocktime: {}\n'.format(
            self.hash().hex(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime,
        )

    def hash(self):
        if self.is_segwit():
            result = int_to_little_endian(self.version, 4)
            # encode_varint on the number of inputs
            result += encode_varint(len(self.tx_ins))
            # iterate inputs
            for tx_in in self.tx_ins:
                # serialize each input
                result += tx_in.serialize()
            # encode_varint on the number of inputs
            result += encode_varint(len(self.tx_outs))
            # iterate outputs
            for tx_out in self.tx_outs:
                # serialize each output
                result += tx_out.serialize()
            # serialize locktime (4 bytes, little endian)
            result += int_to_little_endian(self.locktime, 4)
            return double_sha256(result)[::-1]
        else:
            return double_sha256(self.serialize())[::-1]

    def id(self):
        return self.hash().hex()

    @classmethod
    def get_address_data(cls, addr):
        b58 = decode_base58(addr, num_bytes=cls.num_bytes)
        prefix = b58[:-20]
        h160 = b58[-20:]
        testnet = prefix in cls.testnet_prefixes
        if prefix in cls.p2pkh_prefixes:
            script_pubkey = Script.parse(p2pkh_script(h160))
        elif prefix in cls.p2sh_prefixes:
            script_pubkey = Script.parse(p2sh_script(h160))
        else:
            raise RuntimeError('unknown type of address {} {}'.format(addr, prefix))
        return {
            'testnet': testnet,
            'h160': h160,
            'script_pubkey': script_pubkey,
        }

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the transaction at the start
        return a Tx object
        '''
        # s.read(n) will return n bytes
        # version has 4 bytes, little-endian, interpret as int
        version = little_endian_to_int(s.read(4))
        # num_inputs is a varint, use read_varint(s)
        num_inputs = read_varint(s)
        # if we have a segwit marker, we need to parse in another way
        if num_inputs == 0:
            return cls.parse_segwit(s, version)
        # each input needs parsing
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        # num_outputs is a varint, use read_varint(s)
        num_outputs = read_varint(s)
        # each output needs parsing
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        # locktime is 4 bytes, little-endian
        locktime = little_endian_to_int(s.read(4))
        # return an instance of the class (cls(...))
        return cls(version, inputs, outputs, locktime)

    @classmethod
    def parse_segwit(cls, s, version):
        '''Takes a byte stream and parses the segwit transaction in middle
        return a Tx object
        '''
        flag = s.read(1)
        if flag != b'\x01':
            raise RuntimeError('Not a segwit transaction {}'.format(flag))
        # num_inputs is a varint, use read_varint(s)
        num_inputs = read_varint(s)
        # each input needs parsing
        tx_ins = []
        for _ in range(num_inputs):
            tx_ins.append(TxIn.parse(s))
        # num_outputs is a varint, use read_varint(s)
        num_outputs = read_varint(s)
        # each output needs parsing
        tx_outs = []
        for _ in range(num_outputs):
            tx_outs.append(TxOut.parse(s))
        # now parse the witness program
        for tx_in in tx_ins:
            num_elements = read_varint(s)
            elements = [num_elements]
            for _ in range(num_elements):
                element_len = read_varint(s)
                elements.append(s.read(element_len))
            tx_in.witness_program = Script(elements).serialize()
        # locktime is 4 bytes, little-endian
        locktime = little_endian_to_int(s.read(4))
        # return an instance of the class (cls(...))
        return cls(version, tx_ins, tx_outs, locktime)

    def is_segwit(self):
        for tx_in in self.tx_ins:
            if tx_in.is_segwit():
                return True
        return False

    def serialize(self):
        '''Returns the byte serialization of the transaction'''
        if self.is_segwit():
            return self.serialize_segwit()
        # serialize version (4 bytes, little endian)
        result = int_to_little_endian(self.version, 4)
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_ins))
        # iterate inputs
        for tx_in in self.tx_ins:
            # serialize each input
            result += tx_in.serialize()
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_outs))
        # iterate outputs
        for tx_out in self.tx_outs:
            # serialize each output
            result += tx_out.serialize()
        # serialize locktime (4 bytes, little endian)
        result += int_to_little_endian(self.locktime, 4)
        return result

    def serialize_segwit(self):
        '''Returns the byte serialization of the transaction'''
        # serialize version (4 bytes, little endian)
        result = int_to_little_endian(self.version, 4)
        # segwit marker '0001'
        result += b'\x00\x01'
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_ins))
        # iterate inputs
        for tx_in in self.tx_ins:
            # serialize each input
            result += tx_in.serialize()
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_outs))
        # iterate outputs
        for tx_out in self.tx_outs:
            # serialize each output
            result += tx_out.serialize()
        # add the witness data
        for tx_in in self.tx_ins:
            result += tx_in.witness_program
        # serialize locktime (4 bytes, little endian)
        result += int_to_little_endian(self.locktime, 4)
        return result

    def fee(self):
        '''Returns the fee of this transaction in satoshi'''
        # initialize input sum and output sum
        input_sum, output_sum = 0, 0
        # iterate through inputs
        for tx_in in self.tx_ins:
            # for each input get the value and add to input sum
            input_sum += tx_in.value()
        # iterate through outputs
        for tx_out in self.tx_outs:
            # for each output get the amount and add to output sum
            output_sum += tx_out.amount
        # return input sum - output sum
        return input_sum - output_sum

    def hash_prevouts(self):
        if self._hash_prevouts is None:
            all_prevouts = b''
            all_sequence = b''
            for tx_in in self.tx_ins:
                all_prevouts += tx_in.prev_tx[::-1] + int_to_little_endian(tx_in.prev_index, 4)
                all_sequence += int_to_little_endian(tx_in.sequence, 4)
            self._hash_prevouts = double_sha256(all_prevouts)
            self._hash_sequence = double_sha256(all_sequence)
        return self._hash_prevouts

    def hash_sequence(self):
        if self._hash_sequence is None:
            self.hash_prevouts()  # this should calculate self._hash_prevouts
        return self._hash_sequence

    def hash_outputs(self):
        if self._hash_outputs is None:
            all_outputs = b''
            for tx_out in self.tx_outs:
                all_outputs += tx_out.serialize()
            self._hash_outputs = double_sha256(all_outputs)
        return self._hash_outputs

    def sig_hash_preimage_bip143(self, input_index, hash_type, redeem_script=None):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        tx_in = self.tx_ins[input_index]
        # per BIP143 spec
        s = int_to_little_endian(self.version, 4)
        s += self.hash_prevouts() + self.hash_sequence()
        s += tx_in.prev_tx[::-1] + int_to_little_endian(tx_in.prev_index, 4)
        if tx_in.is_segwit() or redeem_script:
            if redeem_script:
                h160 = redeem_script[-20:]
            else:
                h160 = tx_in.redeem_script()[-20:]
            ser = p2pkh_script(h160)
        else:
            ser = tx_in.script_pubkey().serialize()
        s += bytes([len(ser)]) + ser  # script pubkey
        s += int_to_little_endian(tx_in.value(), 8)
        s += int_to_little_endian(tx_in.sequence, 4)
        s += self.hash_outputs()
        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(hash_type, 4)
        return s

    def sig_hash_bip143(self, input_index, hash_type, redeem_script=None):
        s = self.sig_hash_preimage_bip143(input_index, hash_type, redeem_script=redeem_script)
        return int.from_bytes(double_sha256(s), 'big')

    def sig_hash(self, input_index, hash_type):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        # create a transaction serialization where
        # all the input script_sigs are blanked out
        alt_tx_ins = []
        for tx_in in self.tx_ins:
            alt_tx_ins.append(TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                script_sig=b'',
                sequence=tx_in.sequence,
                value=tx_in.value(),
                script_pubkey=tx_in.script_pubkey().serialize(),
            ))
        # replace the input's scriptSig with the scriptPubKey
        signing_input = alt_tx_ins[input_index]
        script_pubkey = signing_input.script_pubkey(self.testnet)
        sig_type = script_pubkey.type()
        if sig_type == 'p2pkh':
            signing_input.script_sig = script_pubkey
        elif sig_type == 'p2sh':
            current_input = self.tx_ins[input_index]
            signing_input.script_sig = Script.parse(
                current_input.redeem_script())
        else:
            raise RuntimeError('not a valid sig_type: {}'.format(sig_type))
        alt_tx = self.__class__(
            version=self.version,
            tx_ins=alt_tx_ins,
            tx_outs=self.tx_outs,
            locktime=self.locktime,
        )
        # add the hash_type
        result = alt_tx.serialize()
        result += int_to_little_endian(hash_type, 4)
        return int.from_bytes(double_sha256(result), 'big')

    def verify_input(self, input_index):
        '''Returns whether the input has a valid signature'''
        # get the relevant input
        tx_in = self.tx_ins[input_index]
        # get the number of signatures required. This is available in tx_in.script_sig.num_sigs_required()
        sigs_required = tx_in.script_sig.num_sigs_required()
        # iterate over the sigs required and check each signature
        for sig_num in range(sigs_required):
            # get the point from the sec format
            sec = tx_in.sec_pubkey(index=sig_num)
            # get the sec_pubkey at current signature index
            point = S256Point.parse(sec)
            # get the der sig and hash_type from input
            # get the der_signature at current signature index
            der, hash_type = tx_in.der_signature(index=sig_num)
            # get the signature from der format
            signature = Signature.parse(der)
            # get the hash to sign
            if tx_in.is_segwit():
                h160 = hash160(tx_in.script_sig.redeem_script())
                if h160 != tx_in.script_pubkey(self.testnet).elements[1]:
                    return False
                pubkey_h160 = tx_in.script_sig.redeem_script()[-20:]
                if pubkey_h160 != point.h160():
                    return False
                z = self.sig_hash_bip143(input_index, hash_type)
            else:
                z = self.sig_hash(input_index, hash_type)
            # use point.verify on the hash to sign and signature
            if not point.verify(z, signature):
                return False
        return True

    def sign_input(self, input_index, private_key, hash_type, compressed=True, redeem_script=None):
        '''Signs the input using the private key'''
        # get the hash to sign
        tx_in = self.tx_ins[input_index]
        if redeem_script:
            z = self.sig_hash_bip143(input_index, hash_type, redeem_script=redeem_script)
        else:
            z = self.sig_hash(input_index, hash_type)
        # get der signature of z from private key
        der = private_key.sign(z).der()
        # append the hash_type to der (use bytes([hash_type]))
        sig = der + bytes([hash_type])
        # calculate the sec
        sec = private_key.point.sec(compressed=compressed)
        if redeem_script:
            # witness program 0
            tx_in.script_sig = Script([redeem_script])
            tx_in.witness_program = Script([2, sig, sec]).serialize()
        else:
            # initialize a new script with [sig, sec] as the elements
            # change input's script_sig to new script
            tx_in.script_sig = Script([sig, sec])
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def is_coinbase(self):
        '''Returns whether this transaction is a coinbase transaction or not'''
        # check that there is exactly 1 input
        if len(self.tx_ins) != 1:
            return False
        # grab the first input
        first_input = self.tx_ins[0]
        # check that first input prev_tx is b'\x00' * 32 bytes
        if first_input.prev_tx != b'\x00' * 32:
            return False
        # check that first input prev_index is 0xffffffff
        if first_input.prev_index != 0xffffffff:
            return False
        return True

    def coinbase_height(self):
        '''Returns the height of the block this coinbase transaction is in
        Returns None if this transaction is not a coinbase transaction
        '''
        # if this is NOT a coinbase transaction, return None
        if not self.is_coinbase():
            return None
        # grab the first input
        first_input = self.tx_ins[0]
        # grab the first element of the script_sig (.script_sig.elements[0])
        first_element = first_input.script_sig.elements[0]
        # convert the first element from little endian to int
        return little_endian_to_int(first_element)

    def verify(self):
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):
                return False
        return True

class TxIn():

    def __init__(self, prev_tx, prev_index, script_sig, sequence, witness_program=b'\x00', value=None, script_pubkey=None):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        self.script_sig = Script.parse(script_sig)
        self.sequence = sequence
        self.witness_program = witness_program
        self._value = value
        if script_pubkey is None:
            self._script_pubkey = None
        else:
            self._script_pubkey = Script.parse(script_pubkey)

    def __repr__(self):
        return '{}:{}'.format(self.prev_tx.hex(), self.prev_index)

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_input at the start
        return a TxIn object
        '''
        # s.read(n) will return n bytes
        # prev_tx is 32 bytes, little endian
        prev_tx = s.read(32)[::-1]
        # prev_index is 4 bytes, little endian, interpret as int
        prev_index = little_endian_to_int(s.read(4))
        # script_sig is a variable field (length followed by the data)
        # get the length by using read_varint(s)
        script_sig_length = read_varint(s)
        script_sig = s.read(script_sig_length)
        # sequence is 4 bytes, little-endian, interpret as int
        sequence = little_endian_to_int(s.read(4))
        # return an instance of the class (cls(...))
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self):
        '''Returns the byte serialization of the transaction input'''
        # serialize prev_tx, little endian
        result = self.prev_tx[::-1]
        # serialize prev_index, 4 bytes, little endian
        result += int_to_little_endian(self.prev_index, 4)
        # get the scriptSig ready (use self.script_sig.serialize())
        raw_script_sig = self.script_sig.serialize()
        # encode_varint on the length of the scriptSig
        result += encode_varint(len(raw_script_sig))
        # add the scriptSig
        result += raw_script_sig
        # serialize sequence, 4 bytes, little endian
        result += int_to_little_endian(self.sequence, 4)
        return result

    def script_pubkey(self, testnet=False):
        '''Get the scriptPubKey by looking up the tx hash on libbitcoin server
        Returns the binary scriptpubkey
        '''
        if self._script_pubkey is None:
            # use self.fetch_tx to get the transaction
            tx = self.fetch_tx(testnet=testnet)
            # get the output at self.prev_index
            # get the script_pubkey property
            self._script_pubkey = tx.tx_outs[self.prev_index].script_pubkey
        return self._script_pubkey

    def der_signature(self, index=0):
        '''returns a DER format signature and hash_type if the script_sig
        has a signature'''
        if self.is_segwit():
            signature = self.witness_program[2:-34]
        else:
            signature = self.script_sig.der_signature(index=index)
        # last byte is the hash_type, rest is the signature
        return signature[:-1], signature[-1]

    def sec_pubkey(self, index=0):
        '''returns the SEC format public if the script_sig has one'''
        if self.is_segwit():
            return self.witness_program[-33:]
        else:
            return self.script_sig.sec_pubkey(index=index)

    def redeem_script(self):
        '''return the Redeem Script if there is one'''
        return self.script_sig.redeem_script()

    def is_segwit(self):
        # Updated so if TxIn has a witness program present, then it is a segwit input
        if len(self.witness_program) > 1:
            return True
        if self.script_sig.type() != 'p2sh sig':
            return False
        redeem_script_raw = self.script_sig.redeem_script()
        if not redeem_script_raw:
            return False
        redeem_script = Script.parse(redeem_script_raw)
        return redeem_script.elements[0] == 0 and \
            type(redeem_script.elements[1]) == bytes and \
            len(redeem_script.elements[1]) == 20


class TxOut:

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = Script.parse(script_pubkey)

    def __repr__(self):
        return '{}:{}'.format(self.amount, self.script_pubkey.address())

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_output at the start
        return a TxOut object
        '''
        # s.read(n) will return n bytes
        # amount is 8 bytes, little endian, interpret as int
        amount = little_endian_to_int(s.read(8))
        # script_pubkey is a variable field (length followed by the data)
        # get the length by using read_varint(s)
        script_pubkey_length = read_varint(s)
        script_pubkey = s.read(script_pubkey_length)
        # return an instance of the class (cls(...))
        return cls(amount, script_pubkey)

    def serialize(self):
        '''Returns the byte serialization of the transaction output'''
        # serialize amount, 8 bytes, little endian
        result = int_to_little_endian(self.amount, 8)
        # get the scriptPubkey ready (use self.script_pubkey.serialize())
        raw_script_pubkey = self.script_pubkey.serialize()
        # encode_varint on the length of the scriptPubkey
        result += encode_varint(len(raw_script_pubkey))
        # add the scriptPubKey
        result += raw_script_pubkey
        return result
