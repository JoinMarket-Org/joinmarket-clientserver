"""Module to support bitcoin operations using a
different codebase than joinmarket's own.
"""
#Protocol constants
BTC_P2PK_VBYTE = {"mainnet": 0x00, "testnet": 0x6f}
BTC_P2SH_VBYTE = {"mainnet": 0x05, "testnet": 0xc4}
PODLE_COMMIT_FILE = None

from jmbase.support import get_log
import binascii, sys, re, hashlib, base64
from pprint import pformat
log = get_log()

#Required only for PoDLE calculation:
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337

interface = "joinmarket-joinmarket"

try:
    from jmbitcoin import *
    bjm = True
except ImportError:
    #TODO figure out the right flexibility structure
    
    interface = "joinmarket-electrum"
    
    if interface != "joinmarket-electrum":
        raise NotImplementedError
    
    not_supported_string = "not supported by: " + interface

    # Base switching
    code_strings = {
            2: '01',
            10: '0123456789',
            16: '0123456789abcdef',
            32: 'abcdefghijklmnopqrstuvwxyz234567',
            58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
            256: ''.join([chr(x) for x in range(256)])
        }
    def get_code_string(base):
            if base in code_strings:
                return code_strings[base]
            else:
                raise ValueError("Invalid base!")

    def encode(val, base, minlen=0):
        base, minlen = int(base), int(minlen)
        code_string = get_code_string(base)
        result = ""
        while val > 0:
            result = code_string[val % base] + result
            val //= base
        return code_string[0] * max(minlen - len(result), 0) + result

    def decode(string, base):
        base = int(base)
        code_string = get_code_string(base)
        result = 0
        if base == 16:
            string = string.lower()
        while len(string) > 0:
            result *= base
            result += code_string.find(string[0])
            string = string[1:]
        return result

    #Electrum specific code starts here
    import electrum.bitcoin as ebt
    import electrum.transaction as etr
    from ecdsa.ecdsa import curve_secp256k1, generator_secp256k1, point_is_valid
    from ecdsa.util import string_to_number, sigdecode_der, sigencode_der
    from ecdsa import VerifyingKey, BadSignatureError, BadDigestError
    from ecdsa.curves import SECP256k1
    from ecdsa.numbertheory import square_root_mod_prime
    from ecdsa.ellipticcurve import Point

    class PPubKey(object):
        def __init__(self, serP):
            self._point = ebt.ser_to_point(serP)
        def serialize(self):
            return ebt.point_to_ser(self._point)

    class PPrivKey(object):
        def __init__(self, scalar):
            self._privkey = ebt.EC_KEY(scalar)
            self.private_key = scalar
            self.pubkey = PPubKey(binascii.unhexlify(
                self._privkey.get_public_key()))

    podle_PublicKey_class = PPubKey
    podle_PrivateKey_class = PPrivKey

    def podle_PublicKey(P):
        return PPubKey(P)

    def podle_PrivateKey(priv):
        return PPrivKey(priv)

    def multiply(s, pub, usehex, rawpub=True, return_serialized=True):
        """s should be 32 byte scalar, pub should be of type
        podle_PublicKey_class
        """
        if usehex:
            s = binascii.unhexlify(s)
            pub = binascii.unhexlify(pub)
        ppub = PPubKey(pub)
        p = ppub._point
        s_int = decode(s, 256)
        m = p * s_int
        r = PPubKey(ebt.point_to_ser(m))
        if return_serialized:
            return r.serialize()
        return r
    
    def add_pubkeys(pubkeys, usehex):
        """Pubkeys should be a list (for compatibility).
        """
        #Not supporting more than 2 items for now, not needed.
        assert len(pubkeys) == 2
        if usehex:
            pubkeys = [binascii.unhexlify(x) for x in pubkeys]
        p1pt, p2pt = [ebt.ser_to_point(x) for x in pubkeys]
        sumpt = p1pt + p2pt
        return ebt.point_to_ser(sumpt)

    def getG(compressed=True):
        scalar = "\x00"*31 + "\x01"
        return binascii.unhexlify(
            ebt.EC_KEY(scalar).get_public_key(compressed=compressed))
    
    def sign(tx):
        #transaction signing is handled by the wallet for Electrum
        raise NotImplementedError("sign " + not_supported_string)
    
    def get_version_byte(inp):
        leadingzbytes = len(re.match('^1*', inp).group(0))
        data = b'\x00' * leadingzbytes + b58check_to_bin(inp, version=True)
        return ord(data[0])
    
    def b58check_to_bin(addr, version=False):
        """optionally include the version byte for get_version_byte.
        Note that jmbitcoin does not need this flag, because it
        uses the changebase() function, which here has been restricted.
        """
        if not version:
            return ebt.DecodeBase58Check(addr)[1:]
        else:
            return ebt.DecodeBase58Check(addr)
    
    def changebase(inp, frm=256, to=58):
        """Implementation of base58 (*not* b58check) conversion
        only. Used in message channel verifiable nick construction.
        Explicitly disabling any other conversion for now.
        """
        if not (frm==256 and to==58):
            raise NotImplementedError
        return ebt.base_encode(inp, 58)

    def address_to_script(addr):
        return etr.Transaction.pay_script(ebt.TYPE_ADDRESS, addr)
    
    def script_to_address(script):
        bin_script = binascii.unhexlify(script)
        res = etr.get_address_from_output_script(bin_script)
        if not res[0] == ebt.TYPE_ADDRESS:
            raise ValueError("Invalid script for bitcoin address")
        return res[1]
    
    def bin_dbl_sha256(x):
        return ebt.sha256(ebt.sha256(x))
    
    def dbl_sha256(x):
        return binascii.hexlify(bin_dbl_sha256(x))
    
    def verify_tx_input(tx, i, script, sig, pub):
        pub, sig, script = (binascii.unhexlify(x) for x in [pub, sig, script])
        t = etr.Transaction(tx)
        t.deserialize()
        #to prepare for verification (to do the txhash for modtx)
        #we need to have the "address" field set in the input.
        typ, addr = etr.get_address_from_output_script(script)
        if not typ == ebt.TYPE_ADDRESS:
            #Don't support non-p2sh, non-p2pkh for now
            log.debug("Invalid script")
            return False
        t.inputs()[i]["address"] = addr
        t.inputs()[i]["type"] = 'p2pkh'
        txforsig = etr.Hash(t.serialize_preimage(i).decode('hex'))
        ecdsa_pub = get_ecdsa_verifying_key(pub)
        if not ecdsa_pub:
            return False
        try:
            verified = ecdsa_pub.verify_digest(sig, txforsig,
                                       sigdecode = sigdecode_der)
        except (BadSignatureError, BadDigestError):
            return False
        return True
    
    def get_ecdsa_verifying_key(pub):
        #some shenanigans required to validate a transaction sig; see
        #python.ecdsa PR #54. This will be a lot simpler when that's merged.
        #https://github.com/warner/python-ecdsa/pull/54/files
        if not pub[0] in ["\x02", "\x03"]:
            log.debug("Invalid pubkey")
            return None    
        is_even = pub.startswith('\x02')
        x = string_to_number(pub[1:])
        order = SECP256k1.order
        p = SECP256k1.curve.p()
        alpha = (pow(x, 3, p) + (SECP256k1.curve.a() * x) + SECP256k1.curve.b()) % p
        beta = square_root_mod_prime(alpha, p)
        if is_even == bool(beta & 1):
            y = p - beta
        else:
            y = beta
        if not point_is_valid(SECP256k1.generator, x, y):
            return None
        
        point = Point(SECP256k1.curve, x, y, order)
        return VerifyingKey.from_public_point(point, SECP256k1,
                                                   hashfunc=hashlib.sha256)
    
    def ecdsa_verify(msg, sig, pub, usehex=True):
        sig = base64.b64decode(sig)
        if usehex:
            pub = binascii.unhexlify(pub)
        verif_key = get_ecdsa_verifying_key(pub)
        return verif_key.verify_digest(sig,
                                       ebt.Hash(ebt.msg_magic(msg)),
                                       sigdecode = sigdecode_der)
        
    def ecdsa_sign(msg, priv, usehex=True):
        if usehex:
            priv = binascii.unhexlify(priv)
        compressed = False
        if len(priv) == 33 and priv[-1]=="\x01":
            compressed = True
        signkey = ebt.EC_KEY(priv[:32])
        private_key = ebt.MySigningKey.from_secret_exponent(signkey.secret,
                                                            curve=SECP256k1)
        sig = private_key.sign_digest_deterministic(ebt.Hash(ebt.msg_magic(msg)),
                                                hashfunc=hashlib.sha256,
                                            sigencode = sigencode_der)
        return base64.b64encode(sig)

    def serialize(txobj):
        #It is a rather chunky matter to re-use electrum.transaction code
        #to do serialization, it has a very different approach. Hence some
        #code duplication here with bitcoin-joinmarket. However we use the
        #number encoding functions from Electrum. Also, this is always in hex.
        o = []
        o.append(ebt.int_to_hex(txobj["version"], 4))
        o.append(ebt.var_int(len(txobj["ins"])))
        for inp in txobj["ins"]:
            binhash = binascii.unhexlify(inp["outpoint"]["hash"])
            binhash = binhash[::-1]
            o.append(binascii.hexlify(binhash))
            o.append(ebt.int_to_hex(inp["outpoint"]["index"], 4))
            o.append(ebt.var_int(len(inp["script"])/2) + inp["script"])
            o.append(ebt.int_to_hex(inp["sequence"], 4))
        o.append(ebt.var_int(len(txobj["outs"])))
        for out in txobj["outs"]:
            o.append(ebt.int_to_hex(out["value"], 8))
            o.append(ebt.var_int(len(out["script"])/2) + out["script"])
        o.append(ebt.int_to_hex(txobj["locktime"], 4))
        return ''.join(o)

    def deserialize_script(scriptSig):
        #Assumes P2PKH scriptSig
        d = {}
        etr.parse_scriptSig(d, binascii.unhexlify(scriptSig))
        return (d["signatures"][0], d["pubkeys"][0])

    def deserialize(txhex):
        t = etr.deserialize(txhex)
        #translation from Electrum deserialization
        #to pybitcointools form as used in joinmarket
        #pybitcointools structure:
        #obj = {"ins": [..], "outs": [..], "locktime": int}
        #where ins elements are:
        #{"outpoint": {"hash": bigendian32,"index": int},
        #"script": hex,"sequence": int}
        #and outs elements are:
        #{"script": hex, "value": int}
        #
        #while electrum.transaction.deserialize returns object
        #like:
        #{"version": int, "inputs": [..], "outputs": [..], "lockTime": int}
        obj = {}
        obj["version"] = t["version"]
        obj["locktime"] = t["lockTime"]
        obj["ins"] = []
        obj["outs"] = []
        for i in t["inputs"]:
            outpoint = {"hash": i["prevout_hash"], "index": i["prevout_n"]}
            scr = i["scriptSig"]
            sequence = i["sequence"]
            obj["ins"].append({"outpoint": outpoint, "script": scr, "sequence": sequence})
        for i in t["outputs"]:
            obj["outs"].append({"script": i["scriptPubKey"], "value": i["value"]})
        return obj
    
    def privkey_to_pubkey(privkey, usehex=True):
        if usehex:
            privkey = binascii.unhexlify(privkey)
        if len(privkey)==33 and privkey[-1] == "\x01":
            compressed = True
            privkey = privkey[:32]
        elif len(privkey)==32:
            compressed=False
        else:
            raise ValueError("Invalid private key")
        sec = ebt.SecretToASecret(privkey, compressed=compressed)
        
        retval = ebt.public_key_from_private_key(sec)
        if usehex:
            return retval
        return binascii.unhexlify(retval)

    privtopub = privkey_to_pubkey
    
    def privkey_to_address(privkey, magicbyte=0):
        pubkey = privkey_to_pubkey(privkey)
        return pubkey_to_address(pubkey, magicbyte)
    
    privtoaddr = privkey_to_address
    
    def pubkey_to_address(pub, magicbyte=0):
        h160 = ebt.hash_160(pub.decode('hex'))
        return ebt.hash_160_to_bc_address(h160, addrtype=magicbyte)
    
    pubtoaddr = pubkey_to_address
    
    def from_wif_privkey(privkey, vbyte=0):
        #converts a WIF compressed privkey to a hex private key
        return binascii.hexlify(ebt.ASecretToSecret(privkey))
    
    def txhash(txhex):
        t = etr.Transaction(txhex)
        return t.txid()
    
    #A simple copy-paste for now; move into support.py perhaps? TODO
    def estimate_tx_size(ins, outs, txtype='p2pkh'):
        '''Estimate transaction size.
        Assuming p2pkh:
        out: 8+1+3+2+20=34, in: 1+32+4+1+1+~73+1+1+33=147,
        ver:4,seq:4, +2 (len in,out)
        total ~= 34*len_out + 147*len_in + 10 (sig sizes vary slightly)
        '''
        if txtype == 'p2pkh':
            return 10 + ins * 147 + 34 * outs
        else:
            raise NotImplementedError("Non p2pkh transaction size estimation not" +
                                      "yet implemented")
    
    def mktx(ins, outs):
        #Copy-paste from bitcoin-joinmarket
        txobj = {"locktime": 0, "version": 1, "ins": [], "outs": []}
        for i in ins:
            if isinstance(i, dict) and "outpoint" in i:
                txobj["ins"].append(i)
            else:
                if isinstance(i, dict) and "output" in i:
                    i = i["output"]
                txobj["ins"].append({
                    "outpoint": {"hash": i[:64],
                                 "index": int(i[65:])},
                    "script": "",
                    "sequence": 4294967295
                })
        for o in outs:
            if not isinstance(o, dict):
                addr = o[:o.find(':')]
                val = int(o[o.find(':') + 1:])
                o = {}
                if re.match('^[0-9a-fA-F]*$', addr):
                    o["script"] = addr
                else:
                    o["address"] = addr
                o["value"] = val
    
            outobj = {}
            if "address" in o:
                outobj["script"] = address_to_script(o["address"])
            elif "script" in o:
                outobj["script"] = o["script"]
            else:
                raise Exception("Could not find 'address' or 'script' in output.")
            outobj["value"] = o["value"]
            txobj["outs"].append(outobj)
    
        return serialize(txobj)
    
    def set_commitment_file(file_location):
        global PODLE_COMMIT_FILE
        PODLE_COMMIT_FILE = file_location

def test_btc():
    #Sign and verify test (for message signing in joinmarket handshake)
    print("Using interface " + interface)
    priv = dbl_sha256("hello") + "01"
    x = ecdsa_sign("helloxxx", priv)
    log.debug("Got: " + x)
    y = ecdsa_verify("helloxxx", x, privkey_to_pubkey(priv))
    log.debug("Sig ver: " + str(y))
    assert y
    
    #address/script conversion test
    test_addr = "1LT6rwv26bV7mgvRosoSCyGM7ttVRsYidP"
    #Electrum has no support for testnet!
    #test_test_addr = "mgvipZr8kX7fZFQU7QsKTCJT9QCfaiswV7"
    assert script_to_address(address_to_script(test_addr))==test_addr
    assert get_version_byte(test_addr)==0
    
    #Transaction creation test.
    raw_valid_tx = "01000000064cdfe43ad43b187b738644363144784a09bf6d408012409cf9934591109a789b060000006b483045022100d4309edbb8253e62fb59462f2ff5c3445923e0299bf1a15ac5f7db3da5752bee022066f3f219de7e6ee56c3d600da757ec1051cbd11b42969b8935ae35642b6a2e84012102e94b49525342110266a1dc7651221507318c4cb914ede004b3098650e9b951b6ffffffffc2a9b3e8285c2e7aaee2ea50f792172c920c43a675fa8e8d70976727c8752adf030000006a47304402202763d8ad9e41c99c5af587c69d267493773dc9567519a64db8b707af5daf07f0022011729c6d241ad5abe48687d084644bd442b5f9038db04fb28da674126183aca5012102d2cbeb9386fd201bc6eecf27b2858f7bc27462cd9b43ae464e9ef3281f97a3e0ffffffffa787e89792a93111ff08f5a083234c7c2410bd69b6eef42be0fc5f026a3a1cf0030000006b483045022100c3b86d7acadf1be3d8ea6706daedb842b09732621e830440481370d423703741022009fd0f90a07babd481f1011ec883b2aa248c6a4a433599c5b203c6b93fc03b67012103f9a47d3958281b6749921fdf6d9edde0176342c00ced7caacab9ab3a64795086ffffffff23fb90cebcb1784a7a4a0a35489356ba64cf95c0afdc5a0f0184dc22668ff41f050000006b483045022100ea698e5952e23ffdf6d58bdc73e91c555867e3ad99ac9b583f492882395ace9a0220705abe597972d45923fe0515695dd7b99dcfa50e69d49c03a8126180fd263bc70121036532aa886851548a5b62bff29b4c36bfdc33e68c7dbee8efb4b440e50c5ebc6effffffffd401de8afd8fd323ab6abd9db1d261ac69e7c1d2be7f1a40004e7659b7d6cd9b030000006b483045022100b09c4e7f227f2f86d1965edbc4c92b9058243300f3bc62a3169591aacb60ca4d0220390d0d7ae2ee7dab200e166337c65d4a62b576dc4fa138ce40efd240c57346fc0121034cd59665d736d927d9613c7624f8d616d483b06ab8993446f6119f18e22731feffffffff38b8b3ae5fe9ef09c9f1583c9d6cc128bbd2639d49aca97b7686a74ba91bb32a040000006a4730440220105d93aba953edf008cc5b16ac81c10d97db6e59a3e13062ceef7cc1fbffd2ad022027b14b4162d70c4448bec7cb086b4e52880b51b282de98019ec3038153e25ed0012102cdbfb52b3e164203845f72391a3a58205834a3ad473a9d9878488dc1594aa0d4ffffffff087edb0000000000001976a914a1e5f40c6171e91183533f16bbda35e45182bcfa88ac80d97800000000001976a91482985ea6f877d70692072af967af305005fc86fd88ac80d97800000000001976a914a698b206b9f654974afd2056c85c52f88e4c2b2488ac9970af05000000001976a914b05dbb0ede1191e2871209affd8a5922e0a3275288ac80d97800000000001976a914619b3b22b7b66220d22907b8600724aecc49f03488acabc80000000000001976a914911c8c57eb12aa2c1cdce92f82c7e0405a2f3c6988ac80d97800000000001976a91464cd0ed04862f2b7101e9394285d2b3066e5e4dc88ac13b14100000000001976a9143f81fa4fd890845882fbb5226539d9643c99f0f488ac00000000"
    rvtxid = "4489a8cc933cb4e94915ead5b57b4aa707212c1f7b317187b500491e068c7887"
    if interface == "joinmarket-electrum":
        t = etr.Transaction(raw_valid_tx)
        assert rvtxid == t.hash()
    
        #Transaction deserialization/serialization test
        #Electrum requires this call to fill out Transactionfields
        t.deserialize()
        #log.debug("Got inputs: " + str(t.inputs))
        ourdeser = deserialize(t.raw)
        ourraw = serialize(ourdeser)
        #log.debug("Recreated: \n" + ourraw)
        assert ourraw == raw_valid_tx
        #double check round trip too
        assert deserialize(ourraw) == ourdeser
        txinslist = t.inputs()
    elif interface == "joinmarket-joinmarket":
        assert serialize(deserialize(raw_valid_tx)) == raw_valid_tx
        t = deserialize(raw_valid_tx)
        txinslist = t["ins"]
    else:
        raise NotImplementedError("No such interface?")

    #Transaction signature verification tests.
    #All currently assuming 100% p2pkh.
    for i, tin in enumerate(txinslist):
        if interface == "joinmarket-electrum":
            script = address_to_script(tin["address"])
            sig = tin["signatures"][0]
            pub = tin["pubkeys"][0]
        elif interface == "joinmarket-joinmarket":
            log.debug("Joinmarket working with this script: " + tin["script"])
            scriptSig = tin["script"]
            #We need to parse out the pubkey, convert to address, then convert
            #to a pubkeyscript; this assumes p2pkh. Note that this is handled
            #internally by the joinmarket blockchain/maker/taker code, so only
            #for tests.
            pub = scriptSig[-66:]
            script = address_to_script(pubkey_to_address(pub))
            log.debug("Converted to this addr script: " + script)
            #drop the length bytes from the start of sig and pub
            sig = scriptSig[2:-68]
        else:
            raise NotImplementedError("No such interface?")
        log.debug("Got sig, script, pub: " + " ".join([sig, script, pub]))
        assert verify_tx_input(raw_valid_tx, i, script, sig, pub)
        log.debug("Sig at: " + str(i) + " OK.")

    #Note there are no transaction signing tests, as
    #this is done by the wallet in this interface.
    log.debug("All tests passed.")