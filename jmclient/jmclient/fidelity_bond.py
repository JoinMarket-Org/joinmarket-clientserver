import struct
import base64
import json
from jmbitcoin import ecdsa_sign, ecdsa_verify
from jmdaemon import import fidelity_bond_sanity_check


def assert_is_utxo(utxo):
    assert len(utxo) == 2
    assert isinstance(utxo[0], bytes)
    assert len(utxo[0]) == 32
    assert isinstance(utxo[1], int)
    assert utxo[1] >= 0


def get_cert_msg(cert_pub, cert_expiry):
    return b'fidelity-bond-cert|' + cert_pub + b'|' + str(cert_expiry).encode('ascii')


class FidelityBond:
    def __init__(self, utxo, utxo_pubkey, locktime, cert_expiry,
                 cert_privkey, cert_pubkey, cert_signature):
        assert_is_utxo(utxo)
        assert isinstance(utxo_pubkey, bytes)
        assert isinstance(locktime, int)
        assert isinstance(cert_expiry, int)
        assert isinstance(cert_privkey, bytes)
        assert isinstance(cert_pubkey, bytes)
        assert isinstance(cert_signature, bytes)
        self.utxo = utxo
        self.utxo_pubkey = utxo_pubkey
        self.locktime = locktime
        self.cert_expiry = cert_expiry
        self.cert_privkey = cert_privkey
        self.cert_pubkey = cert_pubkey
        self.cert_signature = cert_signature

    def create_proof(self, maker_nick, taker_nick):
        return FidelityBondProof(
            maker_nick, taker_nick, self.cert_pubkey, self.cert_expiry,
            self.cert_signature, self.utxo, self.utxo_pubkey, self.locktime)

    def serialize(self):
        return json.dumps([
            self.utxo,
            self.utxo_pubkey,
            self.locktime,
            self.cert_expiry,
            self.cert_privkey,
            self.cert_pubkey,
            self.cert_signature,
        ])

    @classmethod
    def deserialize(cls, data):
        return cls(*json.loads(data))


class FidelityBondProof:
    # nick_sig + cert_sig + cert_pubkey + cert_expiry + utxo_pubkey + txid + vout + timelock
    # 72       + 72       + 33          + 2           + 33          + 32   + 4    + 4 = 252 bytes
    SER_STUCT_FMT = '<72s72s33sH33s32sII'

    def __init__(self, maker_nick, taker_nick, cert_pub, cert_expiry,
                 cert_sig, utxo, utxo_pub, locktime):
        assert isinstance(maker_nick, str)
        assert isinstance(taker_nick, str)
        assert isinstance(cert_pub, bytes)
        assert isinstance(cert_sig, bytes)
        assert isinstance(utxo_pub, bytes)
        assert isinstance(locktime, int)
        assert_is_utxo(utxo)
        self.maker_nick = maker_nick
        self.taker_nick = taker_nick
        self.cert_pub = cert_pub
        self.cert_expiry = cert_expiry
        self.cert_sig = cert_sig
        self.utxo = utxo
        self.utxo_pub = utxo_pub
        self.locktime = locktime

    @property
    def nick_msg(self):
        return (self.taker_nick + '|' + self.maker_nick).encode('ascii')

    def create_proof_msg(self, cert_priv):
        nick_sig = ecdsa_sign(self.nick_msg, cert_priv)
        # FIXME: remove stupid base64
        nick_sig = base64.b64decode(nick_sig)
        return self._serialize_proof_msg(nick_sig)

    def _serialize_proof_msg(self, msg_signature):
        msg_signature = msg_signature.rjust(72, b'\xff')
        cert_sig = self.cert_sig.rjust(72, b'\xff')
        fidelity_bond_data = struct.pack(
            self.SER_STUCT_FMT,
            msg_signature,
            cert_sig,
            self.cert_pub,
            self.cert_expiry,
            self.utxo_pub,
            self.utxo[0],
            self.utxo[1],
            self.locktime
        )
        return base64.b64encode(fidelity_bond_data).decode('ascii')

    @staticmethod
    def _verify_signature(message, signature, pubkey):
        # FIXME: remove stupid base64
        return ecdsa_verify(message, base64.b64encode(signature), pubkey)

    @classmethod
    def parse_and_verify_proof_msg(cls, maker_nick, taker_nick, data):
        if not fidelity_bond_sanity_check.fidelity_bond_sanity_check(data):
            raise ValueError("sanity check failed")
        decoded_data = base64.b64decode(data)

        unpacked_data = struct.unpack(cls.SER_STUCT_FMT, decoded_data)
        try:
            signature = unpacked_data[0][unpacked_data[0].index(b'\x30'):]
            cert_sig = unpacked_data[1][unpacked_data[1].index(b'\x30'):]
        except ValueError:
            #raised if index() doesnt find the position
            raise ValueError("der signature header not found")
        proof = cls(maker_nick, taker_nick, unpacked_data[2], unpacked_data[3],
                    cert_sig, (unpacked_data[5], unpacked_data[6]),
                    unpacked_data[4], unpacked_data[7])
        cert_msg = get_cert_msg(proof.cert_pub, proof.cert_expiry)

        if not cls._verify_signature(proof.nick_msg, signature, proof.cert_pub):
            raise ValueError("nick sig does not verify")
        if not cls._verify_signature(cert_msg, proof.cert_sig, proof.utxo_pub):
            raise ValueError("cert sig does not verify")

        return proof
