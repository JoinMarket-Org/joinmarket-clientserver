from jmbase import hextobin
from jmclient.configure import validate_address, load_test_config
from jmclient import jm_single
import jmbitcoin as btc
from bitcointx.wallet import CCoinAddress
from bitcointx import ChainParams
import json
import pytest
import os
testdir = os.path.dirname(os.path.realpath(__file__))

def address_valid_somewhere(addr):
    for x in ["bitcoin", "bitcoin/testnet", "bitcoin/regtest"]:
        btc.select_chain_params(x)
        if validate_address(addr)[0]:
            return True
    return False

def test_non_addresses(setup_addresses):
    #could flesh this out with other examples
    res, msg = validate_address(2)
    assert res == False, "Incorrectly accepted number"

def test_b58_invalid_addresses(setup_addresses):
    #none of these are valid as any kind of key or address
    with open(os.path.join(testdir,"base58_keys_invalid.json"), "r") as f:
        json_data = f.read()
    invalid_key_list = json.loads(json_data)
    for k in invalid_key_list:
        bad_key = k[0]
        res = address_valid_somewhere(bad_key)
        assert res == False, "Incorrectly validated address: " + bad_key

def test_b58_valid_addresses():
    with open(os.path.join(testdir,"base58_keys_valid.json"), "r") as f:
        json_data = f.read()
    valid_keys_list = json.loads(json_data)
    for a in valid_keys_list:
        addr, pubkey, prop_dict = a
        if not prop_dict["isPrivkey"]:
            if prop_dict["isTestnet"]:
                jm_single().config.set("BLOCKCHAIN", "network", "testnet")
                btc.select_chain_params("bitcoin/testnet")
            else:
                jm_single().config.set("BLOCKCHAIN", "network", "mainnet")
                btc.select_chain_params("bitcoin")
            #if using pytest -s ; sanity check to see what's actually being tested
            res, message = validate_address(addr)
            assert res == True, "Incorrectly failed to validate address: " + addr + " with message: " + message
    jm_single().config.set("BLOCKCHAIN", "network", "testnet")
    btc.select_chain_params("bitcoin/regtest")

def test_valid_bech32_addresses():
    valids = ["BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
    # TODO these are valid bech32 addresses but rejected by bitcointx
    # because they are not witness version 0; add others.
    #"bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
    #"BC1SW50QA3JX3S",
    #"bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
    "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy"]
    for va in valids:
        if va.lower()[:2] == "bc":
            jm_single().config.set("BLOCKCHAIN", "network", "mainnet")
            btc.select_chain_params("bitcoin")
        else:
            jm_single().config.set("BLOCKCHAIN", "network", "testnet")
            btc.select_chain_params("bitcoin/testnet")
        res, message = validate_address(va)
        assert res == True, "Incorrect failed to validate address: " + va + " with message: " + message
    jm_single().config.set("BLOCKCHAIN", "network", "testnet")
    btc.select_chain_params("bitcoin/regtest")

def test_invalid_bech32_addresses():
    invalids = [
    "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
    "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
    "bc1rw5uspcuh",
    "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
    "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
    "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
    "bc1gmk9yu"]
    for iva in invalids:
        res = address_valid_somewhere(iva)
        assert res == False, "Incorrectly validated address: " + iva

def test_valid_bip341_scriptpubkeys_addresses():
    with ChainParams("bitcoin"):
        with open(os.path.join(testdir,
            "bip341_wallet_test_vectors.json"), "r") as f:
            json_data = json.loads(f.read())
        for x in json_data["scriptPubKey"]:
            sPK = hextobin(x["expected"]["scriptPubKey"])
            addr = x["expected"]["bip350Address"]
            res, message = validate_address(addr)
            assert res, message
            print("address {} was valid bech32m".format(addr))
            # test this specific conversion because this is how
            # our human readable outputs work:
            assert str(CCoinAddress.from_scriptPubKey(
                btc.CScript(sPK))) == addr
            print("and it converts correctly from scriptPubKey: {}".format(
                btc.CScript(sPK)))

# These tests are almost, but not quite, unnecessary:
# we are testing the same failure cases, from BIP350, that
# are already tested in our underlying bitcoin package bitcointx;
# but this represents a sanity check that our top-layer validation
# check is functioning, whatever the backend. We focus strongly on
# detecting invalid encodings/address strings since that is where the
# actual danger of loss exists.
invalid_bech32_bech32m = [
  ["an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4", "overall max length exceeded"],
  ["qyrz8wqd2c9m", "No separator character"],
  ["1qyrz8wqd2c9m", "Empty HRP"],
  ["y1b0jsk6g", "Invalid data character"],
  ["lt1igcx5c0", "Invalid data character"],
  ["in1muywd", "Too short checksum"],
  ["mm1crxm3i", "Invalid character in checksum"],
  ["au1s5cgom", "Invalid character in checksum"],
  ["M1VUXWEZ", "checksum calculated with uppercase form of HRP"],
  ["16plkw9", "empty HRP"],
  ["1p2gdwpf", "empty HRP"],
  ["tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty", "Invalid human-readable part"],
  ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", "Invalid checksum"],
  ["BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2", "Invalid witness version"],
  ["bc1rw5uspcuh", "Invalid program length"],
  ["bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90", "Invalid program length"],
  ["BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P", "Invalid program length for witness version 0 (per BIP141)"],
  ["tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7", "Mixed case"],
  ["bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du", "zero padding of more than 4 bits"],
  ["tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv", "Non-zero padding in 8-to-5 conversion"],
  ["bc1gmk9yu", "Empty data section"],
  ["tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut", "Invalid human-readable part"],
  ["bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd", "Invalid checksum (Bech32 instead of Bech32m)"],
  ["tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf", "Invalid checksum (Bech32 instead of Bech32m)"],
  ["BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL", "Invalid checksum (Bech32 instead of Bech32m)"],
  ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh", "Invalid checksum (Bech32m instead of Bech32)"],
  ["tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47", "Invalid checksum (Bech32m instead of Bech32)"],
  ["bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4", "Invalid character in checksum"],
  ["BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R", "Invalid witness version"],
  ["bc1pw5dgrnzv", "Invalid program length (1 byte)"],
  ["bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav", "Invalid program length (41 bytes)"],
  ["tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq", "Mixed case"],
  ["bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf", "zero padding of more than 4 bits"],
  ["tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j", "Non-zero padding in 8-to-5 conversion"],
  ["bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx", "non-zero version, but bech32 (not bech32m)"],
  ["BC1SW50QA3JX3S", "non-zero version, but bech32 (not bech32m)"],
  ["bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj", "non-zero version, but bech32 (not bech32m)"]]
def test_invalid_bech32m():
    for case in invalid_bech32_bech32m:
        assert not address_valid_somewhere(case[0])

@pytest.fixture(scope="module")
def setup_addresses():
    load_test_config()
