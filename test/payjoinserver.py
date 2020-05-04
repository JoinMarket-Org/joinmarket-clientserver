#! /usr/bin/env python
""" Creates a very simple server for payjoin
    payment requests; uses regtest and a single
    JM wallet, provides a hex seed for the sender
    side of the test.
    Use the same command line setup as for ygrunner.py,
    except you needn't specify --nirc=
    NOTE: to run this test you will need a `key.pem`
    and a `cert.pem` in this (test/) directory,
    created in the standard way for ssl certificates.
    Note that (in test) the client will not verify
    them.
"""
import os
from twisted.web.server import Site
from twisted.web.resource import Resource
from twisted.internet import ssl
from twisted.internet import reactor, endpoints
from io import BytesIO
from common import make_wallets
import pytest
from jmbase import jmprint
import jmbitcoin as btc
from jmclient import load_test_config, jm_single,\
     SegwitWallet, SegwitLegacyWallet, cryptoengine

# TODO change test for arbitrary payment requests
payment_amt = 30000000

dir_path = os.path.dirname(os.path.realpath(__file__))

def get_ssl_context():
    """Construct an SSL context factory from the user's privatekey/cert.
    Here just hardcoded for tests.
    Note this is off by default since the cert needs setting up.
    """
    return ssl.DefaultOpenSSLContextFactory(os.path.join(dir_path, "key.pem"),
                                            os.path.join(dir_path, "cert.pem"))

class PayjoinServer(Resource):
    def __init__(self, wallet_service):
        self.wallet_service = wallet_service
        super().__init__()
    isLeaf = True
    def render_GET(self, request):
        return "<html>Only for testing.</html>".encode("utf-8")
    def render_POST(self, request):
        """ The sender will use POST to send the initial
        payment transaction.
        """
        jmprint("The server got this POST request: ")
        print(request)
        print(request.method)
        print(request.uri)
        print(request.args)
        print(request.path)
        print(request.content)
        proposed_tx = request.content
        assert isinstance(proposed_tx, BytesIO)
        payment_psbt_base64 = proposed_tx.read()
        payment_psbt = btc.PartiallySignedTransaction.from_base64(
            payment_psbt_base64)
        all_receiver_utxos = self.wallet_service.get_all_utxos()
        # TODO is there a less verbose way to get any 2 utxos from the dict?
        receiver_utxos_keys = list(all_receiver_utxos.keys())[:2]
        receiver_utxos = {k: v for k, v in all_receiver_utxos.items(
            ) if k in receiver_utxos_keys}
    
        # receiver will do other checks as discussed above, including payment
        # amount; as discussed above, this is out of the scope of this PSBT test.
    
        # construct unsigned tx for payjoin-psbt:
        payjoin_tx_inputs = [(x.prevout.hash[::-1],
                    x.prevout.n) for x in payment_psbt.unsigned_tx.vin]
        payjoin_tx_inputs.extend(receiver_utxos.keys())
        # find payment output and change output
        pay_out = None
        change_out = None
        for o in payment_psbt.unsigned_tx.vout:
            jm_out_fmt = {"value": o.nValue,
            "address": str(btc.CCoinAddress.from_scriptPubKey(
            o.scriptPubKey))}
            if o.nValue == payment_amt:
                assert pay_out is None
                pay_out = jm_out_fmt
            else:
                assert change_out is None
                change_out = jm_out_fmt
    
        # we now know there were two outputs and know which is payment.
        # bump payment output with our input:
        outs = [pay_out, change_out]
        our_inputs_val = sum([v["value"] for _, v in receiver_utxos.items()])
        pay_out["value"] += our_inputs_val
        print("we bumped the payment output value by: ", our_inputs_val)
        print("It is now: ", pay_out["value"])
        unsigned_payjoin_tx = btc.make_shuffled_tx(payjoin_tx_inputs, outs,
                                    version=payment_psbt.unsigned_tx.nVersion,
                                    locktime=payment_psbt.unsigned_tx.nLockTime)
        print("we created this unsigned tx: ")
        print(btc.hrt(unsigned_payjoin_tx))
        # to create the PSBT we need the spent_outs for each input,
        # in the right order:
        spent_outs = []
        for i, inp in enumerate(unsigned_payjoin_tx.vin):
            input_found = False
            for j, inp2 in enumerate(payment_psbt.unsigned_tx.vin):
                if inp.prevout == inp2.prevout:
                    spent_outs.append(payment_psbt.inputs[j].utxo)
                    input_found = True
                    break
            if input_found:
                continue
            # if we got here this input is ours, we must find
            # it from our original utxo choice list:
            for ru in receiver_utxos.keys():
                if (inp.prevout.hash[::-1], inp.prevout.n) == ru:
                    spent_outs.append(
                        self.wallet_service.witness_utxos_to_psbt_utxos(
                            {ru: receiver_utxos[ru]})[0])
                    input_found = True
                    break
            # there should be no other inputs:
            assert input_found
    
        r_payjoin_psbt = self.wallet_service.create_psbt_from_tx(unsigned_payjoin_tx,
                                                      spent_outs=spent_outs)
        print("Receiver created payjoin PSBT:\n{}".format(
            self.wallet_service.hr_psbt(r_payjoin_psbt)))
    
        signresultandpsbt, err = self.wallet_service.sign_psbt(r_payjoin_psbt.serialize(),
                                                    with_sign_result=True)
        assert not err, err
        signresult, receiver_signed_psbt = signresultandpsbt
        assert signresult.num_inputs_final == len(receiver_utxos)
        assert not signresult.is_final
    
        print("Receiver signing successful. Payjoin PSBT is now:\n{}".format(
            self.wallet_service.hr_psbt(receiver_signed_psbt)))
        content = receiver_signed_psbt.to_base64()
        request.setHeader(b"content-length", ("%d" % len(content)).encode("ascii"))
        return content.encode("ascii")
    
    

def test_start_payjoin_server(setup_payjoin_server):
    # set up the wallet that the server owns, and the wallet for
    # the sender too (print the seed):
    if jm_single().config.get("POLICY", "native") == "true":
        walletclass = SegwitWallet
    else:
        walletclass = SegwitLegacyWallet

    wallet_services = make_wallets(2,
                                   wallet_structures=[[1, 3, 0, 0, 0]] * 2,
                                   mean_amt=2,
                                   walletclass=walletclass)
    #the server bot uses the first wallet, the sender the second
    server_wallet_service = wallet_services[0]['wallet']
    jmprint("\n\nTaker wallet seed : " + wallet_services[1]['seed'])
    jmprint("\n")
    server_wallet_service.sync_wallet(fast=True)
    
    site = Site(PayjoinServer(server_wallet_service))
    # TODO for now, just sticking with TLS test as non-encrypted
    # is unlikely to be used, but add that option.
    reactor.listenSSL(8080, site, contextFactory=get_ssl_context())
    #endpoint = endpoints.TCP4ServerEndpoint(reactor, 8080)
    #endpoint.listen(site)
    reactor.run()

@pytest.fixture(scope="module")
def setup_payjoin_server():
    load_test_config()
    jm_single().bc_interface.tick_forward_chain_interval = 10
    jm_single().bc_interface.simulate_blocks()
    # handles the custom regtest hrp for bech32
    cryptoengine.BTC_P2WPKH.VBYTE = 100
