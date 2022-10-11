#!/usr/bin/env python3

description="""A rudimentary implementation of creation of a SNICKER proposal.

**THIS TOOL DOES NOT SCAN FOR CANDIDATE TRANSACTIONS**

It only creates proposals on candidate transactions (individually)
that you have already found.

Input: the user's wallet, mixdepth to source their (1) coin from,
and a hex encoded pre-existing bitcoin transaction (fully signed)
as target.
User chooses the input to source the pubkey from, and the output
to use to create the SNICKER coinjoin. Tx fees are sourced from
the config, and the user specifies interactively the number of sats
to award the receiver (can be negative).

Once the proposal is created, it is uploaded to the servers as per
the `servers` setting in `joinmarket.cfg`, unless the -n option is
specified (see help for options), in which case the proposal is
output to stdout in the same string format: base64proposal,hexpubkey.
"""

import sys
from optparse import OptionParser
from jmbase import bintohex, jmprint, hextobin, \
     EXIT_ARGERROR, EXIT_FAILURE, EXIT_SUCCESS, get_pow
import jmbitcoin as btc
from jmclient import (process_shutdown,
     jm_single, load_program_config, check_regtest,
     estimate_tx_fee, add_base_options, get_wallet_path,
     open_test_wallet_maybe, WalletService, SNICKERClientProtocolFactory,
     start_reactor, JMPluginService, check_and_start_tor)
from jmclient.configure import get_log

log = get_log()

def main():
    parser = OptionParser(
        usage=
        'usage: %prog [options] walletname hex-tx input-index output-index net-transfer',
        description=description
    )
    add_base_options(parser)
    parser.add_option('-m',
          '--mixdepth',
          action='store',
          type='int',
          dest='mixdepth',
          help='mixdepth/account to spend from, default=0',
          default=0)
    parser.add_option(
        '-g',
        '--gap-limit',
        action='store',
        type='int',
        dest='gaplimit',
        default = 6,
        help='gap limit for Joinmarket wallet, default 6.'
    )
    parser.add_option(
        '-n',
        '--no-upload',
        action='store_true',
        dest='no_upload',
        default=False,
        help="if set, we don't upload the new proposal to the servers"
    )
    parser.add_option(
        '-f',
        '--txfee',
        action='store',
        type='int',
        dest='txfee',
        default=-1,
        help='Bitcoin miner tx_fee to use for transaction(s). A number higher '
        'than 1000 is used as "satoshi per KB" tx fee. A number lower than that '
        'uses the dynamic fee estimation of your blockchain provider as '
        'confirmation target. This temporarily overrides the "tx_fees" setting '
        'in your joinmarket.cfg. Works the same way as described in it. Check '
        'it for examples.')
    parser.add_option('-a',
                      '--amtmixdepths',
                      action='store',
                      type='int',
                      dest='amtmixdepths',
                      help='number of mixdepths in wallet, default 5',
                      default=5)
    (options, args) = parser.parse_args()
    snicker_plugin = JMPluginService("SNICKER")
    load_program_config(config_path=options.datadir,
                        plugin_services=[snicker_plugin])
    if len(args) != 5:
        jmprint("Invalid arguments, see --help")
        sys.exit(EXIT_ARGERROR)
    wallet_name, hextx, input_index, output_index, net_transfer = args
    input_index, output_index, net_transfer = [int(x) for x in [
        input_index, output_index, net_transfer]]

    check_and_start_tor()

    check_regtest()

    # If tx_fees are set manually by CLI argument, override joinmarket.cfg:
    if int(options.txfee) > 0:
        jm_single().config.set("POLICY", "tx_fees", str(options.txfee))
    max_mix_depth = max([options.mixdepth, options.amtmixdepths - 1])
    wallet_path = get_wallet_path(wallet_name, None)
    wallet = open_test_wallet_maybe(
            wallet_path, wallet_name, max_mix_depth,
            wallet_password_stdin=options.wallet_password_stdin,
            gap_limit=options.gaplimit)
    wallet_service = WalletService(wallet)
    if wallet_service.rpc_error:
        sys.exit(EXIT_FAILURE)
    snicker_plugin.start_plugin_logging(wallet_service)
    # in this script, we need the wallet synced before
    # logic processing for some paths, so do it now:
    while not wallet_service.synced:
        wallet_service.sync_wallet(fast=not options.recoversync)
    # the sync call here will now be a no-op:
    wallet_service.startService()

    # now that the wallet is available, we can construct a proposal
    # before encrypting it:
    originating_tx = btc.CMutableTransaction.deserialize(hextobin(hextx))
    txid1 = originating_tx.GetTxid()[::-1]
    # the proposer wallet needs to choose a single utxo, from his selected
    # mixdepth, that is bigger than the output amount of tx1 at the given
    # index.
    fee_est = estimate_tx_fee(2, 3, txtype=wallet_service.get_txtype())
    amt_required = originating_tx.vout[output_index].nValue + fee_est
    
    prop_utxo_dict = wallet_service.select_utxos(options.mixdepth,
                            amt_required)
    prop_utxos = list(prop_utxo_dict)
    prop_utxo_vals = [prop_utxo_dict[x] for x in prop_utxos]
    # get the private key for that utxo
    priv = wallet_service.get_key_from_addr(
        wallet_service.script_to_addr(prop_utxo_vals[0]['script']))
    # construct the arguments for the snicker proposal:
    our_input_utxos = [btc.CMutableTxOut(x['value'],
                        x['script']) for x in prop_utxo_vals]

    # destination must be a different mixdepth:
    prop_destn_spk = wallet_service.get_new_script((
        options.mixdepth + 1) % (wallet_service.mixdepth + 1), 1)
    change_spk = wallet_service.get_new_script(options.mixdepth, 1)
    their_input = (txid1, output_index)
    # we also need to extract the pubkey of the chosen input from
    # the witness; we vary this depending on our wallet type:
    pubkey, msg = btc.extract_pubkey_from_witness(originating_tx, input_index)
    if not pubkey:
        log.error("Failed to extract pubkey from transaction: {}".format(msg))
        sys.exit(EXIT_FAILURE)
    encrypted_proposal = wallet_service.create_snicker_proposal(
            prop_utxos, their_input,
            our_input_utxos,
            originating_tx.vout[output_index],
            net_transfer,
            fee_est,
            priv,
            pubkey,
            prop_destn_spk,
            change_spk,
            version_byte=1) + b"," + bintohex(pubkey).encode('utf-8')
    if options.no_upload:
        jmprint(encrypted_proposal.decode("utf-8"))
        sys.exit(EXIT_SUCCESS)

    daemon = not jm_single().config.getboolean("DAEMON", "no_daemon")
    snicker_client = SNICKERPostingClient([encrypted_proposal])
    servers = jm_single().config.get("SNICKER", "servers").split(",")
    snicker_pf = SNICKERClientProtocolFactory(snicker_client, servers)
    start_reactor(jm_single().config.get("DAEMON", "daemon_host"),
                      jm_single().config.getint("DAEMON", "daemon_port"),
                      snickerfactory=snicker_pf,
                      jm_coinjoin=False,
                      daemon=daemon)

class SNICKERPostingClient(object):
    """ A client object which stores proposals
    ready to be sent to the server/servers, and appends
    proof of work to them according to the server's rules.
    """
    def __init__(self, pre_nonce_proposals, info_callback=None,
                 end_requests_callback=None):
        # the encrypted proposal without the nonce appended for PoW
        self.pre_nonce_proposals = pre_nonce_proposals

        self.proposals_with_nonce = []

        # callback for conveying information messages
        if not info_callback:
            self.info_callback = self.default_info_callback
        else:
            self.info_callback = info_callback

        # callback for action at the end of a set of
        # submissions to servers; by default, this
        # is "one-shot"; we submit to all servers in the
        # config, then shut down the script.
        if not end_requests_callback:
            self.end_requests_callback = \
                self.default_end_requests_callback

    def default_end_requests_callback(self, response):
        process_shutdown()

    def default_info_callback(self, msg):
        jmprint(msg)

    def get_proposals(self, targetbits):
        # the data sent to the server is base64encryptedtx,key,nonce; the nonce
        # part is generated in get_pow().
        for p in self.pre_nonce_proposals:
            nonceval, preimage, niter = get_pow(p+b",", nbits=targetbits,
                                                truncate=32)
            log.debug("Got POW preimage: {}".format(preimage.decode("utf-8")))
            if nonceval is None:
                log.error("Failed to generate proof of work, message:{}".format(
                    preimage))
                sys.exit(EXIT_FAILURE)
            self.proposals_with_nonce.append(preimage)
        return self.proposals_with_nonce

if __name__ == "__main__":
    main()
    jmprint('done', "success")
