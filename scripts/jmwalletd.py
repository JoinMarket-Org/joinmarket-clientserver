#! /usr/bin/env python
import sys
from optparse import OptionParser
from jmclient import (load_program_config, jm_single,
                      add_base_options, JMWalletDaemon,
                      start_reactor)
from jmbase.support import get_log, EXIT_FAILURE

jlog = get_log()

def jmwalletd_main():
    parser = OptionParser(usage='usage: %prog [options] [wallet file]')
    parser.add_option('-p', '--port', action='store', type='int',
                      dest='port', default=28183,
                      help='the port over which to serve RPC, default 28183')
    parser.add_option('-w', '--wss-port', action='store', type='int',
                      dest='wss_port', default=28283,
                      help='the port over which to serve websocket '
                      'subscriptions, default 28283')

    # TODO: remove the non-relevant base options:
    add_base_options(parser)

    (options, args) = parser.parse_args()

    load_program_config(config_path=options.datadir)

    if jm_single().bc_interface is None:
        jlog.error("Running jmwallet-daemon requires configured " +
                   "blockchain source.")
        sys.exit(EXIT_FAILURE)

    # if nothing was configured, we override bitcoind's options so that
    # unconfirmed balance is included in the wallet display by default
    if 'listunspent_args' not in jm_single().config.options('POLICY'):
        jm_single().config.set('POLICY','listunspent_args', '[0]')
    jlog.info("Starting jmwalletd on port: " + str(options.port))
    jm_wallet_daemon = JMWalletDaemon(options.port, options.wss_port)
    jm_wallet_daemon.startService()
    daemon = not jm_single().config.getboolean("DAEMON", "no_daemon")
    start_reactor(jm_single().config.get("DAEMON", "daemon_host"),
                  jm_single().config.getint("DAEMON", "daemon_port"),
                  None, daemon=daemon)

if __name__ == "__main__":
    jmwalletd_main()
