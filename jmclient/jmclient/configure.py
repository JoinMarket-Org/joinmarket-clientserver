
import io
import logging
import os
import binascii
import re
import sys

from configparser import ConfigParser, NoOptionError

import jmbitcoin as btc
from jmclient.jsonrpc import JsonRpc
from jmbase.support import (get_log, joinmarket_alert, core_alert, debug_silence,
                            set_logging_level, jmprint, set_logging_color,
                            JM_APP_NAME, lookup_appdata_folder, EXIT_FAILURE)
from jmclient.podle import set_commitment_file

log = get_log()


class AttributeDict(object):
    """
    A class to convert a nested Dictionary into an object with key-values
    accessibly using attribute notation (AttributeDict.attribute) instead of
    key notation (Dict["key"]). This class recursively sets Dicts to objects,
    allowing you to recurse down nested dicts (like: AttributeDict.attr.attr)
    """

    def __init__(self, **entries):
        self.currentnick = None
        self.add_entries(**entries)
        if not os.path.exists('logs'):
            os.makedirs('logs')

    def add_entries(self, **entries):
        for key, value in entries.items():
            if isinstance(value, dict):
                self.__dict__[key] = AttributeDict(**value)
            else:
                self.__dict__[key] = value

    def __setattr__(self, name, value):
        if name == 'nickname' and value != self.currentnick:
            self.currentnick = value
            logFormatter = logging.Formatter(
                ('%(asctime)s [%(threadName)-12.12s] '
                 '[%(levelname)-5.5s]  %(message)s'))
            logsdir = os.path.join(os.path.dirname(
            global_singleton.config_location), "logs")
            fileHandler = logging.FileHandler(
                logsdir + '/{}.log'.format(value))
            fileHandler.setFormatter(logFormatter)
            log.addHandler(fileHandler)

        super().__setattr__(name, value)

    def __getitem__(self, key):
        """
        Provides dict-style access to attributes
        """
        return getattr(self, key)


global_singleton = AttributeDict()
global_singleton.JM_VERSION = 5
global_singleton.APPNAME = JM_APP_NAME
global_singleton.datadir = None
global_singleton.nickname = None
global_singleton.BITCOIN_DUST_THRESHOLD = 2730
global_singleton.DUST_THRESHOLD = 10 * global_singleton.BITCOIN_DUST_THRESHOLD
global_singleton.bc_interface = None
global_singleton.maker_timeout_sec = 60
global_singleton.debug_file_handle = None
global_singleton.core_alert = core_alert
global_singleton.joinmarket_alert = joinmarket_alert
global_singleton.debug_silence = debug_silence
global_singleton.config = ConfigParser(strict=False)
#This is reset to a full path after load_program_config call
global_singleton.config_location = 'joinmarket.cfg'
#as above
global_singleton.commit_file_location = 'cmtdata/commitments.json'
global_singleton.wait_for_commitments = 0


def jm_single():
    return global_singleton

# FIXME: Add rpc_* options here in the future!
required_options = {'BLOCKCHAIN': ['blockchain_source', 'network'],
                    'MESSAGING': ['host', 'channel', 'port'],
                    'POLICY': ['absurd_fee_per_kb', 'taker_utxo_retries',
                               'taker_utxo_age', 'taker_utxo_amtpercent']}

defaultconfig = \
    """
[DAEMON]
#set to 1 to run the daemon service within this process;
#set to 0 if the daemon is run separately (using script joinmarketd.py)
no_daemon = 1
#port on which daemon serves; note that communication still
#occurs over this port even if no_daemon = 1
daemon_port = 27183
#currently, running the daemon on a remote host is
#*NOT* supported, so don't change this variable
daemon_host = localhost
#by default the client-daemon connection is plaintext, set to 'true' to use TLS;
#for this, you need to have a valid (self-signed) certificate installed
use_ssl = false

[BLOCKCHAIN]
# options: bitcoin-rpc, regtest, bitcoin-rpc-no-history, no-blockchain
# When using bitcoin-rpc-no-history remember to increase the gap limit to scan for more addresses, try -g 5000
# Use 'no-blockchain' to run the ob-watcher.py script in scripts/obwatch without current access
# to Bitcoin Core; note that use of this option for any other purpose is currently unsupported.
blockchain_source = bitcoin-rpc
# options: testnet, mainnet
# Note: for regtest, use network = testnet
network = mainnet
rpc_host = localhost
rpc_port = 8332
rpc_user = bitcoin
rpc_password = password
rpc_wallet_file =

[MESSAGING:server1]
host = irc.darkscience.net
channel = joinmarket-pit
port = 6697
usessl = true
socks5 = false
socks5_host = localhost
socks5_port = 9050

#for tor
#host = darksci3bfoka7tw.onion
#socks5 = true

[MESSAGING:server2]
host = irc.hackint.org
channel = joinmarket-pit
port = 6697
usessl = true
socks5 = false
socks5_host = localhost
socks5_port = 9050

#for tor
#host = ncwkrwxpq2ikcngxq3dy2xctuheniggtqeibvgofixpzvrwpa77tozqd.onion
#port = 6667
#usessl = false
#socks5 = true

#Agora sometimes seems to be unreliable. Not active by default for that reason.
#[MESSAGING:server3]
#host = agora.anarplex.net
#channel = joinmarket-pit
#port = 14716
#usessl = true
#socks5 = false
#socks5_host = localhost
#socks5_port = 9050
#
##for tor
##host = cfyfz6afpgfeirst.onion
##port = 6667
##usessl = false
##socks5 = true

[LOGGING]
# Set the log level for the output to the terminal/console
# Possible choices: DEBUG / INFO / WARNING / ERROR
# Log level for the files in the logs-folder will always be DEBUG
console_log_level = INFO

# Use color-coded log messages to help distinguish log levels?:
color = true

[TIMEOUT]
maker_timeout_sec = 60
unconfirm_timeout_sec = 180
confirm_timeout_hours = 6

[POLICY]
# Use segwit style wallets and transactions
# Only set to false for old wallets, Joinmarket is now segwit only.
segwit = true

# Use native segwit (bech32) wallet. This is NOT
# currently supported in Joinmarket coinjoins. Only set to "true"
# if specifically advised to do so.
native = false

# for dust sweeping, try merge_algorithm = gradual
# for more rapid dust sweeping, try merge_algorithm = greedy
# for most rapid dust sweeping, try merge_algorithm = greediest
# but don't forget to bump your miner fees!
merge_algorithm = default

# The fee estimate is based on a projection of how many satoshis
# per kB are needed to get in one of the next N blocks, N set here
# as the value of 'tx_fees'. This cost estimate is high if you set 
# N=1, so we choose 3 for a more reasonable figure, as our default.
# You can also set your own fee/kb: any number higher than 1000 will
# be interpreted as the fee in satoshi per kB that you wish to use
# example: N=30000 will use 30000 sat/kB as a fee, while N=5
# will use the estimate from your selected blockchain source
# Note that there will be a 20% variation around any manually chosen
# values, so if you set N=10000, it might use any value between
# 8000 and 12000 for your transactions.
tx_fees = 3

# For users getting transaction fee estimates over an API,
# place a sanity check limit on the satoshis-per-kB to be paid.
# This limit is also applied to users using Core, even though
# Core has its own sanity check limit, which is currently
# 1,000,000 satoshis.
absurd_fee_per_kb = 350000

# Maximum absolute coinjoin fee in satoshi to pay to a single
# market maker for a transaction. Both the limits given in
# max_cj_fee_abs and max_cj_fee_rel must be exceeded in order
# to not consider a certain offer.
#max_cj_fee_abs = x

# Maximum relative coinjoin fee, in fractions of the coinjoin value
# e.g. if your coinjoin amount is 2 btc (200000000 satoshi) and
# max_cj_fee_rel = 0.001 (0.1%), the maximum fee allowed would
# be 0.002 btc (200000 satoshi)
#max_cj_fee_rel = x

# the range of confirmations passed to the `listunspent` bitcoind RPC call
# 1st value is the inclusive minimum, defaults to one confirmation
# 2nd value is the exclusive maximum, defaults to most-positive-bignum (Google Me!)
# leaving it unset or empty defers to bitcoind's default values, ie [1, 9999999]
#listunspent_args = []
# that's what you should do, unless you have a specific reason, eg:
#  !!! WARNING !!! CONFIGURING THIS WHILE TAKING LIQUIDITY FROM
#  !!! WARNING !!! THE PUBLIC ORDERBOOK LEAKS YOUR INPUT MERGES
#  spend from unconfirmed transactions:  listunspent_args = [0]
# display only unconfirmed transactions: listunspent_args = [0, 1]
# defend against small reorganizations:  listunspent_args = [3]
#   who is at risk of reorganization?:   listunspent_args = [0, 2]
# NB: using 0 for the 1st value with scripts other than wallet-tool could cause
# spends from unconfirmed inputs, which may then get malleated or double-spent!
# other counterparties are likely to reject unconfirmed inputs... don't do it.

# tx_broadcast: options: self, random-peer, not-self.
#
# self = broadcast transaction with your own bitcoin node.
#
# random-peer = everyone who took part in the coinjoin has a chance of broadcasting
# note: if your counterparties do not support it, you will fall back
# to broadcasting via your own node.
#
# not-self = never broadcast with your own bitcoin node.
# note: in this case if your counterparties do not broadcast for you, you
# will have to broadcast the tx manually (you can take the tx hex from the log
# or terminal) via some other channel. It is not recommended to choose this
# option when running schedules/tumbler.

tx_broadcast = self

# If makers do not respond while creating a coinjoin transaction,
# the non-responding ones will be ignored. This is the minimum
# amount of makers which we are content with for the coinjoin to
# succceed. Less makers means that the whole process will restart
# after a timeout.
minimum_makers = 4

# Threshold number of satoshis below which an incoming utxo
# to a reused address in the wallet will be AUTOMATICALLY frozen.
# This avoids forced address reuse attacks; see:
# https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse
#
# The default is to ALWAYS freeze a utxo to an already used address,
# whatever the value of it, and this is set with the value -1.
max_sats_freeze_reuse = -1

##############################
#THE FOLLOWING SETTINGS ARE REQUIRED TO DEFEND AGAINST SNOOPERS.
#DON'T ALTER THEM UNLESS YOU UNDERSTAND THE IMPLICATIONS.
##############################

# number of retries allowed for a specific utxo, to prevent DOS/snooping.
# Lower settings make snooping more expensive, but also prevent honest users
# from retrying if an error occurs.
taker_utxo_retries = 3

# number of confirmations required for the commitment utxo mentioned above.
# this effectively rate-limits a snooper.
taker_utxo_age = 5

# percentage of coinjoin amount that the commitment utxo must have
# as a minimum BTC amount. Thus 20 means a 1BTC coinjoin requires the
# utxo to be at least 0.2 btc.
taker_utxo_amtpercent = 20

#Set to 1 to accept broadcast PoDLE commitments from other bots, and
#add them to your blacklist (only relevant for Makers).
#There is no way to spoof these values, so the only "risk" is that
#someone fills your blacklist file with a lot of data.
accept_commitment_broadcasts = 1

#Location of your commitments.json file (stores commitments you've used
#and those you want to use in future), relative to the scripts directory.
commit_file_location = cmtdata/commitments.json

[PAYJOIN]
# for the majority of situations, the defaults
# need not be altered - they will ensure you don't pay
# a significantly higher fee.
# MODIFICATION OF THESE SETTINGS IS DISADVISED.

# Payjoin protocol version; currently only '1' is supported.
payjoin_version = 1

# servers can change their destination address by default (0).
# if '1', they cannot. Note that servers can explicitly request
# that this is activated, in which case we respect that choice.
disable_output_substitution = 0

# "default" here indicates that we will allow the receiver to
# increase the fee we pay by:
# 1.2 * (our_fee_rate_per_vbyte * vsize_of_our_input_type)
# (see https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#span_idfeeoutputspanFee_output)
# (and 1.2 to give breathing room)
# which indicates we are allowing roughly one extra input's fee.
# If it is instead set to an integer, then that many satoshis are allowed.
# Additionally, note that we will also set the parameter additionafeeoutputindex
# to that of our change output, unless there is none in which case this is disabled.
max_additional_fee_contribution = default

# this is the minimum satoshis per vbyte we allow in the payjoin
# transaction; note it is decimal, not integer.
min_fee_rate = 1.1

# for payjoins to hidden service endpoints, the socks5 configuration:
onion_socks5_host = localhost
onion_socks5_port = 9050

# for payjoin onion service creation, the tor control configuration:
tor_control_host = localhost
# or, to use a UNIX socket
# control_host = unix:/var/run/tor/control
tor_control_port = 9051

# in some exceptional case the HS may be SSL configured,
# this feature is not yet implemented in code, but here for the
# future:
hidden_service_ssl = false
"""

#This allows use of the jmclient package with a
#configuration set by an external caller; not to be used
#in conjuction with calls to load_program_config.
def set_config(cfg, bcint=None):
    global_singleton.config = cfg
    if bcint:
        global_singleton.bc_interface = bcint


def get_irc_mchannels():
    SECTION_NAME = 'MESSAGING'
    # FIXME: remove in future release
    if jm_single().config.has_section(SECTION_NAME):
        log.warning("Old IRC configuration detected. Please adopt your "
                    "joinmarket.cfg as documented in 'docs/config-irc-"
                    "update.md'. Support for the old setting will be removed "
                    "in a future version.")
        return _get_irc_mchannels_old()

    SECTION_NAME += ':'
    irc_sections = []
    for s in jm_single().config.sections():
        if s.startswith(SECTION_NAME):
            irc_sections.append(s)
    assert irc_sections

    fields = [("host", str), ("port", int), ("channel", str), ("usessl", str),
              ("socks5", str), ("socks5_host", str), ("socks5_port", str)]

    configs = []
    for section in irc_sections:
        server_data = {}
        for option, otype in fields:
            val = jm_single().config.get(section, option)
            server_data[option] = otype(val)
        server_data['btcnet'] = get_network()
        configs.append(server_data)
    return configs


def _get_irc_mchannels_old():
    fields = [("host", str), ("port", int), ("channel", str), ("usessl", str),
              ("socks5", str), ("socks5_host", str), ("socks5_port", str)]
    configdata = {}
    for f, t in fields:
        vals = jm_single().config.get("MESSAGING", f).split(",")
        if t == str:
            vals = [x.strip() for x in vals]
        else:
            vals = [t(x) for x in vals]
        configdata[f] = vals
    configs = []
    for i in range(len(configdata['host'])):
        newconfig = dict([(x, configdata[x][i]) for x in configdata])
        newconfig['btcnet'] = get_network()
        configs.append(newconfig)
    return configs


def get_config_irc_channel(channel_name):
    channel = "#" + channel_name
    if get_network() == 'testnet':
        channel += '-test'
    return channel


def get_network():
    """Returns network name"""
    return global_singleton.config.get("BLOCKCHAIN", "network")

def validate_address(addr):
    try:
        # automatically respects the network
        # as set in btc.select_chain_params(...)
        dummyaddr = btc.CCoinAddress(addr)
    except Exception as e:
        return False, repr(e)
    # additional check necessary because python-bitcointx
    # does not check hash length on p2sh construction.
    try:
        dummyaddr.to_scriptPubKey()
    except Exception as e:
        return False, repr(e)
    return True, "address validated"

_BURN_DESTINATION = "BURN"

def is_burn_destination(destination):
    return destination == _BURN_DESTINATION

def donation_address(reusable_donation_pubkey=None): #pragma: no cover
    #Donation code currently disabled, so not tested.
    if not reusable_donation_pubkey:
        reusable_donation_pubkey = ('02be838257fbfddabaea03afbb9f16e852'
                                    '9dfe2de921260a5c46036d97b5eacf2a')
    sign_k = binascii.hexlify(os.urandom(32)).decode('ascii')
    c = btc.sha256(btc.multiply(sign_k, reusable_donation_pubkey, True))
    sender_pubkey = btc.add_pubkeys(
        [reusable_donation_pubkey, btc.privtopub(c + '01', True)], True)
    sender_address = btc.pubtoaddr(sender_pubkey, get_p2pk_vbyte())
    log.debug('sending coins to ' + sender_address)
    return sender_address, sign_k


def remove_unwanted_default_settings(config):
    for section in config.sections():
        if section.startswith('MESSAGING:'):
            config.remove_section(section)

def load_program_config(config_path="", bs=None):
    global_singleton.config.readfp(io.StringIO(defaultconfig))
    if not config_path:
        config_path = lookup_appdata_folder(global_singleton.APPNAME)
    # we set the global home directory, but keep the config_path variable
    # for callers of this function:
    global_singleton.datadir = config_path
    jmprint("User data location: " + global_singleton.datadir, "info")
    if not os.path.exists(global_singleton.datadir):
        os.makedirs(global_singleton.datadir)
    # prepare folders for wallets and logs
    if not os.path.exists(os.path.join(global_singleton.datadir, "wallets")):
        os.makedirs(os.path.join(global_singleton.datadir, "wallets"))
    if not os.path.exists(os.path.join(global_singleton.datadir, "logs")):
        os.makedirs(os.path.join(global_singleton.datadir, "logs"))
    if not os.path.exists(os.path.join(global_singleton.datadir, "cmtdata")):
        os.makedirs(os.path.join(global_singleton.datadir, "cmtdata"))
    global_singleton.config_location = os.path.join(
        global_singleton.datadir, global_singleton.config_location)

    remove_unwanted_default_settings(global_singleton.config)
    loadedFiles = global_singleton.config.read([global_singleton.config_location
                                               ])
    #Hack required for electrum; must be able to enforce a different
    #blockchain interface even in default/new load.
    if bs:
        global_singleton.config.set("BLOCKCHAIN", "blockchain_source", bs)
    # Create default config file if not found
    if len(loadedFiles) != 1:
        with open(global_singleton.config_location, "w") as configfile:
            configfile.write(defaultconfig)
        jmprint("Created a new `joinmarket.cfg`. Please review and adopt the "
              "settings and restart joinmarket.", "info")
        sys.exit(EXIT_FAILURE)

    #These are left as sanity checks but currently impossible
    #since any edits are overlays to the default, these sections/options will
    #always exist.
    # FIXME: This check is a best-effort attempt. Certain incorrect section
    # names can pass and so can non-first invalid sections.
    for s in required_options: #pragma: no cover
        # check for sections
        avail = None
        if not global_singleton.config.has_section(s):
            for avail in global_singleton.config.sections():
                if avail.startswith(s):
                    break
            else:
                raise Exception(
                    "Config file does not contain the required section: " + s)
        # then check for specific options
        k = avail or s
        for o in required_options[s]:
            if not global_singleton.config.has_option(k, o):
                raise Exception("Config file does not contain the required "
                                "option '{}' in section '{}'.".format(o, k))

    loglevel = global_singleton.config.get("LOGGING", "console_log_level")
    try:
        set_logging_level(loglevel)
    except:
        jmprint("Failed to set logging level, must be DEBUG, INFO, WARNING, ERROR",
                "error")

    # Logs to the console are color-coded if user chooses (file is unaffected)
    if global_singleton.config.get("LOGGING", "color") == "true":
        set_logging_color(True)
    else:
        set_logging_color(False)

    try:
        global_singleton.maker_timeout_sec = global_singleton.config.getint(
            'TIMEOUT', 'maker_timeout_sec')
    except NoOptionError: #pragma: no cover
        log.debug('TIMEOUT/maker_timeout_sec not found in .cfg file, '
                  'using default value')

    # configure the interface to the blockchain on startup
    global_singleton.bc_interface = get_blockchain_interface_instance(
        global_singleton.config)

    # set the location of the commitments file; for non-mainnet a different
    # file is used to avoid conflict
    try:
        global_singleton.commit_file_location = global_singleton.config.get(
            "POLICY", "commit_file_location")
    except NoOptionError: #pragma: no cover
        log.debug("No commitment file location in config, using default "
                  "location cmtdata/commitments.json")
    if get_network() != "mainnet":
        # no need to be flexible for tests; note this is used
        # for regtest as well as testnet(3)
        global_singleton.commit_file_location = "cmtdata/testnet_commitments.json"
    set_commitment_file(os.path.join(config_path,
                                         global_singleton.commit_file_location))


def load_test_config(**kwargs):
    if "config_path" not in kwargs:
        load_program_config(config_path=".", **kwargs)
    else:
        load_program_config(**kwargs)

##########################################################
## Returns a tuple (rpc_user: String, rpc_pass: String) ##
##########################################################
def get_bitcoin_rpc_credentials(_config):
    filepath = None

    try:
        filepath = _config.get("BLOCKCHAIN", "rpc_cookie_file")
    except NoOptionError:
        pass

    if filepath:
        if os.path.isfile(filepath):
            rpc_credentials_string = open(filepath, 'r').read()
            return rpc_credentials_string.split(":")
        else:
            raise ValueError("Invalid cookie auth credentials file location")
    else:
        rpc_user = _config.get("BLOCKCHAIN", "rpc_user")
        rpc_password = _config.get("BLOCKCHAIN", "rpc_password")
        if not (rpc_user and rpc_password):
            raise ValueError("Invalid RPC auth credentials `rpc_user` and `rpc_password`")
        return rpc_user, rpc_password

def get_blockchain_interface_instance(_config):
    # todo: refactor joinmarket module to get rid of loops
    # importing here is necessary to avoid import loops
    from jmclient.blockchaininterface import BitcoinCoreInterface, \
        RegtestBitcoinCoreInterface, ElectrumWalletInterface, \
        BitcoinCoreNoHistoryInterface
    source = _config.get("BLOCKCHAIN", "blockchain_source")
    network = get_network()
    testnet = network == 'testnet'

    if source in ('bitcoin-rpc', 'regtest', 'bitcoin-rpc-no-history'):
        rpc_host = _config.get("BLOCKCHAIN", "rpc_host")
        rpc_port = _config.get("BLOCKCHAIN", "rpc_port")
        rpc_user, rpc_password = get_bitcoin_rpc_credentials(_config)
        rpc_wallet_file = _config.get("BLOCKCHAIN", "rpc_wallet_file")
        rpc = JsonRpc(rpc_host, rpc_port, rpc_user, rpc_password,
            rpc_wallet_file)
        if source == 'bitcoin-rpc': #pragma: no cover
            bc_interface = BitcoinCoreInterface(rpc, network)
            if testnet:
                btc.select_chain_params("bitcoin/testnet")
            else:
                btc.select_chain_params("bitcoin")
        elif source == 'regtest':
            bc_interface = RegtestBitcoinCoreInterface(rpc)
            btc.select_chain_params("bitcoin/regtest")
        elif source == "bitcoin-rpc-no-history":
            bc_interface = BitcoinCoreNoHistoryInterface(rpc, network)
            if testnet or network == "regtest":
                # in tests, for bech32 regtest addresses, for bc-no-history,
                # this will have to be reset manually:
                btc.select_chain_params("bitcoin/testnet")
            else:
                btc.select_chain_params("bitcoin")
        else:
            assert 0
    elif source == 'electrum':
        bc_interface = ElectrumWalletInterface(testnet)
    elif source == 'no-blockchain':
        bc_interface = None
    else:
        raise ValueError("Invalid blockchain source")
    return bc_interface

def update_persist_config(section, name, value):
    """ Unfortunately we cannot persist an updated config
    while preserving the full set of comments with ConfigParser's
    model (the 'set no-value settings' doesn't cut it).
    Hence if we want to update and persist, we must manually
    edit the file at the same time as editing the in-memory
    config object.

    Arguments: section and name must be strings (and
    section must already exist), while value can be any valid
    type for a config value, but must be cast-able to string.

    Returns: False if the config setting was not found,
    or True if it was found and edited+saved as intended.
    """

    m_line  = re.compile(r"^\s*" + name + r"\s*" + "=", re.IGNORECASE)
    m_section = re.compile(r"\[\s*" + section + r"\s*\]", re.IGNORECASE)

    # Find the single line containing the specified value; only accept
    # if it's the right section; create a new copy of all the config
    # lines, with that one line edited.
    # If one match is found and edited, rewrite the config and update
    # the in-memory config, else return an error.
    sectionname = None
    newlines = []
    match_found = False
    with open(jm_single().config_location, "r") as f:
        for line in f.readlines():
            newline  = line
            # ignore comment lines
            if line.strip().startswith("#"):
                newlines.append(line)
                continue
            regexp_match_section = m_section.search(line)
            if regexp_match_section:
                # get the section name from the match
                sectionname = regexp_match_section.group().strip("[]").strip()
            regexp_match = m_line.search(line)
            if regexp_match and sectionname and sectionname.upper(
                ) == section.upper():
                # We have the right line; change it
                newline = name + " = " + str(value)+"\n"
                match_found = True
            newlines.append(newline)
    # If it wasn't found, do nothing but return an error
    if not match_found:
        return False
    # success: update in-mem and re-persist
    jm_single().config.set(section, name, value)
    with open(jm_single().config_location, "wb") as f:
        f.writelines([x.encode("utf-8") for x in newlines])
    return True

def is_segwit_mode():
    return jm_single().config.get('POLICY', 'segwit') != 'false'

def is_native_segwit_mode():
    if not is_segwit_mode():
        return False
    return jm_single().config.get('POLICY', 'native') != 'false'

def process_shutdown(mode="command-line"):
    if mode=="command-line":
        from twisted.internet import reactor
        for dc in reactor.getDelayedCalls():
            dc.cancel()
        reactor.stop()

def process_startup():
    from twisted.internet import reactor
    reactor.run()
