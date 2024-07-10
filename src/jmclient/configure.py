import atexit
import io
import logging
import os
import re
import socket
import subprocess
import sys
from configparser import ConfigParser, NoOptionError
from signal import SIGINT
from typing import Any, List, Optional, Tuple

import jmbitcoin as btc
from jmbase.support import (get_log, joinmarket_alert, core_alert, debug_silence,
                            set_logging_level, jmprint, set_logging_color,
                            JM_APP_NAME, lookup_appdata_folder, EXIT_FAILURE)
from jmclient.jsonrpc import JsonRpc
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
global_singleton.BITCOIN_DUST_THRESHOLD = btc.DUST_THRESHOLD
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


def jm_single() -> AttributeDict:
    return global_singleton

# FIXME: Add rpc_* options here in the future!
required_options = {'BLOCKCHAIN': ['blockchain_source', 'network'],
                    'MESSAGING': ['host', 'channel', 'port'],
                    'POLICY': ['absurd_fee_per_kb', 'taker_utxo_retries',
                               'taker_utxo_age', 'taker_utxo_amtpercent']}

_DEFAULT_INTEREST_RATE = "0.015"

_DEFAULT_BONDLESS_MAKERS_ALLOWANCE = "0.125"

defaultconfig = \
    """
[DAEMON]
# set to 1 to run the daemon service within this process;
# set to 0 if the daemon is run separately (using script joinmarketd.py)
no_daemon = 1

# Port on which daemon serves; note that communication still
# occurs over this port even if no_daemon = 1
daemon_port = 27183

# Currently, running the daemon on a remote host is
# *NOT* supported, so don't change this variable
daemon_host = localhost

# by default the client-daemon connection is plaintext, set to 'true' to use TLS;
# for this, you need to have a valid (self-signed) certificate installed
use_ssl = false

[BLOCKCHAIN]
# options: bitcoin-rpc, regtest, bitcoin-rpc-no-history, no-blockchain
# When using bitcoin-rpc-no-history remember to increase the gap limit to scan for more addresses, try -g 5000
# Use 'no-blockchain' to run the ob-watcher.py script in scripts/obwatch without current access
# to Bitcoin Core; note that use of this option for any other purpose is currently unsupported.
blockchain_source = bitcoin-rpc

# options: signet, testnet, mainnet
# Note: for regtest, use network = testnet
network = mainnet

rpc_host = localhost
# default ports are 8332 for mainnet, 18443 for regtest, 18332 for testnet, 38332 for signet
rpc_port =

# Use either rpc_user / rpc_password pair or rpc_cookie_file.
rpc_user = bitcoin
rpc_password = password
#rpc_cookie_file =

# rpc_wallet_file is Bitcoin Core wallet which is used for address and
# transaction monitoring (it is watchonly, no private keys are stored there).
# It must be created manually if does not exist, see docs/USAGE.md for more
# information.
rpc_wallet_file =

[MESSAGING:onion]
# onion based message channels must have the exact type 'onion'
# (while the section name above can be MESSAGING:whatever), and there must
# be only ONE such message channel configured (note the directory servers
# can be multiple, below):
type = onion

socks5_host = localhost
socks5_port = 9050

# the tor control configuration.
# for most people running the tor daemon
# on Linux, no changes are required here:
tor_control_host = localhost
# or, to use a UNIX socket
# tor_control_host = unix:/var/run/tor/control
# note: port needs to be provided (but is ignored for UNIX socket)
tor_control_port = 9051

# the host/port actually serving the hidden service
# (note the *virtual port*, that the client uses,
# is hardcoded to as per below 'directory node configuration'.
onion_serving_host = 127.0.0.1
onion_serving_port = 8080

# directory node configuration
#
# This is mandatory for directory nodes (who must also set their
# own *.onion:port as the only directory in directory_nodes, below),
# but NOT TO BE USED by non-directory nodes (which is you, unless
# you know otherwise!), as it will greatly degrade your privacy.
# (note the default is no value, don't replace it with "").
hidden_service_dir =
#
# This is a comma separated list (comma can be omitted if only one item).
# Each item has format host:port ; both are required, though port will
# be 5222 if created in this code.
# for MAINNET:
directory_nodes = g3hv4uynnmynqqq2mchf3fcm3yd46kfzmcdogejuckgwknwyq5ya6iad.onion:5222,3kxw6lf5vf6y26emzwgibzhrzhmhqiw6ekrek3nqfjjmhwznb2moonad.onion:5222,bqlpq6ak24mwvuixixitift4yu42nxchlilrcqwk2ugn45tdclg42qid.onion:5222

# for SIGNET (testing network):
# directory_nodes = rr6f6qtleiiwic45bby4zwmiwjrj3jsbmcvutwpqxjziaydjydkk5iad.onion:5222,k74oyetjqgcamsyhlym2vgbjtvhcrbxr4iowd4nv4zk5sehw4v665jad.onion:5222,y2ruswmdbsfl4hhwwiqz4m3sx6si5fr6l3pf62d4pms2b53wmagq3eqd.onion:5222

# This setting is ONLY for developer regtest setups,
# running multiple bots at once. Don't alter it otherwise
regtest_count = 0,0

## IRC SERVER 1: Darkscience IRC (Tor, IP)
################################################################################
[MESSAGING:server1]
# by default the legacy format without a `type` field is
# understood to be IRC, but you can, optionally, add it:
# type = irc
channel = joinmarket-pit
port = 6697
usessl = true

# For traditional IP:
#host = irc.darkscience.net
#socks5 = false

# For Tor (recommended as clearnet alternative):
host = darkirc6tqgpnwd3blln3yfv5ckl47eg7llfxkmtovrv7c7iwohhb6ad.onion
socks5 = true
socks5_host = localhost
socks5_port = 9050

## IRC SERVER 2: ILITA IRC (optional IRC alternate, Tor only)
################################################################################
[MESSAGING:server2]
channel = joinmarket-pit
port = 6667
usessl = false
socks5 = true
socks5_host = localhost

host = ilitafrzzgxymv6umx2ux7kbz3imyeko6cnqkvy4nisjjj4qpqkrptid.onion
socks5_port = 9050

## IRC SERVER 3: (backup) hackint IRC (Tor, IP)
################################################################################
#[MESSAGING:server3]
# channel = joinmarket-pit
# For traditional IP:
## host = irc.hackint.org
## port = 6697
## usessl = true
## socks5 = false
# For Tor (default):
#host = ncwkrwxpq2ikcngxq3dy2xctuheniggtqeibvgofixpzvrwpa77tozqd.onion
#port = 6667
#usessl = false
#socks5 = true
#socks5_host = localhost
#socks5_port = 9050

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

# Use native segwit (bech32) wallet. If set to false, p2sh-p2wkh
# will be used when generating the addresses for this wallet.
# Notes: 1. The default joinmarket pit is native segwit.
#        2. You cannot change the type of a pre-existing wallet.
native = true

# for dust sweeping, try merge_algorithm = gradual
# for more rapid dust sweeping, try merge_algorithm = greedy
# for most rapid dust sweeping, try merge_algorithm = greediest
# but don't forget to bump your miner fees!
merge_algorithm = default

# Used currently by the RPC to modify the gap limit
# for address searching during wallet sync. Command line
# scripts can use the command line flag `-g` instead.
gaplimit = 6

# Disable the caching of addresses and scripts when
# syncing the wallet. You DO NOT need to set this to 'true',
# unless there is an issue of file corruption or a code bug.
wallet_caching_disabled = false

# The fee estimate is based on a projection of how many sats/kilo-vbyte
# are needed to get in one of the next N blocks. N is set here as
# the value of 'tx_fees'. This cost estimate is high if you set
# N=1, so we choose 3 for a more reasonable figure, as our default.
# You can also set your own fee/kilo-vbyte: any number higher than 1 thousand
# will be interpreted as the fee in sats/kilo-vbyte that you wish to use.
#
# Example: N=30000 will use 30 thousand sats/kilo-vbyte (30 sats/vB) as a fee,
# while N=5 will use the 5 block estimate from your selected blockchain source.
tx_fees = 3

# Transaction fee rate variance factor, 0.2 means fee will be random
# between any manually chosen value and 20% above that value, so if you set
# tx_fees=10000 and tx_fees_factor=0.2, it might use any value between
# 10 thousand and 12 thousand for your transactions.
tx_fees_factor = 0.2

# For users getting transaction fee estimates over an API,
# place a sanity check limit on the sats/kilo-vbyte to be paid.
# This limit is also applied to users using Core, even though
# Core has its own sanity check limit, which is currently
# 1 million satoshis.
#
# Example: N=350000 will use 350 thousand sats/kilo-vbyte (350 sats/vB) as a
# maximum fee.
absurd_fee_per_kb = 350000

# In decimal, the maximum allowable change either lower or
# higher, that the fee rate used for coinjoin sweeps is
# allowed to be.
# (note: coinjoin sweeps *must estimate* fee rates;
# they cannot be exact due to the lack of change output.)
#
# Example: max_sweep_fee_change = 0.4, with tx_fees = 10000,
# means actual fee rate achieved in the sweep can be as low
# as 6 thousand sats/kilo-vbyte up to 14 thousand sats/kilo-vbyte.
#
# If this is not achieved, the transaction is aborted. For tumbler,
# it will then be retried until successful.
# WARNING: too-strict setting may result in using up a lot
# of PoDLE commitments, hence the default 0.8 (80%).
max_sweep_fee_change = 0.8

# Maximum absolute coinjoin fee in satoshi to pay to a single
# market maker for a transaction. Both the limits given in
# max_cj_fee_abs and max_cj_fee_rel must be exceeded in order
# to not consider a certain offer.
#max_cj_fee_abs = x

# Maximum relative coinjoin fee, in fractions of the coinjoin value
# e.g. if your coinjoin amount is 2 btc (200 million satoshi) and
# max_cj_fee_rel = 0.001 (0.1%), the maximum fee allowed would
# be 0.002 btc (200 thousand satoshi)
#max_cj_fee_rel = x

# The range of confirmations passed to the `listunspent` bitcoind RPC call
# 1st value is the inclusive minimum, defaults to one confirmation
# 2nd value is the exclusive maximum, defaults to most-positive-bignum (Google Me!)
# leaving it unset or empty defers to bitcoind's default values, ie [1, 9999999]
#listunspent_args = []
# That's what you should do, unless you have a specific reason, eg:
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
# Note: if your counterparties do not support it, you will fall back
# to broadcasting via your own node.
#
# not-self = never broadcast with your own bitcoin node.
#
# Note: in this case if your counterparties do not broadcast for you, you
# will have to broadcast the tx manually (you can take the tx hex from the log
# or terminal) via some other channel. It is not recommended to choose this
# option when running schedules/tumbler.
tx_broadcast = random-peer

# If makers do not respond while creating a coinjoin transaction,
# the non-responding ones will be ignored. This is the minimum
# amount of makers which we are content with for the coinjoin to
# succeed. Less makers means that the whole process will restart
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

# Interest rate used when calculating the value of fidelity bonds created
# by locking bitcoins in timelocked addresses
# See also:
# https://gist.github.com/chris-belcher/87ebbcbb639686057a389acb9ab3e25b#determining-interest-rate-r
# Set as a real number, i.e. 1 = 100% and 0.01 = 1%
interest_rate = """ + _DEFAULT_INTEREST_RATE + """

# Some makers run their bots to mix their funds not just to earn money
# So to improve privacy very slightly takers dont always choose a maker based
# on his fidelity bond but allow a certain small percentage to be chosen completely
# randomly without taking into account fidelity bonds
# This parameter sets how many makers on average will be chosen regardless of bonds
# A real number, i.e. 1 = 100%, 0.125 = 1/8 = 1 in every 8 makers on average will be bondless
bondless_makers_allowance = """ + _DEFAULT_BONDLESS_MAKERS_ALLOWANCE + """

# To (strongly) disincentivize Sybil behaviour, the value assessment of the bond
# is based on the (time value of the bond)^x where x is the bond_value_exponent here,
# where x > 1. It is a real number (so written as a decimal).
bond_value_exponent = 1.3

tx_max_expected_probability = 1.0

##############################
# THE FOLLOWING SETTINGS ARE REQUIRED TO DEFEND AGAINST SNOOPERS.
# DON'T ALTER THEM UNLESS YOU UNDERSTAND THE IMPLICATIONS.
##############################

# Number of retries allowed for a specific utxo, to prevent DOS/snooping.
# Lower settings make snooping more expensive, but also prevent honest users
# from retrying if an error occurs.
taker_utxo_retries = 3

# Number of confirmations required for the commitment utxo mentioned above.
# this effectively rate-limits a snooper.
taker_utxo_age = 5

# Percentage of coinjoin amount that the commitment utxo must have
# as a minimum BTC amount. Thus 20 means a 1BTC coinjoin requires the
# utxo to be at least 0.2 btc.
taker_utxo_amtpercent = 20

# Set to 1 to accept broadcast PoDLE commitments from other bots, and
# add them to your blacklist (only relevant for Makers).
# There is no way to spoof these values, so the only "risk" is that
# someone fills your blacklist file with a lot of data.
accept_commitment_broadcasts = 1

# Location of your commitments.json file (stores commitments you've used
# and those you want to use in future), relative to the scripts directory.
commit_file_location = cmtdata/commitments.json

# Location of the file used by makers to keep track of used/blacklisted
# commitments. For remote daemon, set to `.` to have it stored locally
# (but note that *all* bots using the same code installation share it,
# in this case, which can be bad in testing).
commitment_list_location = cmtdata/commitmentlist

##############################
# END OF ANTI-SNOOPING SETTINGS
##############################

[PAYJOIN]
# For the majority of situations, the defaults
# need not be altered - they will ensure you don't pay
# a significantly higher fee.
# MODIFICATION OF THESE SETTINGS IS DISADVISED.

# Payjoin protocol version; currently only '1' is supported.
payjoin_version = 1

# Servers can change their destination address by default (0).
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

# This is the minimum sats/vbyte we allow in the payjoin
# transaction; note it is decimal, not integer.
min_fee_rate = 1.1

# For payjoins as sender (i.e. client) to hidden service endpoints,
# the socks5 configuration:
onion_socks5_host = localhost
onion_socks5_port = 9050

# For payjoin onion service creation:
# the tor control configuration:
tor_control_host = localhost

# or, to use a UNIX socket
# control_host = unix:/var/run/tor/control
# note: port needs to be provided (but is ignored for UNIX socket)
tor_control_port = 9051

# the host/port actually serving the hidden service
# (note the *virtual port*, that the client uses,
# is hardcoded to 80):
onion_serving_host = 127.0.0.1
onion_serving_port = 8082

# in some exceptional case the HS may be SSL configured,
# this feature is not yet implemented in code, but here for the
# future:
hidden_service_ssl = false

[YIELDGENERATOR]
# [string, 'reloffer' or 'absoffer'], which fee type to actually use
ordertype = reloffer

# [satoshis, any integer] / absolute offer fee you wish to receive for coinjoins (cj)
cjfee_a = 500

# [fraction, any str between 0-1] / relative offer fee you wish to receive based on a cj's amount
cjfee_r = 0.00002

# [fraction, 0-1] / variance around the average fee. Ex: 200 fee, 0.2 var = fee is btw 160-240
cjfee_factor = 0.1

# [satoshis, any integer] / the average transaction fee you're adding to coinjoin transactions
# (note: this will soon be deprecated; leave at zero)
txfee_contribution = 0

# [fraction, 0-1] / variance around the average fee. Ex: 1000 fee, 0.2 var = fee is btw 800-1200
txfee_contribution_factor = 0.3

# [satoshis, any integer] / minimum size of your cj offer. Lower cj amounts will be disregarded
minsize = 100000

# [fraction, 0-1] / variance around all offer sizes. Ex: 500k minsize, 0.1 var = 450k-550k
size_factor = 0.1

[SNICKER]
# Any other value than 'true' will be treated as False,
# and no SNICKER actions will be enabled in that case:
enabled = false

# In satoshis, we require any SNICKER to pay us at least
# this much (can be negative), otherwise we will refuse
# to sign it:
lowest_net_gain = 0

# Comma separated list of servers (if port is omitted as :port, it
# is assumed to be 80) which we will poll against (all, in sequence); note
# that they are allowed to be *.onion or cleartext servers, and no
# scheme (http(s) etc) needs to be added to the start.
servers = cn5lfwvrswicuxn3gjsxoved6l2gu5hdvwy5l3ev7kg6j7lbji2k7hqd.onion,

# How many minutes between each polling event to each server above:
polling_interval_minutes = 60
"""

#This allows use of the jmclient package with a
#configuration set by an external caller; not to be used
#in conjuction with calls to load_program_config.
def set_config(cfg: ConfigParser, bcint = None) -> None:
    global_singleton.config = cfg
    if bcint:
        global_singleton.bc_interface = bcint


def get_mchannels(mode: str = "TAKER") -> list:
    SECTION_NAME = 'MESSAGING'
    # FIXME: remove in future release
    if jm_single().config.has_section(SECTION_NAME):
        log.warning("Old IRC configuration detected. Please adopt your "
                    "joinmarket.cfg as documented in 'docs/config-irc-"
                    "update.md'. Support for the old setting will be removed "
                    "in a future version.")
        return _get_irc_mchannels_old()

    SECTION_NAME += ':'

    irc_fields = [("host", str), ("port", int), ("channel", str), ("usessl", str),
              ("socks5", str), ("socks5_host", str), ("socks5_port", int)]
    onion_fields = [("type", str), ("directory_nodes", str), ("regtest_count", str),
                    ("socks5_host", str), ("socks5_port", int),
                    ("tor_control_host", str), ("tor_control_port", int),
                    ("onion_serving_host", str), ("onion_serving_port", int),
                    ("hidden_service_dir", str)]

    def get_irc_section(s):
        server_data = {}
        # check if socks5 is enabled for tor and load relevant config if so
        try:
            server_data["socks5"] = jm_single().config.get(s, "socks5")
        except NoOptionError:
            server_data["socks5"] = "false"
        if server_data["socks5"].lower() == 'true':
            server_data["socks5_host"] = jm_single().config.get(s, "socks5_host")
            server_data["socks5_port"] = jm_single().config.get(s, "socks5_port")

        for option, otype in irc_fields:
            val = jm_single().config.get(s, option)
            server_data[option] = otype(val)
        server_data['btcnet'] = get_network()
        return server_data

    def get_onion_section(s):
        onion_data = {}
        for option, otype in onion_fields:
            try:
                val = jm_single().config.get(s, option)
            except NoOptionError:
                continue
            onion_data[option] = otype(val)
        # the onion messaging section must specify whether
        # to serve an onion:
        onion_data["serving"] = mode == "MAKER"
        onion_data["passive"] = mode == "PASSIVE"
        onion_data['btcnet'] = get_network()
        # Just to allow a dynamic set of var:
        onion_data["section-name"] = s
        return onion_data

    onion_sections = []
    irc_sections = []
    for section in jm_single().config.sections():
        if not section.startswith(SECTION_NAME):
            continue
        if jm_single().config.has_option(section, "type"):
            channel_type = jm_single().config.get(section, "type").lower()
            if channel_type == "onion":
                onion_sections.append(get_onion_section(section))
            elif channel_type == "irc":
                irc_sections.append(get_irc_section(section))
        else:
            irc_sections.append(get_irc_section(section))
    assert irc_sections or onion_sections
    assert len(onion_sections) < 2
    return irc_sections + onion_sections

def _get_irc_mchannels_old() -> list:
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

class JMPluginService(object):
    """ Allows us to configure on-startup
    any additional service (such as SNICKER).
    For now only covers logging.
    """
    def __init__(self, name: str, requires_logging: bool = True) -> None:
        self.name = name
        self.requires_logging = requires_logging

    def start_plugin_logging(self, wallet: str) -> None:
        """ This requires the name of the active wallet
        to set the logfile; TODO other plugin services may
        need a different setup.
        """
        self.wallet = wallet
        self.logfilename = "{}-{}.log".format(self.name,
                            self.wallet.get_wallet_name())
        self.start_logging()

    def set_log_dir(self, logdirname: str) -> None:
        self.logdirname = logdirname

    def start_logging(self) -> None:
        logFormatter = logging.Formatter(
            ('%(asctime)s [%(levelname)-5.5s] {} - %(message)s'.format(
                self.name)))
        fileHandler = logging.FileHandler(
            self.logdirname + '/{}'.format(self.logfilename))
        fileHandler.setFormatter(logFormatter)
        get_log().addHandler(fileHandler)

def get_network() -> str:
    """Returns network name"""
    return global_singleton.config.get("BLOCKCHAIN", "network")

def validate_address(addr: str) -> Tuple[bool, str]:
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

def is_burn_destination(destination: str) -> bool:
    return destination == _BURN_DESTINATION

def get_interest_rate() -> float:
    return float(global_singleton.config.get('POLICY', 'interest_rate',
        fallback=_DEFAULT_INTEREST_RATE))

def get_bondless_makers_allowance() -> float:
    return float(global_singleton.config.get('POLICY', 'bondless_makers_allowance',
        fallback=_DEFAULT_BONDLESS_MAKERS_ALLOWANCE))

def _remove_unwanted_default_settings(config: ConfigParser) -> None:
    for section in config.sections():
        if section.startswith('MESSAGING:'):
            config.remove_section(section)

def load_program_config(config_path: str = "", bs: Optional[str] = None,
                        plugin_services: List[JMPluginService] = []) -> None:
    global_singleton.config.read_file(io.StringIO(defaultconfig))
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

    _remove_unwanted_default_settings(global_singleton.config)
    try:
        loadedFiles = global_singleton.config.read(
            [global_singleton.config_location])
    except UnicodeDecodeError:
        jmprint("Error loading `joinmarket.cfg`, invalid file format.",
            "info")
        sys.exit(EXIT_FAILURE)

    # Hack required for bitcoin-rpc-no-history and probably others
    # (historicaly electrum); must be able to enforce a different blockchain
    # interface even in default/new load.
    if bs:
        global_singleton.config.set("BLOCKCHAIN", "blockchain_source", bs)
    # Create default config file if not found
    if len(loadedFiles) != 1:
        with open(global_singleton.config_location, "w") as configfile:
            configfile.write(defaultconfig)
        jmprint("Created a new `joinmarket.cfg`. Please review and adopt the "
              "settings and restart joinmarket.", "info")
        sys.exit(EXIT_FAILURE)

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
        if get_network() == "mainnet":
            log.debug("No commitment file location in config, using default "
                  "location cmtdata/commitments.json")
    if get_network() != "mainnet":
        # no need to be flexible for tests; note this is used
        # for regtest, signet and testnet3
        global_singleton.commit_file_location = "cmtdata/" + get_network() + \
            "_commitments.json"
    set_commitment_file(os.path.join(config_path,
                                         global_singleton.commit_file_location))

    if global_singleton.config.get("POLICY", "commitment_list_location") == ".":
        # Exceptional case as explained in comment in joinmarket.cfg:
        global_singleton.commitment_list_location = "."
    else:
        global_singleton.commitment_list_location = os.path.join(config_path,
        global_singleton.config.get("POLICY", "commitment_list_location"))

    for p in plugin_services:
        # for now, at this config level, the only significance
        # of a "plugin" is that it keeps its own separate log.
        # We require that a section exists in the config file,
        # and that it has enabled=true:
        assert isinstance(p, JMPluginService)
        if not (global_singleton.config.has_section(p.name) and \
                global_singleton.config.has_option(p.name, "enabled") and \
                global_singleton.config.get(p.name, "enabled") == "true"):
            break
        if p.requires_logging:
            # make sure the environment can accept a logfile by
            # creating the directory in the correct place,
            # and setting that in the plugin object; the plugin
            # itself will switch on its own logging when ready,
            # attaching a filehandler to the global log.
            plogsdir = os.path.join(os.path.dirname(
                global_singleton.config_location), "logs", p.name)
            if not os.path.exists(plogsdir):
                os.makedirs(plogsdir)
            p.set_log_dir(plogsdir)

def gracefully_kill_subprocess(p) -> None:
    # See https://stackoverflow.com/questions/43274476/is-there-a-way-to-check-if-a-subprocess-is-still-running
    if p.poll() is None:
        p.send_signal(SIGINT)

def check_and_start_tor() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(("127.0.0.1", 9050))
    sock.close()
    if result == 0:
        return
    log.info("Nobody listens on 127.0.0.1:9050, trying to start Tor.")
    tor_bin = os.path.join(sys.prefix, "bin", "tor")
    if not os.path.exists(tor_bin):
        log.info("Can't find our custom tor.")
        return
    command = [tor_bin, "-f", os.path.join(sys.prefix,
        "etc", "tor", "torrc")]
    # output messages from tor if loglevel is debug, they might be useful
    if global_singleton.config.get("LOGGING", "console_log_level") == "DEBUG":
        tor_stdout = sys.stdout
    else:
        tor_stdout = open(os.devnull, 'w')
    tor_subprocess = subprocess.Popen(command, stdout=tor_stdout,
        stderr=subprocess.STDOUT, close_fds=True)
    atexit.register(gracefully_kill_subprocess, tor_subprocess)
    log.debug("Started Tor subprocess with pid " + str(tor_subprocess.pid))

def load_test_config(**kwargs) -> None:
    if "config_path" not in kwargs:
        load_program_config(config_path=".", **kwargs)
    else:
        load_program_config(**kwargs)

##########################################################
## Returns a tuple (rpc_user: String, rpc_pass: String) ##
##########################################################
def _get_bitcoin_rpc_credentials(_config: ConfigParser) -> Tuple[str, str]:
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

def get_blockchain_interface_instance(_config: ConfigParser):
    # todo: refactor joinmarket module to get rid of loops
    # importing here is necessary to avoid import loops
    from jmclient.blockchaininterface import BitcoinCoreInterface, \
        RegtestBitcoinCoreInterface, \
        BitcoinCoreNoHistoryInterface
    source = _config.get("BLOCKCHAIN", "blockchain_source")
    network = get_network()
    testnet = (network == 'testnet' or network == 'signet')

    if source in ('bitcoin-rpc', 'regtest', 'bitcoin-rpc-no-history'):
        rpc_host = _config.get("BLOCKCHAIN", "rpc_host")
        rpc_port = _config.get("BLOCKCHAIN", "rpc_port")
        if rpc_port == '':
            if network == 'mainnet':
                rpc_port = 8332
            elif network == 'regtest':
                rpc_port = 18443
            elif network == 'testnet':
                rpc_port = 18332
            elif network == 'signet':
                rpc_port = 38332
            else:
                raise ValueError('wrong network configured: ' + network)
        rpc_user, rpc_password = _get_bitcoin_rpc_credentials(_config)
        rpc_wallet_file = _config.get("BLOCKCHAIN", "rpc_wallet_file")
        rpc = JsonRpc(rpc_host, rpc_port, rpc_user, rpc_password)
        if source == 'bitcoin-rpc': #pragma: no cover
            bc_interface = BitcoinCoreInterface(rpc, network,
                rpc_wallet_file)
            if testnet:
                btc.select_chain_params("bitcoin/testnet")
            else:
                btc.select_chain_params("bitcoin")
        elif source == 'regtest':
            bc_interface = RegtestBitcoinCoreInterface(rpc,
                rpc_wallet_file)
            btc.select_chain_params("bitcoin/regtest")
        elif source == "bitcoin-rpc-no-history":
            bc_interface = BitcoinCoreNoHistoryInterface(rpc, network,
                rpc_wallet_file)
            if testnet or network == "regtest":
                # in tests, for bech32 regtest addresses, for bc-no-history,
                # this will have to be reset manually:
                btc.select_chain_params("bitcoin/testnet")
            else:
                btc.select_chain_params("bitcoin")
        else:
            assert 0
    elif source == 'no-blockchain':
        bc_interface = None
    else:
        raise ValueError("Invalid blockchain source")
    return bc_interface

def update_persist_config(section: str, name: str, value: Any) -> bool:
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

def is_segwit_mode() -> bool:
    return jm_single().config.get('POLICY', 'segwit') != 'false'

def is_native_segwit_mode() -> bool:
    if not is_segwit_mode():
        return False
    return jm_single().config.get('POLICY', 'native') != 'false'

def process_shutdown(mode: str = "command-line") -> None:
    if mode=="command-line":
        from twisted.internet import reactor
        for dc in reactor.getDelayedCalls():
            dc.cancel()
        reactor.stop()

def process_startup() -> None:
    from twisted.internet import reactor
    reactor.run()
