#Protocol version
JM_VERSION = 5

#Username on all messagechannels; will be set in MessageChannelCollection
nickname = None

separator = " "
offertypes = {"reloffer": [(int, "oid"), (int, "minsize"), (int, "maxsize"),
                           (int, "txfee"), (float, "cjfee")],
              "absoffer": [(int, "oid"), (int, "minsize"), (int, "maxsize"),
                           (int, "txfee"), (int, "cjfee")],
              "swreloffer": [(int, "oid"), (int, "minsize"), (int, "maxsize"),
                           (int, "txfee"), (float, "cjfee")],
              "swabsoffer": [(int, "oid"), (int, "minsize"), (int, "maxsize"),
                           (int, "txfee"), (int, "cjfee")],
              "sw0reloffer": [(int, "oid"), (int, "minsize"), (int, "maxsize"),
                           (int, "txfee"), (float, "cjfee")],
              "sw0absoffer": [(int, "oid"), (int, "minsize"), (int, "maxsize"),
                           (int, "txfee"), (int, "cjfee")]}

offername_list = list(offertypes.keys())

fidelity_bond_cmd_list = ["tbond"]

ORDER_KEYS = ['counterparty', 'oid', 'ordertype', 'minsize', 'maxsize', 'txfee',
              'cjfee']

COMMAND_PREFIX = '!'
JOINMARKET_NICK_HEADER = 'J'
NICK_HASH_LENGTH = 10
NICK_MAX_ENCODED = 14  #comes from base58 expansion; recalculate if above changes

#commitments; note multiple options may be used in future
COMMITMENT_PREFIXES = ["P"]
#Lists of valid commands
encrypted_commands = ["auth", "ioauth", "tx", "sig"]
plaintext_commands = ["fill", "error", "pubkey", "orderbook", "push"]
commitment_broadcast_list = ["hp2"]
plaintext_commands += offername_list
plaintext_commands += commitment_broadcast_list
public_commands = commitment_broadcast_list + ["orderbook", "cancel"
                                              ] + offername_list
private_commands = encrypted_commands + plaintext_commands
