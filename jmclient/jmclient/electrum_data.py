# Default server list from electrum client
# https://github.com/spesmilo/electrum, file https://github.com/spesmilo/electrum/blob/7dbd612d5dad13cd6f1c0df32534a578bad331ad/lib/servers.json

# Edit this to 't' instead of 's' to use TCP;
# This is specifically not exposed in joinmarket.cfg
# since there is no good reason to prefer TCP over SSL
# unless the latter simply doesn't work.
DEFAULT_PROTO = 's'

DEFAULT_PORTS = {'t': '50001', 's': '50002'}

DEFAULT_SERVERS = {
    "E-X.not.fyi": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "ELECTRUMX.not.fyi": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "ELEX01.blackpole.online": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "VPS.hsmiths.com": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "bitcoin.freedomnode.com": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "btc.smsys.me": {
        "pruning": "-",
        "s": "995",
        "version": "1.1"
    },
    "currentlane.lovebitco.in": {
        "pruning": "-",
        "t": "50001",
        "version": "1.1"
    },
    "daedalus.bauerj.eu": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "de01.hamster.science": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "ecdsa.net": {
        "pruning": "-",
        "s": "110",
        "t": "50001",
        "version": "1.1"
    },
    "elec.luggs.co": {
        "pruning": "-",
        "s": "443",
        "version": "1.1"
    },
    "electrum.akinbo.org": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrum.antumbra.se": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrum.be": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrum.coinucopia.io": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrum.cutie.ga": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrum.festivaldelhumor.org": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrum.hsmiths.com": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrum.qtornado.com": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrum.vom-stausee.de": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrum3.hachre.de": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrumx.bot.nu": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "electrumx.westeurope.cloudapp.azure.com": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "elx01.knas.systems": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "ex-btc.server-on.net": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "helicarrier.bauerj.eu": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "mooo.not.fyi": {
        "pruning": "-",
        "s": "50012",
        "t": "50011",
        "version": "1.1"
    },
    "ndnd.selfhost.eu": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "node.arihanc.com": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "node.xbt.eu": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "node1.volatilevictory.com": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "noserver4u.de": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "qmebr.spdns.org": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "raspi.hsmiths.com": {
        "pruning": "-",
        "s": "51002",
        "t": "51001",
        "version": "1.1"
    },
    "s2.noip.pl": {
        "pruning": "-",
        "s": "50102",
        "version": "1.1"
    },
    "s5.noip.pl": {
        "pruning": "-",
        "s": "50105",
        "version": "1.1"
    },
    "songbird.bauerj.eu": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "us.electrum.be": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    },
    "us01.hamster.science": {
        "pruning": "-",
        "s": "50002",
        "t": "50001",
        "version": "1.1"
    }
}


def set_electrum_testnet():
    global DEFAULT_PORTS, DEFAULT_SERVERS
    DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    DEFAULT_SERVERS = {
        'testnetnode.arihanc.com': {'t': '51001', 's': '51002'},
        'testnet1.bauerj.eu': {'t': '51001', 's': '51002'},
        # '14.3.140.101': {'t':'51001', 's':'51002'}, #non-responsive?
        'testnet.hsmiths.com': {'t': '53011', 's': '53012'},
        'electrum.akinbo.org': {'t': '51001', 's': '51002'},
        'ELEX05.blackpole.online': {'t': '52011', 's': '52002'}, }
    # Replace with for regtest:
    # 'localhost': {'t': '50001', 's': '51002'},}


def get_default_servers():
    return DEFAULT_SERVERS


def get_default_ports():
    return DEFAULT_PORTS
