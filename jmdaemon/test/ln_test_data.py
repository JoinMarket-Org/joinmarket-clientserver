from jmbase import bintohex
from jmdaemon.lnonion import NICK_PEERLOCATOR_SEPARATOR

nick1 = "ln_publisher"
nick2 = "ln_receiver"
nick3 = "ln_thirdparty"

mock_getinfo_result = {'id': '03df15dbd9e20c811cc5f4155745e89540a0b83f33978317cebe9dfc46c5253c55',
                       'alias': 'BIZARREYARD-v0.9.1-13-gc8c2227', 'color': '028984', 'num_peers': 0,
                       'num_pending_channels': 0, 'num_active_channels': 0, 'num_inactive_channels': 0,
                       'address': [], 'binding': [{'type': 'ipv4', 'address': '127.0.0.1', 'port': 9835}],
                       'version': 'v0.9.1-13-gc8c2227', 'blockheight': 61988, 'network': 'regtest',
                       'msatoshi_fees_collected': 0, 'fees_collected_msat': "0msat", 'lightning-dir': '/not/real/path'}

def get_mock_msg(num, msg, nick=None):
    hextype = "%0.4x" % num
    msgval = b""
    if nick:
        msgval = (nick + NICK_PEERLOCATOR_SEPARATOR).encode("utf-8")
    msgval += msg
    msgval = bintohex(msgval)
    return {"peer_id": "fake_peerid", "payload": hextype + msgval}

mock_control_message1 = get_mock_msg(789, b";028984b787834f93dbac6b9902368cdc2da34c563cb5626a484109f35aac32e84e", nick2)
mock_control_connected_message = get_mock_msg(785, b"028984b787834f93dbac6b9902368cdc2da34c563cb5626a484109f35aac32e84e@dummyhost:9735")
mock_receiver_pubmsg = get_mock_msg(687, b"!PUBLIC!orderbook", nick2)