from jmbase import bintohex, JM_APP_NAME
import json
from jmdaemon import JM_VERSION

nick1 = "ln_publisher"
nick2 = "ln_receiver"
nick3 = "ln_thirdparty"

mock_getinfo_result = {'id': '03df15dbd9e20c811cc5f4155745e89540a0b83f33978317cebe9dfc46c5253c55',
                       'alias': 'BIZARREYARD-v0.9.1-13-gc8c2227', 'color': '028984', 'num_peers': 0,
                       'num_pending_channels': 0, 'num_active_channels': 0, 'num_inactive_channels': 0,
                       'address': [], 'binding': [{'type': 'ipv4', 'address': '127.0.0.1', 'port': 9835}],
                       'version': 'v0.9.1-13-gc8c2227', 'blockheight': 61988, 'network': 'regtest',
                       'msatoshi_fees_collected': 0, 'fees_collected_msat': "0msat", 'lightning-dir': '/not/real/path'}

mock_client_handshake_json = {"app-name": JM_APP_NAME,
 "directory": False,
 "location-string": "028984b787834f93dbac6b9902368cdc2da34c563cb5626a484109f35aac32e84e@dummyhost:9735",
 "proto-ver": JM_VERSION,
 "features": {},
 "nick": nick2
}

def get_mock_msg(num, msg, peerid=None, nick=None):
    hextype = "%0.4x" % num
    msgval = b""
    if nick:
        msgval = nick.encode("utf-8")
    msgval += msg
    msgval = bintohex(msgval)
    if not peerid:
        # this is the case for local control messages
        peerid = "00"
    return {"peer_id": peerid, "payload": hextype + msgval}

mock_control_message1 = get_mock_msg(789, b";028984b787834f93dbac6b9902368cdc2da34c563cb5626a484109f35aac32e84e",
                                     "028984b787834f93dbac6b9902368cdc2da34c563cb5626a484109f35aac32e84e", nick2)
mock_control_connected_message = get_mock_msg(785, b"028984b787834f93dbac6b9902368cdc2da34c563cb5626a484109f35aac32e84e@dummyhost:9735")
mock_receiver_pubmsg = get_mock_msg(687, b"!PUBLIC!orderbook", "028984b787834f93dbac6b9902368cdc2da34c563cb5626a484109f35aac32e84e", nick2)
mock_client_handshake_message = get_mock_msg(793, json.dumps(mock_client_handshake_json).encode("utf-8"),
                                             "028984b787834f93dbac6b9902368cdc2da34c563cb5626a484109f35aac32e84e")