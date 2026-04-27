#! /usr/bin/env python
"""Tests for onion message channel DoS protections:
- Per-connection message rate limiting in OnionLineProtocol.
- Handshake requirement before processing JM messages.
"""

import json
import time
from unittest.mock import MagicMock

from twisted.internet.address import IPv4Address

from jmdaemon.onionmc import (
    OnionLineProtocol,
    OnionCustomMessage,
    OnionMessageChannel,
    JM_MESSAGE_TYPES,
    CONTROL_MESSAGE_TYPES,
    PEER_STATUS_CONNECTED,
    PEER_STATUS_HANDSHAKED,
    ONION_MSG_RATE_LIMIT,
    ONION_MSG_RATE_INTERVAL,
)


class FakeTransport:
    """Minimal transport mock for testing OnionLineProtocol."""

    def __init__(self):
        self.disconnected = False
        self._peer = IPv4Address("TCP", "127.0.0.1", 12345)

    def getPeer(self):
        return self._peer

    def loseConnection(self):
        self.disconnected = True

    def write(self, data):
        pass


class FakeFactory:
    """Minimal factory mock for testing OnionLineProtocol."""

    def __init__(self):
        self.received_messages = []
        self.connections = []
        self.disconnections = []

    def register_connection(self, proto):
        self.connections.append(proto)

    def register_disconnection(self, proto):
        self.disconnections.append(proto)

    def receive_message(self, msg, proto):
        self.received_messages.append((msg, proto))


def make_valid_line(text="hello", msgtype=685):
    """Create a valid JSON-encoded message line."""
    return json.dumps({"type": msgtype, "line": text}).encode("utf-8")


def create_protocol():
    """Create an OnionLineProtocol with mocked transport and factory."""
    proto = OnionLineProtocol()
    proto.factory = FakeFactory()
    proto.transport = FakeTransport()
    # Initialize rate limiting state as connectionMade would
    proto.msg_count = 0
    proto.msg_count_reset_time = time.monotonic()
    # Needed by LineReceiver
    proto.delimiter = b"\r\n"
    return proto


class TestOnionLineProtocolRateLimiting:
    """Tests for per-connection rate limiting in OnionLineProtocol."""

    def test_messages_under_limit_are_processed(self):
        proto = create_protocol()
        line = make_valid_line()
        for _ in range(ONION_MSG_RATE_LIMIT):
            proto.lineReceived(line)
        assert not proto.transport.disconnected
        assert len(proto.factory.received_messages) == ONION_MSG_RATE_LIMIT

    def test_messages_over_limit_trigger_disconnect(self):
        proto = create_protocol()
        line = make_valid_line()
        for _ in range(ONION_MSG_RATE_LIMIT + 5):
            proto.lineReceived(line)
        assert proto.transport.disconnected
        # Only ONION_MSG_RATE_LIMIT messages should have been processed
        assert len(proto.factory.received_messages) == ONION_MSG_RATE_LIMIT

    def test_rate_limit_resets_after_interval(self):
        proto = create_protocol()
        line = make_valid_line()
        # Send up to the limit
        for _ in range(ONION_MSG_RATE_LIMIT):
            proto.lineReceived(line)
        assert not proto.transport.disconnected
        assert len(proto.factory.received_messages) == ONION_MSG_RATE_LIMIT

        # Simulate time passing beyond the rate interval
        proto.msg_count_reset_time = (
            time.monotonic() - ONION_MSG_RATE_INTERVAL - 1
        )
        # Should be able to send more messages now
        for _ in range(ONION_MSG_RATE_LIMIT):
            proto.lineReceived(line)
        assert not proto.transport.disconnected
        assert len(proto.factory.received_messages) == 2 * ONION_MSG_RATE_LIMIT

    def test_invalid_message_still_disconnects(self):
        proto = create_protocol()
        proto.lineReceived(b"not valid json")
        assert proto.transport.disconnected

    def test_rate_limit_counter_initialized_on_connection(self):
        proto = OnionLineProtocol()
        proto.factory = FakeFactory()
        proto.transport = FakeTransport()
        proto.delimiter = b"\r\n"
        # Simulate connectionMade
        proto.connectionMade()
        assert proto.msg_count == 0
        assert proto.msg_count_reset_time > 0

    def test_first_message_after_limit_triggers_disconnect(self):
        """Verify that the very first message exceeding the limit
        causes disconnection, not the second."""
        proto = create_protocol()
        line = make_valid_line()
        # Send exactly up to the limit
        for _ in range(ONION_MSG_RATE_LIMIT):
            proto.lineReceived(line)
        assert not proto.transport.disconnected
        # The next message should trigger the disconnect
        proto.lineReceived(line)
        assert proto.transport.disconnected
        # No additional messages should have been processed
        assert len(proto.factory.received_messages) == ONION_MSG_RATE_LIMIT


class TestReceiveMsgHandshakeCheck:
    """Tests that JM messages from non-handshaked peers are rejected."""

    def _make_mock_mc(self):
        """Create a minimal mock of OnionMessageChannel for testing
        receive_msg logic."""
        mc = MagicMock(spec=OnionMessageChannel)
        mc.self_as_peer = MagicMock()
        mc.self_as_peer.directory = False
        mc.nick = "testnick"
        mc.active_directories = {}
        # process_control_message returns False for JM messages
        # (meaning: "this was not a control message, keep processing")
        mc.process_control_message = MagicMock(return_value=False)
        # We want to call the real receive_msg
        mc.receive_msg = OnionMessageChannel.receive_msg.__get__(mc)
        return mc

    def test_jm_message_rejected_from_connected_but_not_handshaked_peer(self):
        mc = self._make_mock_mc()
        peer = MagicMock()
        peer.directory = False
        peer.status.return_value = PEER_STATUS_CONNECTED
        mc.get_peer_by_id = MagicMock(return_value=peer)

        # Construct a pubmsg-type JM message
        msg = OnionCustomMessage("somenick!PUBLIC!orderbook",
                                 JM_MESSAGE_TYPES["pubmsg"])
        mc.receive_msg(msg, "127.0.0.1:9999")

        # on_pubmsg should NOT have been called
        mc.on_pubmsg.assert_not_called()

    def test_jm_message_accepted_from_handshaked_peer(self):
        mc = self._make_mock_mc()
        peer = MagicMock()
        peer.directory = False
        peer.status.return_value = PEER_STATUS_HANDSHAKED
        peer.nick = "somenick"
        mc.get_peer_by_id = MagicMock(return_value=peer)

        msg = OnionCustomMessage("somenick!PUBLIC!orderbook",
                                 JM_MESSAGE_TYPES["pubmsg"])
        mc.receive_msg(msg, "127.0.0.1:9999")

        # on_pubmsg should have been called since peer is handshaked
        mc.on_pubmsg.assert_called_once()

    def test_jm_message_accepted_from_directory_peer_regardless_of_status(self):
        mc = self._make_mock_mc()
        peer = MagicMock()
        peer.directory = True
        peer.status.return_value = PEER_STATUS_CONNECTED
        mc.get_peer_by_id = MagicMock(return_value=peer)

        msg = OnionCustomMessage("somenick!PUBLIC!orderbook",
                                 JM_MESSAGE_TYPES["pubmsg"])
        mc.receive_msg(msg, "127.0.0.1:9999")

        # Directory peers should bypass the handshake check
        mc.on_pubmsg.assert_called_once()

    def test_control_messages_still_processed_without_handshake(self):
        mc = self._make_mock_mc()
        # For this test, process_control_message should return True
        # (meaning it handled the message as a control message)
        mc.process_control_message = MagicMock(return_value=True)
        peer = MagicMock()
        peer.directory = False
        peer.status.return_value = PEER_STATUS_CONNECTED
        mc.get_peer_by_id = MagicMock(return_value=peer)

        # Send a handshake control message (should be processed)
        handshake_json = json.dumps({
            "app-name": "joinmarket",
            "directory": False,
            "proto-ver": 5,
            "features": {},
            "location-string": "test.onion:5222",
            "nick": "testnick2",
            "network": "mainnet",
        })
        msg = OnionCustomMessage(handshake_json,
                                 CONTROL_MESSAGE_TYPES["handshake"])
        mc.receive_msg(msg, "127.0.0.1:9999")

        # process_control_message should have been called
        mc.process_control_message.assert_called()
        # on_pubmsg should NOT have been called (control message handled it)
        mc.on_pubmsg.assert_not_called()

    def test_privmsg_rejected_from_non_handshaked_peer(self):
        mc = self._make_mock_mc()
        peer = MagicMock()
        peer.directory = False
        peer.status.return_value = PEER_STATUS_CONNECTED
        mc.get_peer_by_id = MagicMock(return_value=peer)

        # Construct a privmsg-type JM message
        msg = OnionCustomMessage("somenick!testnick!fill 0 100000",
                                 JM_MESSAGE_TYPES["privmsg"])
        mc.receive_msg(msg, "127.0.0.1:9999")

        # on_privmsg should NOT have been called
        mc.on_privmsg.assert_not_called()
