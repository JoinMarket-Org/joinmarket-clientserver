from unittest.mock import Mock, patch

import pytest

from jmdaemon.onionmc import OnionMessageChannel


@pytest.fixture
def configdata():
    return {
        "btcnet": "mainnet",
        "tor_control_host": "127.0.0.1",
        "tor_control_port": 9051,
        "onion_serving_host": "127.0.0.1",
        "serving": False,
        "socks5_host": "127.0.0.1",
        "socks5_port": 9050,
        "directory_nodes": "",
        "passive": False,
    }


class TestOnionMessageChannelListener:
    def test_start_listener_creates_tcp_endpoint(self, configdata):
        with (
            patch("jmdaemon.onionmc.reactor") as mock_reactor,
            patch("jmdaemon.onionmc.serverFromString") as mock_server_from_string,
        ):
            mock_deferred = Mock()
            mock_endpoint = Mock()
            mock_endpoint.listen.return_value = mock_deferred
            mock_server_from_string.return_value = mock_endpoint

            mc = OnionMessageChannel(configdata)
            mc.onion_serving_host = "127.0.0.1"
            mc.onion_serving_port = 8080
            mc.proto_factory = Mock()
            mc.on_welcome = Mock()
            mc.setup_error_callback = Mock()

            mc._start_listener()

            expected_serverstring = "tcp:8080:interface=127.0.0.1"
            mock_server_from_string.assert_called_once_with(
                mock_reactor, expected_serverstring
            )

            mock_endpoint.listen.assert_called_once_with(mc.proto_factory)

            mock_deferred.addCallback.assert_called_once_with(mc.on_welcome)
            mock_deferred.addErrback.assert_called_once()

            errback_callback = mock_deferred.addErrback.call_args[0][0]
            test_failure = Exception("Test error")
            errback_callback(test_failure)

            mc.setup_error_callback.assert_called_once_with("Listen failed: Test error")

    @pytest.mark.parametrize(
        "host,port",
        [
            ("192.168.1.1", 9000),
            ("localhost", 1234),
            ("0.0.0.0", 80),
        ],
    )
    def test_start_listener_different_ports_and_hosts(self, configdata, host, port):
        with (
            patch("jmdaemon.onionmc.reactor") as mock_reactor,
            patch("jmdaemon.onionmc.serverFromString") as mock_server_from_string,
        ):
            mock_endpoint = Mock()
            mock_server_from_string.return_value = mock_endpoint

            configdata["onion_serving_host"] = host
            configdata["onion_serving_port"] = port

            mc = OnionMessageChannel(configdata)
            mc.onion_serving_host = host
            mc.onion_serving_port = port
            mc.proto_factory = Mock()
            mc.on_welcome = Mock()
            mc.setup_error_callback = Mock()

            mc._start_listener()

            expected_serverstring = f"tcp:{port}:interface={host}"
            mock_server_from_string.assert_called_once_with(
                mock_reactor, expected_serverstring
            )
