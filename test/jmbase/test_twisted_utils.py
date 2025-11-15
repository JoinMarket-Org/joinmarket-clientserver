from unittest.mock import Mock, patch

import pytest

from jmbase.twisted_utils import JMHiddenService


def mock_hs(hidden_service_dir: str = "") -> JMHiddenService:
    return JMHiddenService(
        Mock(),
        Mock(),
        Mock(),
        Mock(),
        "127.0.0.1",
        9051,
        "127.0.0.1",
        8080,
        80,
        None,
        hidden_service_dir,
    )


class TestTorManagedHiddenService:
    @pytest.mark.parametrize(
        "hidden_service_dir,expect_managed,expect_connect",
        [
            ("tor-managed:/path/to/dir", True, False),
            ("/normal/path", False, True),
        ],
    )
    def test_hidden_service_dir_detection(
        self, hidden_service_dir, expect_managed, expect_connect
    ):
        with (
            patch.object(JMHiddenService, "start_tor_managed_onion") as mock_managed,
            patch("jmbase.twisted_utils.txtorcon.connect") as mock_connect,
        ):
            hs = mock_hs(hidden_service_dir)

            hs.start_tor()

            if expect_managed:
                mock_managed.assert_called_once()
                mock_connect.assert_not_called()
            else:
                mock_managed.assert_not_called()
                mock_connect.assert_called_once()

    def test_ephemeral_service_creation(self):
        with patch("jmbase.twisted_utils.txtorcon") as mock_txtorcon:
            mock_t = Mock()
            mock_t.create_onion_service.return_value = Mock()

            hs = mock_hs()
            hs.tor_connection = mock_t
            hs.virtual_port = 80
            hs.serving_host = "127.0.0.1"
            hs.serving_port = 8080

            hs.create_onion_ep(mock_t)

            mock_t.create_onion_service.assert_called_once_with(
                ports=["80 127.0.0.1:8080"], private_key=mock_txtorcon.DISCARD
            )
