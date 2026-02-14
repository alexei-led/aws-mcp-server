"""Tests for the main entry point of the AWS MCP Server."""

import select
import threading
import warnings
from unittest.mock import MagicMock, Mock, patch

import pytest

from aws_mcp_server.__main__ import handle_interrupt, main, monitor_stdio_disconnect


def test_handle_interrupt():
    try:
        handle_interrupt(MagicMock(), MagicMock())
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("Expected SystemExit to be raised")


def test_monitor_stdio_disconnect_triggers_shutdown_on_pollhup():
    mock_poller = Mock()
    mock_poller.poll.return_value = [(0, select.POLLHUP)]

    shutdown_callback = Mock()
    stop_event = threading.Event()

    monitor_stdio_disconnect(
        stop_event=stop_event,
        shutdown_callback=shutdown_callback,
        poller_factory=Mock(return_value=mock_poller),
    )

    shutdown_callback.assert_called_once_with()


@pytest.mark.parametrize(
    "transport",
    ["stdio", "sse", "streamable-http"],
)
def test_valid_transport_accepted(transport):
    with (
        patch("aws_mcp_server.__main__.run_startup_checks"),
        patch("aws_mcp_server.config.TRANSPORT", transport),
        patch("aws_mcp_server.config.is_docker_environment", return_value=False),
        patch("aws_mcp_server.__main__.mcp") as mock_mcp,
        patch("sys.exit") as mock_exit,
    ):
        mock_mcp.settings = MagicMock()
        main()
        mock_exit.assert_not_called()
        mock_mcp.run.assert_called_once_with(transport=transport)


def test_invalid_transport_exits():
    with (
        patch("aws_mcp_server.__main__.run_startup_checks"),
        patch("aws_mcp_server.config.TRANSPORT", "invalid"),
        patch("aws_mcp_server.__main__.mcp"),
        patch("sys.exit") as mock_exit,
    ):
        main()
        mock_exit.assert_called_once_with(1)


def test_sse_transport_emits_deprecation_warning():
    with (
        patch("aws_mcp_server.__main__.run_startup_checks"),
        patch("aws_mcp_server.config.TRANSPORT", "sse"),
        patch("aws_mcp_server.config.is_docker_environment", return_value=False),
        patch("aws_mcp_server.__main__.mcp") as mock_mcp,
    ):
        mock_mcp.settings = MagicMock()
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            main()
            deprecation_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecation_warnings) == 1
            assert "deprecated" in str(deprecation_warnings[0].message).lower()
            assert "streamable-http" in str(deprecation_warnings[0].message)


def test_streamable_http_does_not_emit_deprecation_warning():
    with (
        patch("aws_mcp_server.__main__.run_startup_checks"),
        patch("aws_mcp_server.config.TRANSPORT", "streamable-http"),
        patch("aws_mcp_server.config.is_docker_environment", return_value=False),
        patch("aws_mcp_server.__main__.mcp") as mock_mcp,
    ):
        mock_mcp.settings = MagicMock()
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            main()
            deprecation_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecation_warnings) == 0


@pytest.mark.parametrize(
    "transport",
    ["sse", "streamable-http"],
)
def test_http_transport_sets_host_in_docker(transport):
    with (
        patch("aws_mcp_server.__main__.run_startup_checks"),
        patch("aws_mcp_server.config.TRANSPORT", transport),
        patch("aws_mcp_server.config.is_docker_environment", return_value=True),
        patch("aws_mcp_server.__main__.mcp") as mock_mcp,
    ):
        mock_mcp.settings = MagicMock()
        main()
        assert mock_mcp.settings.host == "0.0.0.0"


@pytest.mark.parametrize(
    "transport",
    ["sse", "streamable-http"],
)
def test_http_transport_sets_localhost_outside_docker(transport):
    with (
        patch("aws_mcp_server.__main__.run_startup_checks"),
        patch("aws_mcp_server.config.TRANSPORT", transport),
        patch("aws_mcp_server.config.is_docker_environment", return_value=False),
        patch("aws_mcp_server.__main__.mcp") as mock_mcp,
    ):
        mock_mcp.settings = MagicMock()
        main()
        assert mock_mcp.settings.host == "127.0.0.1"
