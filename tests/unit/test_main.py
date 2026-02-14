"""Tests for the main entry point of the AWS MCP Server."""

import select
import threading
from unittest.mock import MagicMock, Mock

from aws_mcp_server.__main__ import handle_interrupt, monitor_stdio_disconnect


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
