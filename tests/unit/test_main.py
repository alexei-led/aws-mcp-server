"""Tests for the main entry point of the AWS MCP Server."""

from unittest.mock import MagicMock, patch

from aws_mcp_server.__main__ import handle_interrupt


def test_handle_interrupt():
    with patch("os._exit") as mock_exit:
        handle_interrupt(MagicMock(), MagicMock())
        mock_exit.assert_called_once_with(0)
