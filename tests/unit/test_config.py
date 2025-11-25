"""Tests for the config module."""

import os
from unittest.mock import mock_open, patch

from aws_mcp_server.config import (
    check_security_warnings,
    is_running_in_docker,
)


def test_is_running_in_docker_dockerenv_exists():
    """Test Docker detection via .dockerenv file."""
    with patch("pathlib.Path.exists", return_value=True):
        assert is_running_in_docker() is True


def test_is_running_in_docker_cgroup_docker():
    """Test Docker detection via cgroup file containing 'docker'."""
    with patch("pathlib.Path.exists", return_value=False):
        with patch("builtins.open", mock_open(read_data="12:memory:/docker/abc123")):
            assert is_running_in_docker() is True


def test_is_running_in_docker_cgroup_containerd():
    """Test Docker detection via cgroup file containing 'containerd'."""
    with patch("pathlib.Path.exists", return_value=False):
        with patch(
            "builtins.open", mock_open(read_data="12:memory:/containerd/abc123")
        ):
            assert is_running_in_docker() is True


def test_is_running_in_docker_container_env_var():
    """Test Docker detection via container environment variable."""
    with patch("pathlib.Path.exists", return_value=False):
        with patch("builtins.open", side_effect=FileNotFoundError()):
            with patch.dict(os.environ, {"container": "docker"}):
                assert is_running_in_docker() is True


def test_is_running_in_docker_not_in_docker():
    """Test Docker detection when not running in Docker."""
    with patch("pathlib.Path.exists", return_value=False):
        with patch("builtins.open", side_effect=FileNotFoundError()):
            with patch.dict(os.environ, {}, clear=True):
                # Also need to make sure 'container' key doesn't exist
                env_copy = os.environ.copy()
                env_copy.pop("container", None)
                with patch.dict(os.environ, env_copy, clear=True):
                    assert is_running_in_docker() is False


def test_check_security_warnings_outside_docker_strict():
    """Test security warnings when running outside Docker in strict mode."""
    with patch("aws_mcp_server.config.is_running_in_docker", return_value=False):
        with patch("aws_mcp_server.config.SECURITY_MODE", "strict"):
            with patch("aws_mcp_server.config.logger.warning") as mock_warning:
                check_security_warnings()
                mock_warning.assert_called_once()
                assert "SECURITY WARNING" in mock_warning.call_args[0][0]
                assert "Docker" in mock_warning.call_args[0][0]


def test_check_security_warnings_permissive_mode():
    """Test security warnings in permissive mode."""
    with patch("aws_mcp_server.config.is_running_in_docker", return_value=True):
        with patch("aws_mcp_server.config.SECURITY_MODE", "permissive"):
            with patch("aws_mcp_server.config.logger.warning") as mock_warning:
                check_security_warnings()
                mock_warning.assert_called_once()
                assert "PERMISSIVE" in mock_warning.call_args[0][0]


def test_check_security_warnings_docker_strict_recommended():
    """Test security status message when running in Docker with strict mode."""
    with patch("aws_mcp_server.config.is_running_in_docker", return_value=True):
        with patch("aws_mcp_server.config.SECURITY_MODE", "strict"):
            with patch("aws_mcp_server.config.logger.info") as mock_info:
                check_security_warnings()
                mock_info.assert_called_once()
                assert "recommended configuration" in mock_info.call_args[0][0]
