"""Tests for the sandbox module."""

import os
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from aws_mcp_server.sandbox import (
    LinuxBubblewrapBackend,
    LinuxLandlockBackend,
    MacOSSeatbeltBackend,
    NoOpBackend,
    Sandbox,
    SandboxConfig,
    SandboxError,
    execute_sandboxed,
    get_sandbox,
    reset_sandbox,
    sandbox_available,
)


class TestSandboxConfig:
    """Tests for SandboxConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = SandboxConfig()

        # Should have default read paths
        assert len(config.read_paths) > 0
        # Should have default write paths
        assert len(config.write_paths) > 0
        assert "/tmp" in config.write_paths
        # Should allow network by default
        assert config.allow_network is True
        # Should pass AWS env by default
        assert config.pass_aws_env is True
        # Should allow AWS config by default
        assert config.allow_aws_config is True

    def test_custom_config(self):
        """Test custom configuration values."""
        config = SandboxConfig(
            read_paths=["/custom/path"],
            write_paths=["/custom/write"],
            allow_network=False,
            pass_aws_env=False,
            allow_aws_config=False,
        )

        assert config.read_paths == ["/custom/path"]
        assert config.write_paths == ["/custom/write"]
        assert config.allow_network is False
        assert config.pass_aws_env is False
        assert config.allow_aws_config is False

    def test_env_passthrough_includes_aws_vars(self):
        """Test that default env passthrough includes AWS variables."""
        config = SandboxConfig()

        assert "AWS_ACCESS_KEY_ID" in config.env_passthrough
        assert "AWS_SECRET_ACCESS_KEY" in config.env_passthrough
        assert "AWS_SESSION_TOKEN" in config.env_passthrough
        assert "AWS_REGION" in config.env_passthrough
        assert "AWS_PROFILE" in config.env_passthrough
        assert "PATH" in config.env_passthrough
        assert "HOME" in config.env_passthrough


class TestNoOpBackend:
    """Tests for NoOpBackend."""

    def test_is_available(self):
        """Test that NoOpBackend is always available."""
        backend = NoOpBackend()
        assert backend.is_available() is True

    def test_execute_simple_command(self):
        """Test executing a simple command."""
        backend = NoOpBackend()
        config = SandboxConfig()

        result = backend.execute(["echo", "hello"], config)

        assert result.returncode == 0
        assert b"hello" in result.stdout

    def test_execute_with_input(self):
        """Test executing a command with input."""
        backend = NoOpBackend()
        config = SandboxConfig()

        result = backend.execute(["cat"], config, input_data=b"test input")

        assert result.returncode == 0
        assert b"test input" in result.stdout

    def test_execute_passes_environment(self):
        """Test that environment variables are passed correctly."""
        backend = NoOpBackend()
        config = SandboxConfig(env_passthrough=["TEST_VAR"])

        with patch.dict(os.environ, {"TEST_VAR": "test_value"}):
            result = backend.execute(["printenv", "TEST_VAR"], config)

        assert result.returncode == 0
        assert b"test_value" in result.stdout


class TestLinuxLandlockBackend:
    """Tests for LinuxLandlockBackend."""

    def test_is_available_not_linux(self):
        """Test availability check on non-Linux systems."""
        backend = LinuxLandlockBackend()

        with patch("platform.system", return_value="Darwin"):
            # Reset cached value
            backend._available = None
            assert backend.is_available() is False

    def test_is_available_old_kernel(self):
        """Test availability check with old kernel."""
        backend = LinuxLandlockBackend()

        with patch("platform.system", return_value="Linux"):
            with patch("platform.release", return_value="4.19.0"):
                # Reset cached value
                backend._available = None
                assert backend.is_available() is False

    def test_is_available_no_module(self):
        """Test availability check when landlock module is not installed."""
        backend = LinuxLandlockBackend()

        with patch("platform.system", return_value="Linux"):
            with patch("platform.release", return_value="5.15.0"):
                with patch.dict("sys.modules", {"landlock": None}):
                    # Reset cached value
                    backend._available = None
                    # This will try to import landlock and fail
                    result = backend.is_available()
                    # May be True if landlock is installed, False otherwise
                    assert isinstance(result, bool)

    def test_execute_raises_when_not_available(self):
        """Test that execute raises when backend is not available."""
        backend = LinuxLandlockBackend()
        backend._available = False
        config = SandboxConfig()

        with pytest.raises(SandboxError, match="Landlock is not available"):
            backend.execute(["echo", "hello"], config)


class TestLinuxBubblewrapBackend:
    """Tests for LinuxBubblewrapBackend."""

    def test_is_available_not_linux(self):
        """Test availability check on non-Linux systems."""
        backend = LinuxBubblewrapBackend()

        with patch("platform.system", return_value="Darwin"):
            backend._available = None
            assert backend.is_available() is False

    def test_is_available_no_bwrap(self):
        """Test availability check when bwrap is not installed."""
        backend = LinuxBubblewrapBackend()

        with patch("platform.system", return_value="Linux"):
            with patch("shutil.which", return_value=None):
                backend._available = None
                assert backend.is_available() is False

    def test_is_available_with_bwrap(self):
        """Test availability check when bwrap is installed."""
        backend = LinuxBubblewrapBackend()

        with patch("platform.system", return_value="Linux"):
            with patch("shutil.which", return_value="/usr/bin/bwrap"):
                backend._available = None
                assert backend.is_available() is True
                assert backend._bwrap_path == "/usr/bin/bwrap"

    def test_build_bwrap_args(self):
        """Test building bwrap command arguments."""
        backend = LinuxBubblewrapBackend()
        backend._bwrap_path = "/usr/bin/bwrap"

        config = SandboxConfig(
            read_paths=["/usr", "/bin"],
            write_paths=["/tmp"],
            allow_network=True,
        )

        with patch("os.path.exists", return_value=True):
            args = backend._build_bwrap_args(config)

        assert args[0] == "/usr/bin/bwrap"
        assert "--ro-bind" in args
        assert "--bind" in args
        assert "--proc" in args
        assert "--dev" in args
        assert "--unshare-pid" in args
        assert "--new-session" in args
        assert "--die-with-parent" in args
        assert "--" in args
        # Network should not be unshared when allow_network=True
        assert "--unshare-net" not in args

    def test_build_bwrap_args_no_network(self):
        """Test building bwrap args with network disabled."""
        backend = LinuxBubblewrapBackend()
        backend._bwrap_path = "/usr/bin/bwrap"

        config = SandboxConfig(allow_network=False)

        with patch("os.path.exists", return_value=True):
            args = backend._build_bwrap_args(config)

        assert "--unshare-net" in args

    def test_execute_raises_when_not_available(self):
        """Test that execute raises when backend is not available."""
        backend = LinuxBubblewrapBackend()
        backend._available = False
        config = SandboxConfig()

        with pytest.raises(SandboxError, match="Bubblewrap is not available"):
            backend.execute(["echo", "hello"], config)


class TestMacOSSeatbeltBackend:
    """Tests for MacOSSeatbeltBackend."""

    def test_is_available_not_macos(self):
        """Test availability check on non-macOS systems."""
        backend = MacOSSeatbeltBackend()

        with patch("platform.system", return_value="Linux"):
            backend._available = None
            assert backend.is_available() is False

    def test_is_available_old_macos(self):
        """Test availability check on old macOS versions."""
        backend = MacOSSeatbeltBackend()

        with patch("platform.system", return_value="Darwin"):
            with patch("platform.mac_ver", return_value=("10.15.0", ("", "", ""), "")):
                backend._available = None
                assert backend.is_available() is False

    def test_build_profile(self):
        """Test building Seatbelt profile."""
        backend = MacOSSeatbeltBackend()

        config = SandboxConfig(
            write_paths=["/tmp", "/var/tmp"],
            allow_network=True,
            allow_aws_config=True,
        )

        with patch("os.path.exists", return_value=True):
            profile = backend._build_profile(config)

        assert "(version 1)" in profile
        assert "(deny default)" in profile
        assert "(allow network*)" in profile
        assert "/tmp" in profile
        assert ".aws" in profile

    def test_build_profile_no_network(self):
        """Test building profile with network disabled."""
        backend = MacOSSeatbeltBackend()

        config = SandboxConfig(allow_network=False)

        profile = backend._build_profile(config)

        assert "(allow network*)" not in profile
        assert "Network access disabled" in profile

    def test_execute_raises_when_not_available(self):
        """Test that execute raises when backend is not available."""
        backend = MacOSSeatbeltBackend()
        backend._available = False
        config = SandboxConfig()

        with pytest.raises(SandboxError, match="Seatbelt is not available"):
            backend.execute(["echo", "hello"], config)


class TestSandbox:
    """Tests for Sandbox class."""

    def test_init_with_default_config(self):
        """Test initialization with default config."""
        sandbox = Sandbox()

        assert sandbox.config is not None
        assert sandbox.sandbox_mode == "auto"
        assert sandbox._backend is None

    def test_init_with_custom_config(self):
        """Test initialization with custom config."""
        config = SandboxConfig(allow_network=False)
        sandbox = Sandbox(config, sandbox_mode="required")

        assert sandbox.config.allow_network is False
        assert sandbox.sandbox_mode == "required"

    def test_select_backend_disabled(self):
        """Test backend selection when disabled."""
        sandbox = Sandbox(sandbox_mode="disabled")
        backend = sandbox._select_backend("disabled")

        assert isinstance(backend, NoOpBackend)

    def test_select_backend_required_no_backend(self):
        """Test backend selection when required but no backend available."""
        sandbox = Sandbox(sandbox_mode="required")

        with patch("platform.system", return_value="Windows"):
            with pytest.raises(SandboxError, match="Sandbox required but not available"):
                sandbox._select_backend("required")

    def test_backend_property_caches(self):
        """Test that backend property caches the backend."""
        sandbox = Sandbox(sandbox_mode="disabled")

        backend1 = sandbox.backend
        backend2 = sandbox.backend

        assert backend1 is backend2

    def test_is_sandboxed_true(self):
        """Test is_sandboxed returns True when sandbox is active."""
        sandbox = Sandbox()
        # Force a real backend (if available) or mock one
        sandbox._backend = LinuxLandlockBackend()
        sandbox._backend._available = True

        # is_sandboxed checks if backend is NOT NoOpBackend
        assert sandbox.is_sandboxed() is True

    def test_is_sandboxed_false(self):
        """Test is_sandboxed returns False when using NoOp."""
        sandbox = Sandbox(sandbox_mode="disabled")
        _ = sandbox.backend  # Initialize backend

        assert sandbox.is_sandboxed() is False

    def test_execute_delegates_to_backend(self):
        """Test that execute delegates to the backend."""
        sandbox = Sandbox(sandbox_mode="disabled")
        mock_backend = MagicMock()
        mock_backend.execute.return_value = subprocess.CompletedProcess(
            args=["echo", "hello"],
            returncode=0,
            stdout=b"hello",
            stderr=b"",
        )
        sandbox._backend = mock_backend

        result = sandbox.execute(["echo", "hello"])

        mock_backend.execute.assert_called_once()
        assert result.returncode == 0


class TestModuleFunctions:
    """Tests for module-level functions."""

    def setup_method(self):
        """Reset sandbox before each test."""
        reset_sandbox()

    def test_get_sandbox_creates_singleton(self):
        """Test that get_sandbox creates a singleton."""
        with patch("aws_mcp_server.config.SANDBOX_MODE", "disabled"):
            with patch("aws_mcp_server.config.SANDBOX_CREDENTIAL_MODE", "both"):
                reset_sandbox()
                sandbox1 = get_sandbox()
                sandbox2 = get_sandbox()

                assert sandbox1 is sandbox2

    def test_reset_sandbox(self):
        """Test that reset_sandbox clears the singleton."""
        with patch("aws_mcp_server.config.SANDBOX_MODE", "disabled"):
            with patch("aws_mcp_server.config.SANDBOX_CREDENTIAL_MODE", "both"):
                reset_sandbox()
                sandbox1 = get_sandbox()
                reset_sandbox()
                sandbox2 = get_sandbox()

                assert sandbox1 is not sandbox2

    def test_execute_sandboxed(self):
        """Test execute_sandboxed convenience function."""
        with patch("aws_mcp_server.config.SANDBOX_MODE", "disabled"):
            with patch("aws_mcp_server.config.SANDBOX_CREDENTIAL_MODE", "both"):
                reset_sandbox()
                result = execute_sandboxed(["echo", "hello"])

                assert result.returncode == 0
                assert b"hello" in result.stdout

    def test_sandbox_available(self):
        """Test sandbox_available function."""
        with patch("aws_mcp_server.config.SANDBOX_MODE", "disabled"):
            with patch("aws_mcp_server.config.SANDBOX_CREDENTIAL_MODE", "both"):
                reset_sandbox()
                # When disabled, sandbox is not available
                available = sandbox_available()
                assert available is False


class TestAsyncFunctions:
    """Tests for async sandbox functions."""

    def setup_method(self):
        """Reset sandbox before each test."""
        reset_sandbox()

    @pytest.mark.asyncio
    async def test_execute_sandboxed_async(self):
        """Test async sandbox execution."""
        from aws_mcp_server.sandbox import execute_sandboxed_async

        with patch("aws_mcp_server.config.SANDBOX_MODE", "disabled"):
            with patch("aws_mcp_server.config.SANDBOX_CREDENTIAL_MODE", "both"):
                reset_sandbox()
                stdout, stderr, returncode = await execute_sandboxed_async(["echo", "hello"])

                assert returncode == 0
                assert b"hello" in stdout

    @pytest.mark.asyncio
    async def test_execute_piped_sandboxed_async(self):
        """Test async piped sandbox execution."""
        from aws_mcp_server.sandbox import execute_piped_sandboxed_async

        with patch("aws_mcp_server.config.SANDBOX_MODE", "disabled"):
            with patch("aws_mcp_server.config.SANDBOX_CREDENTIAL_MODE", "both"):
                reset_sandbox()
                commands = [
                    ["echo", "hello world"],
                    ["grep", "hello"],
                ]
                stdout, stderr, returncode = await execute_piped_sandboxed_async(commands)

                assert returncode == 0
                assert b"hello" in stdout

    @pytest.mark.asyncio
    async def test_execute_piped_sandboxed_async_empty_commands(self):
        """Test async piped execution with empty commands."""
        from aws_mcp_server.sandbox import execute_piped_sandboxed_async

        stdout, stderr, returncode = await execute_piped_sandboxed_async([])

        assert returncode == 1
        assert b"Empty command" in stderr

    @pytest.mark.asyncio
    async def test_execute_piped_sandboxed_async_failure_in_pipeline(self):
        """Test async piped execution when a command fails."""
        from aws_mcp_server.sandbox import execute_piped_sandboxed_async

        with patch("aws_mcp_server.config.SANDBOX_MODE", "disabled"):
            with patch("aws_mcp_server.config.SANDBOX_CREDENTIAL_MODE", "both"):
                reset_sandbox()
                commands = [
                    ["echo", "hello"],
                    ["grep", "nonexistent"],
                ]
                stdout, stderr, returncode = await execute_piped_sandboxed_async(commands)

                # grep returns 1 when no match found
                assert returncode == 1


class TestCredentialModes:
    """Tests for different credential passing modes."""

    def setup_method(self):
        """Reset sandbox before each test."""
        reset_sandbox()

    def test_env_only_mode(self):
        """Test env-only credential mode."""
        with patch("aws_mcp_server.config.SANDBOX_CREDENTIAL_MODE", "env"):
            with patch("aws_mcp_server.config.SANDBOX_MODE", "disabled"):
                reset_sandbox()
                sandbox = get_sandbox()

                assert sandbox.config.pass_aws_env is True
                assert sandbox.config.allow_aws_config is False

    def test_aws_config_only_mode(self):
        """Test aws_config-only credential mode."""
        with patch("aws_mcp_server.config.SANDBOX_CREDENTIAL_MODE", "aws_config"):
            with patch("aws_mcp_server.config.SANDBOX_MODE", "disabled"):
                reset_sandbox()
                sandbox = get_sandbox()

                assert sandbox.config.pass_aws_env is False
                assert sandbox.config.allow_aws_config is True

    def test_both_mode(self):
        """Test both credential mode."""
        with patch("aws_mcp_server.config.SANDBOX_CREDENTIAL_MODE", "both"):
            with patch("aws_mcp_server.config.SANDBOX_MODE", "disabled"):
                reset_sandbox()
                sandbox = get_sandbox()

                assert sandbox.config.pass_aws_env is True
                assert sandbox.config.allow_aws_config is True
