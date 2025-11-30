"""Tests for the sandbox module."""

import asyncio
import os
import subprocess
import sys
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
    get_aws_credential_paths,
    get_sandbox,
    reset_sandbox,
    sandbox_available,
)

# Platform detection helpers
IS_LINUX = sys.platform.startswith("linux")
IS_MACOS = sys.platform == "darwin"


class TestSandboxConfig:
    """Tests for SandboxConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = SandboxConfig()

        assert len(config.read_paths) > 0
        assert len(config.write_paths) > 0
        assert "/tmp" in config.write_paths
        assert config.allow_network is True
        assert config.pass_aws_env is True
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

    def test_execute_with_timeout(self):
        """Test that timeout is respected."""
        backend = NoOpBackend()
        config = SandboxConfig()

        with pytest.raises(subprocess.TimeoutExpired):
            backend.execute(["sleep", "10"], config, timeout=0.1)


class TestLinuxLandlockBackend:
    """Tests for LinuxLandlockBackend."""

    def test_is_available_not_linux(self):
        """Test availability check on non-Linux systems."""
        backend = LinuxLandlockBackend()

        with patch("platform.system", return_value="Darwin"):
            backend._available = None
            assert backend.is_available() is False

    def test_is_available_old_kernel(self):
        """Test availability check with old kernel."""
        backend = LinuxLandlockBackend()

        with patch("platform.system", return_value="Linux"):
            with patch("platform.release", return_value="4.19.0"):
                backend._available = None
                assert backend.is_available() is False

    def test_is_available_no_module(self):
        """Test availability check when landlock module is not installed."""
        backend = LinuxLandlockBackend()

        with patch("platform.system", return_value="Linux"):
            with patch("platform.release", return_value="5.15.0"):
                with patch.dict("sys.modules", {"landlock": None}):
                    backend._available = None
                    result = backend.is_available()
                    assert isinstance(result, bool)

    def test_is_available_kernel_parse_error(self):
        """Test availability check with unparseable kernel version."""
        backend = LinuxLandlockBackend()

        with patch("platform.system", return_value="Linux"):
            with patch("platform.release", return_value="invalid-version"):
                backend._available = None
                assert backend.is_available() is False

    def test_execute_raises_when_not_available(self):
        """Test that execute raises when backend is not available."""
        backend = LinuxLandlockBackend()
        backend._available = False
        config = SandboxConfig()

        with pytest.raises(SandboxError, match="Landlock is not available"):
            backend.execute(["echo", "hello"], config)

    def test_execute_accepts_sandbox_mode_parameter(self):
        """Test that execute accepts sandbox_mode parameter."""
        backend = LinuxLandlockBackend()
        backend._available = False
        config = SandboxConfig()

        with pytest.raises(SandboxError):
            backend.execute(["echo", "hello"], config, sandbox_mode="auto")

        with pytest.raises(SandboxError):
            backend.execute(["echo", "hello"], config, sandbox_mode="required")

    @pytest.mark.skipif(not IS_LINUX, reason="Landlock only available on Linux")
    def test_execute_on_linux(self):
        """Test actual Landlock execution on Linux."""
        backend = LinuxLandlockBackend()
        if not backend.is_available():
            pytest.skip("Landlock not available on this Linux system")

        config = SandboxConfig()
        result = backend.execute(["echo", "sandboxed"], config)

        assert result.returncode == 0
        assert b"sandboxed" in result.stdout


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

    @pytest.mark.skipif(not IS_LINUX, reason="Bubblewrap only available on Linux")
    def test_execute_on_linux(self):
        """Test actual Bubblewrap execution on Linux."""
        backend = LinuxBubblewrapBackend()
        if not backend.is_available():
            pytest.skip("Bubblewrap not available on this Linux system")

        config = SandboxConfig()
        result = backend.execute(["echo", "sandboxed"], config)

        assert result.returncode == 0
        assert b"sandboxed" in result.stdout


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

    def test_is_available_version_parse_error(self):
        """Test availability check with unparseable macOS version."""
        backend = MacOSSeatbeltBackend()

        with patch("platform.system", return_value="Darwin"):
            with patch("platform.mac_ver", return_value=("invalid", ("", "", ""), "")):
                backend._available = None
                # Should not crash, may return True or False based on other checks
                result = backend.is_available()
                assert isinstance(result, bool)

    def test_build_profile(self):
        """Test building Seatbelt profile."""
        backend = MacOSSeatbeltBackend()

        config = SandboxConfig(
            write_paths=["/tmp", "/var/tmp"],
            allow_network=True,
            allow_aws_config=True,
        )

        with patch("os.path.exists", return_value=True):
            with patch(
                "aws_mcp_server.sandbox.get_aws_credential_paths",
                return_value=["/Users/test/.aws"],
            ):
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

    def test_build_profile_no_aws_config(self):
        """Test building profile with AWS config disabled."""
        backend = MacOSSeatbeltBackend()

        config = SandboxConfig(allow_aws_config=False)

        profile = backend._build_profile(config)

        assert "AWS config access disabled" in profile

    def test_execute_raises_when_not_available(self):
        """Test that execute raises when backend is not available."""
        backend = MacOSSeatbeltBackend()
        backend._available = False
        config = SandboxConfig()

        with pytest.raises(SandboxError, match="Seatbelt is not available"):
            backend.execute(["echo", "hello"], config)

    @pytest.mark.skipif(not IS_MACOS, reason="Seatbelt only available on macOS")
    def test_execute_on_macos(self):
        """Test actual Seatbelt execution on macOS."""
        backend = MacOSSeatbeltBackend()
        if not backend.is_available():
            pytest.skip("Seatbelt not available on this macOS version")

        config = SandboxConfig()
        result = backend.execute(["echo", "sandboxed"], config)

        assert result.returncode == 0
        assert b"sandboxed" in result.stdout


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

    @pytest.mark.skipif(not IS_LINUX, reason="Linux backend selection test")
    def test_select_backend_linux_auto(self):
        """Test auto backend selection on Linux."""
        sandbox = Sandbox(sandbox_mode="auto")

        with patch("platform.system", return_value="Linux"):
            backend = sandbox._select_backend("auto")
            # Should return either Landlock, Bubblewrap, or NoOp depending on availability
            assert isinstance(backend, (LinuxLandlockBackend, LinuxBubblewrapBackend, NoOpBackend))

    @pytest.mark.skipif(not IS_MACOS, reason="macOS backend selection test")
    def test_select_backend_macos_auto(self):
        """Test auto backend selection on macOS."""
        sandbox = Sandbox(sandbox_mode="auto")

        backend = sandbox._select_backend("auto")
        # Should return either Seatbelt or NoOp depending on availability
        assert isinstance(backend, (MacOSSeatbeltBackend, NoOpBackend))

    def test_select_backend_unsupported_platform(self):
        """Test backend selection on unsupported platform."""
        sandbox = Sandbox(sandbox_mode="auto")

        with patch("platform.system", return_value="FreeBSD"):
            backend = sandbox._select_backend("auto")
            assert isinstance(backend, NoOpBackend)

    def test_backend_property_caches(self):
        """Test that backend property caches the backend."""
        sandbox = Sandbox(sandbox_mode="disabled")

        backend1 = sandbox.backend
        backend2 = sandbox.backend

        assert backend1 is backend2

    def test_is_sandboxed_true(self):
        """Test is_sandboxed returns True when sandbox is active."""
        sandbox = Sandbox()
        sandbox._backend = LinuxLandlockBackend()
        sandbox._backend._available = True

        assert sandbox.is_sandboxed() is True

    def test_is_sandboxed_false(self):
        """Test is_sandboxed returns False when using NoOp."""
        sandbox = Sandbox(sandbox_mode="disabled")
        _ = sandbox.backend

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

    def test_execute_passes_sandbox_mode_to_backend(self):
        """Test that execute passes sandbox_mode to the backend."""
        sandbox = Sandbox(sandbox_mode="required")
        mock_backend = MagicMock()
        mock_backend.execute.return_value = subprocess.CompletedProcess(
            args=["echo", "hello"],
            returncode=0,
            stdout=b"hello",
            stderr=b"",
        )
        sandbox._backend = mock_backend

        sandbox.execute(["echo", "hello"])

        call_kwargs = mock_backend.execute.call_args[1]
        assert call_kwargs["sandbox_mode"] == "required"

    def test_execute_passes_auto_mode_by_default(self):
        """Test that execute passes auto mode by default."""
        sandbox = Sandbox()
        mock_backend = MagicMock()
        mock_backend.execute.return_value = subprocess.CompletedProcess(
            args=["echo", "hello"],
            returncode=0,
            stdout=b"hello",
            stderr=b"",
        )
        sandbox._backend = mock_backend

        sandbox.execute(["echo", "hello"])

        call_kwargs = mock_backend.execute.call_args[1]
        assert call_kwargs["sandbox_mode"] == "auto"


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
                available = sandbox_available()
                assert available is False

    def test_sandbox_available_returns_false_on_sandbox_error(self):
        """Test sandbox_available returns False when SandboxError is raised.

        This tests the fix for the issue where sandbox_available() was called
        in a log statement before the try block, causing uncaught exceptions
        when AWS_MCP_SANDBOX=required but no backend was available.
        """
        with patch("aws_mcp_server.sandbox.get_sandbox") as mock_get_sandbox:
            mock_get_sandbox.side_effect = SandboxError("Sandbox required but not available")
            available = sandbox_available()
            assert available is False

    def test_sandbox_available_propagates_other_exceptions(self):
        """Test that sandbox_available only catches SandboxError, not other exceptions."""
        with patch("aws_mcp_server.sandbox.get_sandbox") as mock_get_sandbox:
            mock_get_sandbox.side_effect = RuntimeError("Unexpected error")
            with pytest.raises(RuntimeError, match="Unexpected error"):
                sandbox_available()


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
    async def test_execute_sandboxed_async_timeout(self):
        """Test async sandbox execution with timeout."""
        from aws_mcp_server.sandbox import execute_sandboxed_async

        with patch("aws_mcp_server.config.SANDBOX_MODE", "disabled"):
            with patch("aws_mcp_server.config.SANDBOX_CREDENTIAL_MODE", "both"):
                reset_sandbox()
                with pytest.raises(asyncio.TimeoutError):
                    await execute_sandboxed_async(["sleep", "10"], timeout=0.1)

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

                assert returncode == 1

    @pytest.mark.asyncio
    async def test_execute_piped_sandboxed_async_timeout(self):
        """Test async piped execution with timeout."""
        from aws_mcp_server.sandbox import execute_piped_sandboxed_async

        with patch("aws_mcp_server.config.SANDBOX_MODE", "disabled"):
            with patch("aws_mcp_server.config.SANDBOX_CREDENTIAL_MODE", "both"):
                reset_sandbox()
                commands = [["sleep", "10"]]
                with pytest.raises(asyncio.TimeoutError):
                    await execute_piped_sandboxed_async(commands, timeout=0.1)

    @pytest.mark.asyncio
    async def test_execute_piped_sandboxed_async_total_timeout(self):
        """Test that timeout applies to entire pipeline, not per-stage."""
        import time

        from aws_mcp_server.sandbox import execute_piped_sandboxed_async

        with patch("aws_mcp_server.config.SANDBOX_MODE", "disabled"):
            with patch("aws_mcp_server.config.SANDBOX_CREDENTIAL_MODE", "both"):
                reset_sandbox()
                commands = [
                    ["sleep", "0.15"],
                    ["sleep", "0.15"],
                    ["sleep", "0.15"],
                ]
                start = time.monotonic()
                with pytest.raises(asyncio.TimeoutError):
                    await execute_piped_sandboxed_async(commands, timeout=0.3)
                elapsed = time.monotonic() - start
                assert elapsed < 0.5, f"Pipeline took {elapsed}s, should timeout around 0.3s"

    @pytest.mark.asyncio
    async def test_execute_piped_sandboxed_async_zero_timeout(self):
        """Test timeout=0 raises TimeoutError immediately (not TypeError)."""
        from aws_mcp_server.sandbox import execute_piped_sandboxed_async

        with patch("aws_mcp_server.config.SANDBOX_MODE", "disabled"):
            with patch("aws_mcp_server.config.SANDBOX_CREDENTIAL_MODE", "both"):
                reset_sandbox()
                commands = [["echo", "hello"]]
                with pytest.raises(asyncio.TimeoutError):
                    await execute_piped_sandboxed_async(commands, timeout=0)


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

    def test_build_env_skips_aws_when_disabled(self, monkeypatch):
        """Ensure AWS env vars are not passed when env creds are disabled."""
        backend = NoOpBackend()
        config = SandboxConfig(pass_aws_env=False)
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "secret")
        monkeypatch.setenv("PATH", "/bin")

        env = backend._build_env(config)

        assert "AWS_ACCESS_KEY_ID" not in env
        assert env["PATH"] == "/bin"

    def test_build_env_skips_manual_aws_passthrough_when_disabled(self, monkeypatch):
        """Even manually added AWS vars should be filtered when disabled."""
        backend = NoOpBackend()
        config = SandboxConfig(pass_aws_env=False)
        config.env_passthrough.append("AWS_SECRET_ACCESS_KEY")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "supersecret")
        monkeypatch.setenv("PATH", "/usr/bin")

        env = backend._build_env(config)

        assert "AWS_SECRET_ACCESS_KEY" not in env
        assert env["PATH"] == "/usr/bin"

    def test_build_env_keeps_non_secret_aws_when_disabled(self, monkeypatch):
        """Non-secret AWS settings should still pass through."""
        backend = NoOpBackend()
        config = SandboxConfig(pass_aws_env=False)
        monkeypatch.setenv("AWS_REGION", "us-west-2")
        monkeypatch.setenv("AWS_PROFILE", "custom")

        env = backend._build_env(config)

        assert env["AWS_REGION"] == "us-west-2"
        assert env["AWS_PROFILE"] == "custom"

    def test_build_env_includes_aws_when_enabled(self, monkeypatch):
        """AWS env vars should be passed when env creds are enabled."""
        backend = NoOpBackend()
        config = SandboxConfig(pass_aws_env=True)
        monkeypatch.setenv("AWS_SESSION_TOKEN", "token")

        env = backend._build_env(config)

        assert env["AWS_SESSION_TOKEN"] == "token"


class TestGetAwsCredentialPaths:
    """Tests for get_aws_credential_paths helper function."""

    def test_default_aws_directory_included(self, tmp_path, monkeypatch):
        """Test that default ~/.aws directory is included when it exists."""
        aws_dir = tmp_path / ".aws"
        aws_dir.mkdir()

        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        monkeypatch.delenv("AWS_SHARED_CREDENTIALS_FILE", raising=False)
        monkeypatch.delenv("AWS_CONFIG_FILE", raising=False)
        monkeypatch.delenv("AWS_WEB_IDENTITY_TOKEN_FILE", raising=False)

        paths = get_aws_credential_paths()

        assert str(aws_dir) in paths

    def test_default_aws_directory_not_included_when_missing(self, tmp_path, monkeypatch):
        """Test that non-existent ~/.aws directory is not included."""
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        monkeypatch.delenv("AWS_SHARED_CREDENTIALS_FILE", raising=False)
        monkeypatch.delenv("AWS_CONFIG_FILE", raising=False)
        monkeypatch.delenv("AWS_WEB_IDENTITY_TOKEN_FILE", raising=False)

        paths = get_aws_credential_paths()

        assert len(paths) == 0

    def test_custom_credentials_file_included(self, tmp_path, monkeypatch):
        """Test that AWS_SHARED_CREDENTIALS_FILE path is included."""
        creds_file = tmp_path / "custom_credentials"
        creds_file.write_text("[default]\naws_access_key_id = test\n")

        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "nonexistent")
        monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds_file))
        monkeypatch.delenv("AWS_CONFIG_FILE", raising=False)
        monkeypatch.delenv("AWS_WEB_IDENTITY_TOKEN_FILE", raising=False)

        paths = get_aws_credential_paths()

        assert str(creds_file) in paths

    def test_custom_config_file_included(self, tmp_path, monkeypatch):
        """Test that AWS_CONFIG_FILE path is included."""
        config_file = tmp_path / "custom_config"
        config_file.write_text("[default]\nregion = us-west-2\n")

        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "nonexistent")
        monkeypatch.delenv("AWS_SHARED_CREDENTIALS_FILE", raising=False)
        monkeypatch.setenv("AWS_CONFIG_FILE", str(config_file))
        monkeypatch.delenv("AWS_WEB_IDENTITY_TOKEN_FILE", raising=False)

        paths = get_aws_credential_paths()

        assert str(config_file) in paths

    def test_web_identity_token_file_included(self, tmp_path, monkeypatch):
        """Test that AWS_WEB_IDENTITY_TOKEN_FILE path is included (EKS IRSA)."""
        token_file = tmp_path / "token"
        token_file.write_text("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")

        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "nonexistent")
        monkeypatch.delenv("AWS_SHARED_CREDENTIALS_FILE", raising=False)
        monkeypatch.delenv("AWS_CONFIG_FILE", raising=False)
        monkeypatch.setenv("AWS_WEB_IDENTITY_TOKEN_FILE", str(token_file))

        paths = get_aws_credential_paths()

        assert str(token_file) in paths

    def test_nonexistent_custom_paths_not_included(self, tmp_path, monkeypatch):
        """Test that non-existent custom paths are not included."""
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "nonexistent")
        monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent/credentials")
        monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent/config")
        monkeypatch.setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "/nonexistent/token")

        paths = get_aws_credential_paths()

        assert len(paths) == 0

    def test_duplicate_paths_deduplicated(self, tmp_path, monkeypatch):
        """Test that duplicate paths are deduplicated."""
        aws_dir = tmp_path / ".aws"
        aws_dir.mkdir()
        creds_file = aws_dir / "credentials"
        creds_file.write_text("[default]\n")
        config_file = aws_dir / "config"
        config_file.write_text("[default]\n")

        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds_file))
        monkeypatch.setenv("AWS_CONFIG_FILE", str(config_file))
        monkeypatch.delenv("AWS_WEB_IDENTITY_TOKEN_FILE", raising=False)

        paths = get_aws_credential_paths()

        assert len(paths) == len(set(paths))

    def test_all_paths_combined(self, tmp_path, monkeypatch):
        """Test that all credential paths are included when all exist."""
        aws_dir = tmp_path / ".aws"
        aws_dir.mkdir()

        custom_creds = tmp_path / "custom_creds"
        custom_creds.write_text("[default]\n")

        custom_config = tmp_path / "custom_config"
        custom_config.write_text("[default]\n")

        token_file = tmp_path / "token"
        token_file.write_text("token")

        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(custom_creds))
        monkeypatch.setenv("AWS_CONFIG_FILE", str(custom_config))
        monkeypatch.setenv("AWS_WEB_IDENTITY_TOKEN_FILE", str(token_file))

        paths = get_aws_credential_paths()

        assert str(aws_dir) in paths
        assert str(custom_creds) in paths
        assert str(custom_config) in paths
        assert str(token_file) in paths
