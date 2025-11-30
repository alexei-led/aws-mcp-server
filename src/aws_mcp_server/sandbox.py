"""Sandbox execution for AWS CLI commands.

This module provides OS-level process isolation for running AWS CLI commands
securely. It supports:
- Linux: Landlock LSM (kernel 5.13+) with bubblewrap fallback
- macOS: Seatbelt (sandbox-exec) via ctypes

The sandbox restricts filesystem access while allowing:
- Read access to system binaries and libraries
- Read access to AWS configuration (~/.aws) if configured
- Write access to /tmp and current working directory
- Network access for AWS API calls
"""

import ctypes
import logging
import os
import platform
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)

# AWS environment variables passed through to sandboxed processes
AWS_ENV_VARS = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_PROFILE",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CA_BUNDLE",
    "AWS_ROLE_ARN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_SESSION_NAME",
    "AWS_STS_REGIONAL_ENDPOINTS",
    "AWS_EC2_METADATA_DISABLED",
    "AWS_METADATA_SERVICE_TIMEOUT",
    "AWS_METADATA_SERVICE_NUM_ATTEMPTS",
]

# Secret-bearing variables excluded when pass_aws_env=False
AWS_SECRET_ENV_VARS = {
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_ROLE_ARN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_SESSION_NAME",
}


def get_aws_credential_paths() -> list[str]:
    """Get all AWS credential-related paths that should be accessible.

    Returns specific file paths (not directories) for minimal access scope.
    The default ~/.aws directory is still whitelisted as a directory for
    backward compatibility, but custom paths are file-only.
    """
    paths: list[str] = []

    # Default ~/.aws directory (backward compat)
    default_aws_dir = Path.home() / ".aws"
    if default_aws_dir.exists():
        paths.append(str(default_aws_dir))

    # Custom credentials file
    creds_file = os.environ.get("AWS_SHARED_CREDENTIALS_FILE")
    if creds_file:
        creds_path = Path(creds_file)
        if creds_path.exists():
            paths.append(str(creds_path))

    # Custom config file
    config_file = os.environ.get("AWS_CONFIG_FILE")
    if config_file:
        config_path = Path(config_file)
        if config_path.exists():
            paths.append(str(config_path))

    # Web identity token file (EKS IRSA)
    token_file = os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE")
    if token_file:
        token_path = Path(token_file)
        if token_path.exists():
            paths.append(str(token_path))

    seen: set[str] = set()
    unique_paths: list[str] = []
    for path in paths:
        if path not in seen:
            seen.add(path)
            unique_paths.append(path)
    return unique_paths


@dataclass
class SandboxConfig:
    """Configuration for sandbox execution."""

    # Paths with read-only access
    read_paths: list[str] = field(default_factory=list)
    # Paths with read-write access
    write_paths: list[str] = field(default_factory=list)
    # Allow network access
    allow_network: bool = True
    # Pass AWS credentials via environment variables
    pass_aws_env: bool = True
    # Allow read access to ~/.aws directory
    allow_aws_config: bool = True
    # Environment variables to pass through
    env_passthrough: list[str] = field(default_factory=list)

    def __post_init__(self):
        """Set up default paths."""
        if not self.read_paths:
            self.read_paths = self._default_read_paths()
        if not self.write_paths:
            self.write_paths = self._default_write_paths()
        if not self.env_passthrough:
            self.env_passthrough = self._default_env_passthrough()
        # Remove secret AWS variables if env-based credentials are disabled
        if not self.pass_aws_env:
            self.env_passthrough = [var for var in self.env_passthrough if var not in AWS_SECRET_ENV_VARS]

    @staticmethod
    def _default_read_paths() -> list[str]:
        """Return default read-only paths for the platform."""
        system = platform.system()
        if system == "Linux":
            return [
                "/usr",
                "/bin",
                "/lib",
                "/lib64",
                "/etc/ssl",
                "/etc/ca-certificates",
                "/etc/pki",
                "/etc/resolv.conf",
                "/etc/hosts",
                "/etc/nsswitch.conf",
                "/etc/passwd",
                "/etc/group",
            ]
        elif system == "Darwin":
            return [
                "/usr",
                "/bin",
                "/sbin",
                "/Library",
                "/System",
                "/private/etc",
                "/var/run",
                "/dev",
            ]
        return []

    @staticmethod
    def _default_write_paths() -> list[str]:
        """Return default writable paths."""
        return [
            "/tmp",
            os.environ.get("TMPDIR", "/tmp"),
            os.getcwd(),
        ]

    @staticmethod
    def _default_env_passthrough() -> list[str]:
        """Return default environment variables to pass through."""
        return [
            "PATH",
            "HOME",
            "USER",
            "LANG",
            "LC_ALL",
            "TERM",
            "TZ",
            # AWS-specific
            *AWS_ENV_VARS,
        ]


class SandboxError(Exception):
    """Exception raised when sandbox operations fail."""

    pass


class SandboxBackend(ABC):
    """Abstract base class for sandbox backends."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this sandbox backend is available on the current system."""

    @abstractmethod
    def execute(
        self,
        cmd: "Sequence[str]",
        config: SandboxConfig,
        *,
        input_data: bytes | None = None,
        timeout: float | None = None,
        sandbox_mode: str = "auto",
    ) -> subprocess.CompletedProcess[bytes]:
        """Execute a command in the sandbox.

        Args:
            cmd: Command and arguments to execute
            config: Sandbox configuration
            input_data: Optional input to pass to the process stdin
            timeout: Optional timeout in seconds
            sandbox_mode: One of "auto", "disabled", or "required"

        Returns:
            CompletedProcess with stdout and stderr

        Raises:
            SandboxError: If sandbox execution fails
            subprocess.TimeoutExpired: If command times out
        """

    def _build_env(self, config: SandboxConfig) -> dict[str, str]:
        """Build environment variables for sandboxed process.

        Args:
            config: Sandbox configuration with env_passthrough list

        Returns:
            Dictionary of environment variables to pass to subprocess
        """
        env: dict[str, str] = {}
        for key in config.env_passthrough:
            if not config.pass_aws_env and key in AWS_SECRET_ENV_VARS:
                continue
            if key in os.environ:
                env[key] = os.environ[key]
        return env


class LinuxLandlockBackend(SandboxBackend):
    """Linux sandbox using Landlock LSM.

    Landlock is a Linux security module that allows unprivileged processes
    to restrict themselves. Requires kernel 5.13+.
    """

    def __init__(self):
        self._available: bool | None = None
        self._landlock_module = None

    def is_available(self) -> bool:
        """Check if Landlock is available."""
        if self._available is not None:
            return self._available

        if platform.system() != "Linux":
            self._available = False
            return False

        try:
            release = platform.release()
            major, minor = map(int, release.split(".")[:2])
            if major < 5 or (major == 5 and minor < 13):
                logger.debug(f"Kernel {release} too old for Landlock (need 5.13+)")
                self._available = False
                return False
        except (ValueError, IndexError):
            logger.debug(f"Could not parse kernel version: {platform.release()}")
            self._available = False
            return False

        try:
            import landlock

            self._landlock_module = landlock
            self._available = True
            logger.debug("Landlock is available")
        except ImportError:
            logger.debug("landlock Python module not installed")
            self._available = False

        return self._available

    def execute(
        self,
        cmd: "Sequence[str]",
        config: SandboxConfig,
        *,
        input_data: bytes | None = None,
        timeout: float | None = None,
        sandbox_mode: str = "auto",
    ) -> subprocess.CompletedProcess[bytes]:
        """Execute command with Landlock restrictions."""
        if not self.is_available():
            raise SandboxError("Landlock is not available")

        # Import here to avoid errors on non-Linux
        import landlock

        def setup_sandbox():
            """Set up Landlock sandbox before exec."""
            try:
                rs = landlock.Ruleset()

                for path in config.read_paths:
                    if os.path.exists(path):
                        rs.allow(path)

                # AWS credential paths (includes custom paths from env vars)
                if config.allow_aws_config:
                    for aws_path in get_aws_credential_paths():
                        if os.path.exists(aws_path):
                            rs.allow(aws_path)

                for path in config.write_paths:
                    if os.path.exists(path):
                        rs.allow(path, write=True)

                rs.apply()
            except Exception as e:
                if sandbox_mode == "required":
                    raise RuntimeError(f"Sandboxing required but Landlock failed: {e}") from e
                logger.warning(f"Landlock sandbox failed (mode={sandbox_mode}), continuing unsandboxed: {e}")

        env = self._build_env(config)

        return subprocess.run(
            list(cmd),
            input=input_data,
            capture_output=True,
            timeout=timeout,
            env=env,
            preexec_fn=setup_sandbox,
        )


class LinuxBubblewrapBackend(SandboxBackend):
    """Linux sandbox using bubblewrap (bwrap).

    Bubblewrap is a lightweight sandbox tool that uses Linux namespaces
    and seccomp. It's available on most Linux distributions.
    """

    def __init__(self):
        self._available: bool | None = None
        self._bwrap_path: str | None = None

    def is_available(self) -> bool:
        """Check if bubblewrap is available."""
        if self._available is not None:
            return self._available

        if platform.system() != "Linux":
            self._available = False
            return False

        self._bwrap_path = shutil.which("bwrap")
        self._available = self._bwrap_path is not None

        if self._available:
            logger.debug(f"Bubblewrap available at {self._bwrap_path}")
        else:
            logger.debug("Bubblewrap (bwrap) not found")

        return self._available

    def _build_bwrap_args(self, config: SandboxConfig) -> list[str]:
        """Build bwrap command line arguments."""
        args = [self._bwrap_path]

        for path in config.read_paths:
            if os.path.exists(path):
                args.extend(["--ro-bind", path, path])

        # AWS credential paths (includes custom paths from env vars)
        if config.allow_aws_config:
            for aws_path in get_aws_credential_paths():
                if os.path.exists(aws_path):
                    args.extend(["--ro-bind", aws_path, aws_path])

        for path in config.write_paths:
            if os.path.exists(path):
                args.extend(["--bind", path, path])

        args.extend(
            [
                "--proc",
                "/proc",
                "--dev",
                "/dev",
            ]
        )

        # Security: PID namespace isolation
        args.append("--unshare-pid")
        # Security: Prevent TTY injection attacks
        args.append("--new-session")
        # Security: Kill sandbox if parent dies
        args.append("--die-with-parent")

        if not config.allow_network:
            args.append("--unshare-net")

        args.append("--")

        return args

    def execute(
        self,
        cmd: "Sequence[str]",
        config: SandboxConfig,
        *,
        input_data: bytes | None = None,
        timeout: float | None = None,
        sandbox_mode: str = "auto",
    ) -> subprocess.CompletedProcess[bytes]:
        """Execute command in bubblewrap sandbox."""
        if not self.is_available():
            raise SandboxError("Bubblewrap is not available")

        bwrap_args = self._build_bwrap_args(config)
        full_cmd = bwrap_args + list(cmd)
        env = self._build_env(config)

        return subprocess.run(
            full_cmd,
            input=input_data,
            capture_output=True,
            timeout=timeout,
            env=env,
        )


class MacOSSeatbeltBackend(SandboxBackend):
    """macOS sandbox using Seatbelt (sandbox-exec).

    Seatbelt is macOS's built-in sandboxing technology. While Apple considers
    the public API deprecated, it's still functional and used by Chrome,
    Firefox, and other major applications.
    """

    PROFILE_TEMPLATE = """
(version 1)
(deny default)

; Allow process operations
(allow process*)
(allow signal)
(allow sysctl-read)
(allow mach-lookup)
(allow mach-register)
(allow ipc-posix*)
(allow system-socket)

; Allow reading system paths
(allow file-read*
    (subpath "/usr")
    (subpath "/bin")
    (subpath "/sbin")
    (subpath "/Library")
    (subpath "/System")
    (subpath "/private/etc")
    (subpath "/private/var/run")
    (subpath "/var/run")
    (subpath "/dev")
    (subpath "/Applications/Xcode.app")
    (literal "/")
    (literal "/private")
    (literal "/private/var")
)

; Allow reading AWS config if enabled
{aws_config_rule}

; Allow reading and writing to allowed paths
{write_rules}

; Allow network access if enabled
{network_rule}

; Allow reading environment and process info
(allow file-read-metadata)
(allow process-info*)
"""

    def __init__(self):
        self._available: bool | None = None

    def is_available(self) -> bool:
        """Check if Seatbelt is available."""
        if self._available is not None:
            return self._available

        if platform.system() != "Darwin":
            self._available = False
            return False

        # Check macOS version (need 12+)
        try:
            version = platform.mac_ver()[0]
            major = int(version.split(".")[0])
            if major < 12:
                logger.debug(f"macOS {version} too old for Seatbelt (need 12+)")
                self._available = False
                return False
        except (ValueError, IndexError):
            logger.debug(f"Could not parse macOS version: {platform.mac_ver()}")

        # Try to load libSystem for sandbox_init
        try:
            ctypes.CDLL("/usr/lib/libSystem.B.dylib")
            self._available = True
            logger.debug("Seatbelt is available")
        except OSError:
            logger.debug("Could not load libSystem")
            self._available = False

        return self._available

    def _build_profile(self, config: SandboxConfig) -> str:
        """Build Seatbelt profile from configuration."""
        # AWS credential paths rule (includes custom paths from env vars)
        if config.allow_aws_config:
            aws_paths = get_aws_credential_paths()
            rules = []
            for aws_path in aws_paths:
                if os.path.isdir(aws_path):
                    rules.append(f'(allow file-read* (subpath "{aws_path}"))')
                else:
                    rules.append(f'(allow file-read* (literal "{aws_path}"))')
            aws_config_rule = "\n".join(rules) if rules else "; No AWS paths"
        else:
            aws_config_rule = "; AWS config access disabled"

        # Write rules
        write_rules = []
        for path in config.write_paths:
            if os.path.exists(path):
                write_rules.append(f'(allow file-read* file-write* (subpath "{path}"))')
        write_rules_str = "\n".join(write_rules) if write_rules else "; No write paths"

        # Network rule
        if config.allow_network:
            network_rule = "(allow network*)"
        else:
            network_rule = "; Network access disabled"

        return self.PROFILE_TEMPLATE.format(
            aws_config_rule=aws_config_rule,
            write_rules=write_rules_str,
            network_rule=network_rule,
        )

    def execute(
        self,
        cmd: "Sequence[str]",
        config: SandboxConfig,
        *,
        input_data: bytes | None = None,
        timeout: float | None = None,
        sandbox_mode: str = "auto",
    ) -> subprocess.CompletedProcess[bytes]:
        """Execute command with Seatbelt sandbox."""
        if not self.is_available():
            raise SandboxError("Seatbelt is not available")

        profile = self._build_profile(config)
        env = self._build_env(config)

        # Use sandbox-exec command line tool
        sandbox_cmd = [
            "/usr/bin/sandbox-exec",
            "-p",
            profile,
            *cmd,
        ]

        return subprocess.run(
            sandbox_cmd,
            input=input_data,
            capture_output=True,
            timeout=timeout,
            env=env,
        )


class NoOpBackend(SandboxBackend):
    """No-op sandbox backend that executes commands without isolation.

    Used when sandboxing is disabled or no sandbox backend is available.
    """

    def is_available(self) -> bool:
        """Always available as fallback."""
        return True

    def execute(
        self,
        cmd: "Sequence[str]",
        config: SandboxConfig,
        *,
        input_data: bytes | None = None,
        timeout: float | None = None,
        sandbox_mode: str = "auto",
    ) -> subprocess.CompletedProcess[bytes]:
        """Execute command without sandboxing."""
        env = self._build_env(config)

        return subprocess.run(
            list(cmd),
            input=input_data,
            capture_output=True,
            timeout=timeout,
            env=env,
        )


class Sandbox:
    """Main sandbox class that selects and uses the appropriate backend."""

    def __init__(
        self,
        config: SandboxConfig | None = None,
        sandbox_mode: str = "auto",
    ):
        """Initialize sandbox with configuration.

        Args:
            config: Sandbox configuration. If None, uses defaults.
            sandbox_mode: One of "auto", "disabled", or "required"
        """
        self.config = config or SandboxConfig()
        self.sandbox_mode = sandbox_mode
        self._backend: SandboxBackend | None = None

    def _select_backend(self, sandbox_mode: str = "auto") -> SandboxBackend:
        """Select the best available sandbox backend.

        Args:
            sandbox_mode: One of "auto", "disabled", or "required"
        """
        if sandbox_mode == "disabled":
            logger.info("Sandbox disabled via configuration")
            return NoOpBackend()

        system = platform.system()

        if system == "Linux":
            # Landlock preferred (kernel-level, no external dependencies)
            landlock_backend = LinuxLandlockBackend()
            if landlock_backend.is_available():
                logger.info("Using Landlock sandbox backend")
                return landlock_backend

            # Bubblewrap fallback
            bwrap = LinuxBubblewrapBackend()
            if bwrap.is_available():
                logger.info("Using Bubblewrap sandbox backend")
                return bwrap

            logger.warning("No Linux sandbox backend available, running without isolation")

        elif system == "Darwin":
            seatbelt = MacOSSeatbeltBackend()
            if seatbelt.is_available():
                logger.info("Using Seatbelt sandbox backend")
                return seatbelt

            logger.warning("Seatbelt not available on this macOS version")

        else:
            logger.warning(f"No sandbox support for {system}")

        if sandbox_mode == "required":
            raise SandboxError(f"Sandbox required but not available on {system}")

        return NoOpBackend()

    @property
    def backend(self) -> SandboxBackend:
        """Get the sandbox backend, selecting one if needed."""
        if self._backend is None:
            self._backend = self._select_backend(self.sandbox_mode)
        return self._backend

    def execute(
        self,
        cmd: "Sequence[str]",
        *,
        input_data: bytes | None = None,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        """Execute a command in the sandbox.

        Args:
            cmd: Command and arguments to execute
            input_data: Optional input to pass to the process stdin
            timeout: Optional timeout in seconds

        Returns:
            CompletedProcess with stdout and stderr

        Raises:
            SandboxError: If sandbox execution fails
            subprocess.TimeoutExpired: If command times out
        """
        return self.backend.execute(
            cmd,
            self.config,
            input_data=input_data,
            timeout=timeout,
            sandbox_mode=self.sandbox_mode,
        )

    def is_sandboxed(self) -> bool:
        """Check if commands will actually be sandboxed."""
        return not isinstance(self.backend, NoOpBackend)


# Global sandbox instance with default configuration
_default_sandbox: Sandbox | None = None


def get_sandbox() -> Sandbox:
    """Get the default sandbox instance."""
    global _default_sandbox
    if _default_sandbox is None:
        # Avoid circular imports
        from aws_mcp_server.config import SANDBOX_CREDENTIAL_MODE, SANDBOX_MODE

        config = SandboxConfig(
            allow_aws_config=(SANDBOX_CREDENTIAL_MODE in ("aws_config", "both")),
            pass_aws_env=(SANDBOX_CREDENTIAL_MODE in ("env", "both")),
        )
        _default_sandbox = Sandbox(config, sandbox_mode=SANDBOX_MODE)
    return _default_sandbox


def reset_sandbox() -> None:
    """Reset the global sandbox instance. Useful for testing."""
    global _default_sandbox
    _default_sandbox = None


def execute_sandboxed(
    cmd: "Sequence[str]",
    *,
    input_data: bytes | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Execute a command in the default sandbox.

    This is a convenience function that uses the global sandbox instance.

    Args:
        cmd: Command and arguments to execute
        input_data: Optional input to pass to the process stdin
        timeout: Optional timeout in seconds

    Returns:
        CompletedProcess with stdout and stderr
    """
    return get_sandbox().execute(cmd, input_data=input_data, timeout=timeout)


async def execute_sandboxed_async(
    cmd: "Sequence[str]",
    *,
    input_data: bytes | None = None,
    timeout: float | None = None,
) -> tuple[bytes, bytes, int]:
    """Execute a command in the sandbox asynchronously.

    This runs the sandboxed command in a thread pool to avoid blocking
    the event loop.

    Args:
        cmd: Command and arguments to execute
        input_data: Optional input to pass to the process stdin
        timeout: Optional timeout in seconds

    Returns:
        Tuple of (stdout, stderr, return_code)

    Raises:
        SandboxError: If sandbox execution fails
        asyncio.TimeoutError: If command times out
    """
    import asyncio

    loop = asyncio.get_running_loop()

    def run_sandboxed():
        try:
            result = get_sandbox().execute(cmd, input_data=input_data, timeout=timeout)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as e:
            raise asyncio.TimeoutError(f"Command timed out after {e.timeout} seconds") from e

    # Run in thread pool to avoid blocking
    return await loop.run_in_executor(None, run_sandboxed)


async def execute_piped_sandboxed_async(
    commands: "Sequence[Sequence[str]]",
    *,
    timeout: float | None = None,
) -> tuple[bytes, bytes, int]:
    """Execute a pipeline of commands in the sandbox asynchronously.

    This runs commands in sequence, passing stdout of each to stdin of the next.

    Args:
        commands: List of commands, each being a sequence of command + args
        timeout: Optional timeout in seconds for the entire pipeline

    Returns:
        Tuple of (stdout, stderr, return_code)

    Raises:
        SandboxError: If sandbox execution fails
        asyncio.TimeoutError: If command times out
    """
    import asyncio
    import time

    if not commands:
        return b"", b"Empty command", 1

    loop = asyncio.get_running_loop()

    def run_pipeline():
        sandbox = get_sandbox()
        current_input: bytes | None = None
        stderr_parts: list[bytes] = []
        start_time = time.monotonic() if timeout is not None else None

        for i, cmd in enumerate(commands):
            # Calculate remaining time for this stage
            stage_timeout: float | None = None
            if timeout is not None:
                elapsed = time.monotonic() - start_time
                remaining = timeout - elapsed
                if remaining <= 0:
                    raise asyncio.TimeoutError(f"Pipeline timed out after {timeout} seconds (at stage {i})")
                stage_timeout = remaining

            try:
                result = sandbox.execute(
                    cmd,
                    input_data=current_input,
                    timeout=stage_timeout,
                )
                if result.stderr:
                    stderr_parts.append(result.stderr)

                if result.returncode != 0:
                    return result.stdout, b"\n".join(stderr_parts), result.returncode

                current_input = result.stdout

            except subprocess.TimeoutExpired as e:
                elapsed = time.monotonic() - start_time if start_time else timeout
                raise asyncio.TimeoutError(f"Pipeline timed out after {elapsed:.1f} seconds (at stage {i})") from e

        return current_input or b"", b"\n".join(stderr_parts), 0

    return await loop.run_in_executor(None, run_pipeline)


def sandbox_available() -> bool:
    """Check if sandboxing is available on the current system.

    Returns False if sandbox is unavailable or if initialization fails
    (e.g., when AWS_MCP_SANDBOX=required but no backend is available).
    """
    try:
        return get_sandbox().is_sandboxed()
    except SandboxError:
        return False
