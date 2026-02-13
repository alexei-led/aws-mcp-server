"""Main entry point for the AWS MCP Server.

This module provides the entry point for running the AWS MCP Server.
FastMCP handles the command-line arguments and server configuration.
"""

import logging
import os
import signal
import sys
import threading

from aws_mcp_server.server import logger, mcp, run_startup_checks

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)


def handle_interrupt(signum, frame):
    """Handle interrupt signal by exiting immediately."""
    logger.info(f"Received signal {signum}, shutting down...")
    os._exit(0)


def monitor_stdin_pipe():
    """Monitor stdin pipe for hangup and exit when the MCP client disconnects.

    When running over stdio transport (especially in Docker), the MCP client
    communicates via stdin/stdout pipes. If the client exits without sending
    SIGTERM (common with IDE integrations like VS Code/Cline), the write end
    of the stdin pipe gets closed.

    This thread uses poll() to detect POLLHUP (hang-up) on stdin without
    consuming any data, so it doesn't interfere with FastMCP's own stdin
    reading for the MCP protocol.

    This prevents orphaned Docker containers that accumulate over time.
    See: https://github.com/alexei-led/aws-mcp-server/issues/16
    """
    try:
        import select

        poll_obj = select.poll()
        poll_obj.register(sys.stdin.fileno(), select.POLLHUP | select.POLLERR)

        while True:
            events = poll_obj.poll(2000)  # Check every 2 seconds
            for _fd, event in events:
                if event & (select.POLLHUP | select.POLLERR):
                    logger.info("Stdin pipe closed (client disconnected), shutting down...")
                    os._exit(0)
    except (OSError, ValueError) as e:
        logger.info(f"Stdin monitor error ({e}), shutting down...")
        os._exit(0)
    except AttributeError:
        # select.poll() is not available on all platforms (e.g., some macOS builds).
        # Fall back to periodic parent PID check.
        _monitor_parent_fallback()


def _monitor_parent_fallback():
    """Fallback: monitor parent PID for platforms without select.poll().

    On non-Docker environments where the server is a child of the MCP client,
    detect parent process death by checking if ppid changes (reparented to init).
    """
    import time

    original_ppid = os.getppid()
    if original_ppid <= 1:
        # Already PID 1 or child of init — no parent to monitor
        logger.info("Stdin monitor fallback: no parent process to monitor, skipping")
        return

    while True:
        time.sleep(2)
        current_ppid = os.getppid()
        if current_ppid != original_ppid:
            logger.info(
                f"Parent process changed ({original_ppid} -> {current_ppid}), "
                "client likely disconnected. Shutting down..."
            )
            os._exit(0)


def main():
    """Entry point for the AWS MCP Server CLI."""
    run_startup_checks()

    signal.signal(signal.SIGINT, handle_interrupt)
    signal.signal(signal.SIGTERM, handle_interrupt)

    try:
        from aws_mcp_server.config import TRANSPORT, is_docker_environment

        if TRANSPORT not in ("stdio", "sse"):
            logger.error(f"Invalid transport protocol: {TRANSPORT}. Must be 'stdio' or 'sse'")
            sys.exit(1)

        logger.info(f"Starting server with transport protocol: {TRANSPORT}")

        if TRANSPORT == "sse":
            # Bind to 0.0.0.0 in Docker (required for port mapping), 127.0.0.1 otherwise
            host = "0.0.0.0" if is_docker_environment() else "127.0.0.1"
            mcp.settings.host = host
            logger.info(f"SSE server binding to {host}:{mcp.settings.port}")
        else:
            # For stdio transport, monitor stdin pipe to detect client disconnection.
            # Uses poll() for POLLHUP on Linux/Docker, falls back to parent PID
            # monitoring on other platforms.
            stdin_thread = threading.Thread(target=monitor_stdin_pipe, daemon=True)
            stdin_thread.start()
            logger.info("Stdin pipe monitor started for client disconnect detection")

        mcp.run(transport=TRANSPORT)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Shutting down...")
        os._exit(0)


if __name__ == "__main__":
    main()
