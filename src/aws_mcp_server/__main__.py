"""Main entry point for the AWS MCP Server.

This module provides the entry point for running the AWS MCP Server.
FastMCP handles the command-line arguments and server configuration.
"""

import logging
import os
import select
import signal
import sys
import threading
import time
from collections.abc import Callable

from aws_mcp_server.server import logger, mcp, run_startup_checks

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)


def handle_interrupt(signum, frame):
    """Handle interrupt signal by exiting cleanly."""
    logger.info(f"Received signal {signum}, shutting down...")
    raise SystemExit(0) from None


def request_shutdown() -> None:
    """Request process shutdown through SIGTERM."""
    os.kill(os.getpid(), signal.SIGTERM)


def monitor_stdio_disconnect(
    stop_event: threading.Event,
    shutdown_callback: Callable[[], None],
    parent_pid: int | None = None,
    poll_interval_seconds: float = 0.5,
    poller_factory: Callable[[], object] | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> None:
    """Monitor stdio lifecycle and trigger shutdown when the client disconnects."""
    if parent_pid is None:
        parent_pid = os.getppid()

    if poller_factory is None:
        poller_factory = getattr(select, "poll", None)

    if poller_factory is not None:
        try:
            poller = poller_factory()
            poller.register(sys.stdin.fileno(), select.POLLHUP | select.POLLERR | select.POLLNVAL)

            while not stop_event.is_set():
                for _, event in poller.poll(max(1, int(poll_interval_seconds * 1000))):
                    if event & (select.POLLHUP | select.POLLERR | select.POLLNVAL):
                        logger.info("MCP stdio input disconnected, requesting shutdown")
                        shutdown_callback()
                        return
        except (OSError, ValueError, AttributeError):
            logger.warning("select.poll unavailable for stdin monitoring, using parent PID fallback")

    while not stop_event.is_set():
        if os.getppid() != parent_pid:
            logger.info("MCP parent process changed, requesting shutdown")
            shutdown_callback()
            return
        sleep_fn(poll_interval_seconds)


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

        monitor_stop_event: threading.Event | None = None
        monitor_thread: threading.Thread | None = None

        if TRANSPORT == "sse":
            # Bind to 0.0.0.0 in Docker (required for port mapping), 127.0.0.1 otherwise
            host = "0.0.0.0" if is_docker_environment() else "127.0.0.1"
            mcp.settings.host = host
            logger.info(f"SSE server binding to {host}:{mcp.settings.port}")
        else:
            monitor_stop_event = threading.Event()
            monitor_thread = threading.Thread(
                target=monitor_stdio_disconnect,
                kwargs={
                    "stop_event": monitor_stop_event,
                    "shutdown_callback": request_shutdown,
                    "parent_pid": os.getppid(),
                },
                daemon=True,
                name="stdio-disconnect-monitor",
            )
            monitor_thread.start()

        try:
            mcp.run(transport=TRANSPORT)
        finally:
            if monitor_stop_event is not None:
                monitor_stop_event.set()
            if monitor_thread is not None:
                monitor_thread.join(timeout=1)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Shutting down...")
        raise SystemExit(0) from None


if __name__ == "__main__":
    main()
