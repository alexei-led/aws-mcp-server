"""Main entry point for the AWS MCP Server.

This module provides the entry point for running the AWS MCP Server.
FastMCP handles the command-line arguments and server configuration.
"""

import logging
import os
import signal
import sys

from aws_mcp_server.server import logger, mcp

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)


def handle_interrupt(signum, frame):
    """Handle interrupt signal by exiting immediately."""
    logger.info(f"Received signal {signum}, shutting down...")
    os._exit(0)


def main():
    """Entry point for the AWS MCP Server CLI."""
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

        mcp.run(transport=TRANSPORT)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Shutting down...")
        os._exit(0)


if __name__ == "__main__":
    main()
