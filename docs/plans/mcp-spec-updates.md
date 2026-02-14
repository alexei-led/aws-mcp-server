# Plan: MCP Spec 2025-11-25 Compliance Updates

Implement MCP specification 2025-11-25 compliance updates for aws-mcp-server.
Current version: 1.5.6. Target: 1.6.0.

## Validation Commands
- `UV_CACHE_DIR=/tmp/uv-cache uv run ruff check src/ tests/`
- `UV_CACHE_DIR=/tmp/uv-cache uv run pytest -q tests/unit/ -x --timeout=30`

### Task 1: Add Implementation description field (issue #35)
- [x] In `src/aws_mcp_server/server.py`, update the FastMCP constructor to include a `description` parameter: `description="A lightweight MCP server that enables AI assistants to execute AWS CLI commands through the Model Context Protocol"`. This is a simple one-line addition.
- [x] Add a unit test in `tests/unit/test_server.py` that verifies `mcp.settings.description` (or equivalent) is set and non-empty.
- [x] Run validation commands. Fix any lint errors (especially B904, F401).

### Task 2: Add tool icons metadata (issue #36)
- [ ] Check if FastMCP's `@mcp.tool()` decorator or `ToolAnnotations` supports an `icons` field. The FastMCP constructor accepts `icons` parameter. If tool-level icons are not supported in the current `mcp` library version, add server-level icons only.
- [ ] For server-level icons: update `FastMCP()` constructor in `src/aws_mcp_server/server.py` to include `icons=[{"url": "https://raw.githubusercontent.com/alexei-led/aws-mcp-server/main/media/aws-mcp-logo.png", "mediaType": "image/png"}]` (or similar, check the API).
- [ ] Run validation commands. Fix any lint errors.

### Task 3: Return input validation errors as tool execution errors (issue #34)
- [ ] In `src/aws_mcp_server/server.py`, review `aws_cli_help` and `aws_cli_pipeline` tool functions. Currently exceptions are caught and returned as `CommandResult(status="error", ...)`. Ensure that input validation errors (like missing/invalid parameters) are returned as tool results with `isError=True` in the MCP response, NOT as JSON-RPC protocol errors. Check if FastMCP already handles this via return types or if we need to use `mcp.types.TextContent` with `isError`.
- [ ] In `src/aws_mcp_server/cli_executor.py`, check if `CommandExecutionError` is raised for validation issues and ensure it's caught at the tool level and returned as a tool error result.
- [ ] Add a unit test that verifies an invalid command returns a tool execution error (not a protocol error).
- [ ] Run validation commands. Fix any lint errors.

### Task 4: Add Streamable HTTP transport support (issue #33)
- [ ] In `src/aws_mcp_server/config.py`, add `"streamable-http"` as a valid transport option alongside `"stdio"` and `"sse"`. Update the `TRANSPORT` variable validation.
- [ ] In `src/aws_mcp_server/__main__.py`, add handling for the `"streamable-http"` transport: set `mcp.settings.host` like SSE (0.0.0.0 in Docker, 127.0.0.1 otherwise). The FastMCP library already has `streamable_http_path` support. Call `mcp.run(transport="streamable-http")`.
- [ ] Keep `sse` transport working for backward compatibility but log a deprecation warning when it's used.
- [ ] Update `README.md` to document the new transport option, including Docker run examples with `AWS_MCP_TRANSPORT=streamable-http`.
- [ ] Add unit tests for transport configuration validation.
- [ ] Run validation commands. Fix any lint errors.

### Task 5: Merge PR #32 and prepare release
- [ ] Do NOT create a git tag or GitHub release — that will be done manually.
- [ ] Update README.md changelog/features section if it exists, mentioning: graceful shutdown on client disconnect (#16), streamable HTTP transport (#33), input validation error handling (#34), implementation description (#35), server icons (#36).
