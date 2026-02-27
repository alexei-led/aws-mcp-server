# AWS MCP Server Development Guide

## Build & Test Commands

- Install all deps: `uv pip install --system -e ".[dev]"`
- Run tests: `make test` or `python -m pytest -v -m "not integration" --timeout=60`
- Run single test: `pytest tests/path/to/test_file.py::test_function_name -v`
- Run linter: `ruff check src/ tests/`
- Format code: `ruff format src/ tests/`
- Run server: `python -m aws_mcp_server`
- Run with streamable-http: `AWS_MCP_TRANSPORT=streamable-http python -m aws_mcp_server`
- Run with sandbox disabled: `AWS_MCP_SANDBOX=disabled python -m aws_mcp_server`
- Update lockfile: `uv pip compile --system pyproject.toml -o uv.lock`
- Versioning: `setuptools_scm` from Git tags — tag as `v1.x.y` to release

## Architecture

### Server (`server.py`)
- Two tools: `aws_cli_help` (readOnly) and `aws_cli_pipeline` (destructive, openWorld)
- `FastMCP` instance with `instructions`, `icons`, `SERVER_DESCRIPTION`
- Tools use `ToolAnnotations` from `mcp.types` for tool metadata
- Tool functions return typed dataclasses (`CommandResult`, `CommandHelpResult`)
- All tool failures raise `ToolError` — FastMCP sets `isError: true` in protocol response (SEP-1303)

### Sandbox (`sandbox.py`)
- Landlock LSM for filesystem isolation (Linux only)
- Seccomp-bpf for syscall filtering
- AWS env vars from `SANDBOX_AWS_ENV_VARS` are passed through to sandboxed processes
- `AWS_MCP_SANDBOX=disabled` to bypass for development; `required` to fail hard if unavailable

### CLI Executor (`cli_executor.py`)
- All commands validated before execution (must start with `aws`)
- Pipe support: commands can include `| jq`, `| grep`, etc.
- Timeout handling with configurable default (300s)
- Returns `{"status": "success"|"error", "output": "..."}` dict

### Transport & Lifecycle (`__main__.py`)
- Transports: `stdio` (default), `streamable-http` (recommended for web), `sse` (deprecated)
- On `stdio`: background thread monitors for client disconnect via `select.poll` or parent PID
- On `sse`/`streamable-http`: binds to `0.0.0.0` in Docker, `127.0.0.1` otherwise

### Resources (`resources.py`)
- `aws://profiles` — parses `~/.aws/credentials` and `~/.aws/config`
- `aws://regions` — hardcoded list + optional live fetch from EC2 API
- `aws://config` — summary of current AWS config state

### Prompts (`prompts.py`)
- 10+ prompt templates for common AWS tasks (Well-Architected, cost optimization, security)
- Consistent pattern: Pydantic `Field(description=...)` for all parameters

## Testing Patterns

- **Mocking AWS CLI:** `unittest.mock.patch` on `asyncio.create_subprocess_exec`
- **Sandbox tests:** separate unit (mocked) and integration (requires Linux + Landlock kernel)
- **Fixtures:** shared fixtures in `conftest.py` for mock subprocess results
- **Integration tests:** need actual AWS CLI + credentials — skip in CI with `-m "not integration"`
- **Coverage target:** >80% on `src/aws_mcp_server` — run with `--cov=aws_mcp_server`
- **Timeout:** always run with `--timeout=60` to avoid CI hangs on sandbox tests

## MCP Development Guidelines

- **Tool annotations:** always set `ToolAnnotations` on new tools (`readOnlyHint`, `destructiveHint`, `openWorldHint`)
- **Error handling:** raise `ToolError` for all tool failures — never return error status text from tool functions (SEP-1303)
- **FastMCP patterns:** `@mcp.tool()`, `@mcp.resource()`, `@mcp.prompt()` decorators
- **Context:** accept `ctx: Context | None = None` in tool functions for progress reporting via `ctx.info()`/`ctx.warning()`
- **Field descriptions:** use `pydantic.Field(description=...)` for all tool parameters — these become tool schema
- **Icons:** server-level icon set via `icons=[Icon(src=..., mimeType=...)]` in `FastMCP()`
- **Description:** server description via `SERVER_DESCRIPTION` prepended to `instructions`

## Security Notes

- **NEVER** log or store AWS credentials (access keys, session tokens, profile names with secrets)
- **NEVER** disable sandbox in production
- AWS env vars (`AWS_ACCESS_KEY_ID`, etc.) are in `SANDBOX_AWS_ENV_VARS` — update if new ones added
- Command validation must reject commands that don't start with `aws` or pipe to non-allowlisted executables
- `AWS_MCP_SANDBOX=disabled` is for development only — never in Dockerfile or production config
