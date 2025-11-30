# Development Guide

This guide covers setting up the development environment, running tests, and contributing to AWS MCP Server.

## Requirements

- Python 3.13+
- AWS CLI installed and configured
- Docker (optional, for containerized testing)

## Development Setup

### Using pip

```bash
# Clone repository
git clone https://github.com/alexei-led/aws-mcp-server.git
cd aws-mcp-server

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install runtime dependencies
pip install -e .

# Install development dependencies
pip install -e ".[dev]"
```

### Using uv (Recommended)

[uv](https://github.com/astral-sh/uv) provides faster dependency management:

```bash
# Install uv
pip install uv

# Install runtime dependencies
make uv-install

# Install development dependencies
make uv-dev-install
```

## Running the Server

```bash
# Standard mode (stdio transport)
python -m aws_mcp_server

# SSE transport mode
AWS_MCP_TRANSPORT=sse python -m aws_mcp_server

# With sandbox disabled (for development)
AWS_MCP_SANDBOX=disabled python -m aws_mcp_server

# Using MCP CLI
mcp run src/aws_mcp_server/server.py
```

## Makefile Commands

The project includes a Makefile with targets for common tasks:

### Test Commands

```bash
make test             # Run unit tests (excludes integration)
make test-unit        # Run unit tests only
make test-integration # Run integration tests (requires AWS credentials)
make test-all         # Run all tests including integration
```

### Coverage

```bash
make test-coverage     # Coverage report (excludes integration)
make test-coverage-all # Coverage report (includes integration)
```

### Linting and Formatting

```bash
make lint      # Run linters (ruff check, format --check)
make lint-fix  # Run linters and auto-fix issues
make format    # Format code with ruff
```

### Full List

Run `make help` to see all available commands.

## Testing

### Unit Tests

```bash
# Run all unit tests
pytest

# Run specific test file
pytest tests/path/to/test_file.py

# Run specific test function
pytest tests/path/to/test_file.py::test_function_name -v

# Run with coverage
python -m pytest --cov=src/aws_mcp_server tests/
```

### Integration Tests

Integration tests verify functionality with actual AWS resources:

1. **Set up AWS resources:**

   ```bash
   # Create an S3 bucket for testing
   aws s3 mb s3://your-test-bucket-name

   # Set environment variable
   export AWS_TEST_BUCKET=your-test-bucket-name
   ```

2. **Run integration tests:**

   ```bash
   # All tests including integration
   make test-all

   # Only integration tests
   make test-integration

   # Or using pytest directly
   pytest --run-integration -m integration
   ```

## Code Style

### Formatting

- Use `ruff format` (Black-compatible)
- Run `make format` before committing

### Linting

- Use `ruff check` for linting
- Run `make lint` to check, `make lint-fix` to auto-fix

### Type Hints

Use native Python type hints:

```python
# Good
def process_items(items: list[str]) -> dict[str, int]:
    ...

# Avoid (old style)
from typing import List, Dict
def process_items(items: List[str]) -> Dict[str, int]:
    ...
```

### Docstrings

Use Google-style docstrings:

```python
def execute_command(command: str, timeout: int = 300) -> str:
    """Execute an AWS CLI command.

    Args:
        command: The AWS CLI command to execute.
        timeout: Maximum execution time in seconds.

    Returns:
        The command output as a string.

    Raises:
        CommandExecutionError: If the command fails to execute.
        TimeoutError: If the command exceeds the timeout.
    """
```

## Project Structure

```
aws-mcp-server/
├── src/aws_mcp_server/    # Main source code
│   ├── __init__.py
│   ├── __main__.py        # Entry point
│   ├── server.py          # MCP server implementation
│   ├── cli_executor.py    # AWS CLI execution with error handling
│   ├── sandbox.py         # OS-level sandbox execution
│   ├── tools.py           # Pipe command utilities
│   ├── config.py          # Configuration settings
│   ├── resources.py       # MCP resources (profiles, regions)
│   └── prompts.py         # Prompt templates
├── tests/                 # Test files
│   ├── unit/              # Unit tests
│   └── integration/       # Integration tests
├── deploy/docker/         # Docker deployment files
└── docs/                  # Documentation
```

## Versioning

The project uses [setuptools_scm](https://github.com/pypa/setuptools_scm) for automatic version management based on Git tags.

### Version Format

- **Release versions**: Git tag (e.g., `1.2.3`)
- **Development versions**: `<tag>.post<commits>+g<hash>.d<date>` (e.g., `1.2.3.post10+gb697684.d20250406`)

### Creating a Release

```bash
# Create and push a tag
git tag -a 1.2.3 -m "Release version 1.2.3"
git push origin 1.2.3
```

The CI/CD pipeline automatically builds and publishes Docker images with version tags.

For more details, see [VERSION.md](VERSION.md).

## Dependency Management

### Adding Dependencies

1. Add to `pyproject.toml` under `dependencies` or `[project.optional-dependencies]`
2. Regenerate lock file: `uv pip compile --system pyproject.toml -o uv.lock`
3. Install: `uv pip sync --system uv.lock`

### Lock File

The `uv.lock` file ensures reproducible builds. Always update it when changing dependencies.

## Docker Development

The Docker image uses a pre-built Python wheel for faster builds and consistent versioning.

### Building the Image

```bash
# Step 1: Build the Python wheel (required)
uv build

# Step 2: Build Docker image
docker build -f deploy/docker/Dockerfile -t aws-mcp-server .
```

The wheel in `dist/` contains the correct version from `setuptools_scm`. This approach:

- Reuses the same versioned package across CI, PyPI, and Docker
- Speeds up Docker builds (no Python build inside container)
- Ensures version consistency between `pip install aws-mcp` and Docker image

### Running in Docker

```bash
# Using docker-compose
docker compose -f deploy/docker/docker-compose.yml up -d

# Using docker run
docker run -i --rm \
  -v ~/.aws:/home/appuser/.aws:ro \
  aws-mcp-server
```

## Troubleshooting

### Common Issues

**Import errors**: Ensure you installed in development mode (`pip install -e .`)

**AWS credential errors**: Verify `~/.aws/credentials` or environment variables are set

**Test failures**: Check AWS_TEST_BUCKET is set for integration tests

**Sandbox errors**: Verify kernel support (Linux 5.13+ for Landlock) or install Bubblewrap

### Debug Mode

Enable debug logging:

```bash
export LOG_LEVEL=DEBUG
python -m aws_mcp_server
```
