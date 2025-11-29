# Contributing to AWS MCP Server

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/aws-mcp-server.git`
3. Set up development environment - see [Development Guide](docs/DEVELOPMENT.md)

## Making Changes

### Before You Start

- Check existing [issues](https://github.com/alexei-led/aws-mcp-server/issues) for related work
- For major changes, open an issue first to discuss

### Code Style

- **Formatting**: `ruff format src/ tests/`
- **Linting**: `ruff check src/ tests/`
- **Type hints**: Use native Python types (`list[str]` not `List[str]`)
- **Docstrings**: Google style

### Running Tests

```bash
# Unit tests
make test

# All tests including integration
make test-all

# With coverage
make test-coverage
```

### Commit Messages

- Use present tense: "Add feature" not "Added feature"
- Be concise but descriptive
- Reference issues: "Fix timeout handling (#123)"

## Pull Request Process

1. **Branch**: Create from `main`
2. **Test**: Ensure all tests pass
3. **Lint**: Run `make lint` - must be clean
4. **Document**: Update docs if behavior changes
5. **PR Description**: Explain what and why

### PR Checklist

- [ ] Tests pass (`make test`)
- [ ] Linting passes (`make lint`)
- [ ] Documentation updated (if applicable)
- [ ] Commit messages are clear

## Types of Contributions

### Bug Reports

Open an issue with:

- Steps to reproduce
- Expected vs actual behavior
- Environment (OS, Python version, Docker version)

### Feature Requests

Open an issue describing:

- Use case
- Proposed solution
- Alternatives considered

### Code Contributions

- Bug fixes
- New features (discuss first)
- Test improvements
- Documentation improvements

### Documentation

- Fix typos or unclear explanations
- Add examples
- Improve guides

## Questions?

Open a [discussion](https://github.com/alexei-led/aws-mcp-server/discussions) or issue.
