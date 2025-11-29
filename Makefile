.PHONY: help install dev-install uv-install uv-dev-install uv-update-lock test test-unit test-integration test-all test-coverage lint lint-fix format clean docker-build docker-run docker-compose docker-compose-down docker-buildx

# Default target
.DEFAULT_GOAL := help

# Python related commands (with pip)
install: ## Install the package with pip
	pip install -e .

dev-install: ## Install the package with development dependencies using pip
	pip install -e ".[dev]"

# Python related commands (with uv - recommended)
uv-install: ## Install the package with uv (creates .venv)
	uv sync --locked

uv-dev-install: ## Install with dev dependencies using uv
	uv sync --locked --all-extras --dev

uv-update-lock: ## Update the uv.lock file
	uv lock

lint: ## Run linters (ruff check and format --check)
	ruff check src/ tests/
	ruff format --check src/ tests/

lint-fix: ## Run linters and auto-fix issues where possible
	ruff check --fix src/ tests/
	ruff format src/ tests/

format: ## Format code with ruff
	ruff format src/ tests/

test: ## Run tests excluding integration tests
	python -m pytest -v -m "not integration" --cov=aws_mcp_server --cov-report=xml --cov-report=term

test-unit: ## Run unit tests only (all tests except integration tests)
	python -m pytest -v -m "not integration" --cov=aws_mcp_server --cov-report=term

test-integration: ## Run integration tests only (requires AWS credentials)
	python -m pytest -v -m integration --run-integration

test-all: ## Run all tests including integration tests
	python -m pytest -v --run-integration

test-coverage: ## Run tests with coverage report (excluding integration tests)
	python -m pytest -m "not integration" --cov=aws_mcp_server --cov-report=term-missing

test-coverage-all: ## Run all tests with coverage report (including integration tests)
	python -m pytest --run-integration --cov=aws_mcp_server --cov-report=term-missing

clean: ## Remove build artifacts and cache directories
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .coverage htmlcov/ .ruff_cache/ __pycache__/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name '*.egg-info' -exec rm -rf {} +

# Server run commands
run: ## Run server with default transport (stdio)
	python -m aws_mcp_server

run-sse: ## Run server with SSE transport
	AWS_MCP_TRANSPORT=sse python -m aws_mcp_server

run-mcp-cli: ## Run server with MCP CLI
	mcp run src/aws_mcp_server/server.py

# Get version information using setuptools_scm directly
VERSION_RAW := $(shell python -m setuptools_scm 2>/dev/null || echo "0.0.0+unknown")
# Make version Docker-compatible (replace + with -)
VERSION := $(shell echo "$(VERSION_RAW)" | tr '+' '-')

# Docker related commands
docker-build: ## Build Docker image with proper labels and args
	docker build -t aws-mcp-server:$(VERSION) -f deploy/docker/Dockerfile . \
		--build-arg BUILD_DATE=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ') \
		--build-arg VERSION=$(VERSION)

docker-run: ## Run server in Docker with AWS credentials mounted
	docker run -p 8000:8000 -v ~/.aws:/home/appuser/.aws:ro aws-mcp-server:$(VERSION)

docker-compose: ## Run server using Docker Compose
	docker-compose -f deploy/docker/docker-compose.yml up -d

docker-compose-down: ## Stop Docker Compose services
	docker-compose -f deploy/docker/docker-compose.yml down

# Multi-architecture build (requires Docker Buildx)
docker-buildx: ## Build multi-architecture Docker image
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-t aws-mcp-server:$(VERSION) \
		-f deploy/docker/Dockerfile \
		--build-arg BUILD_DATE=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ') \
		--build-arg VERSION=$(VERSION) .

# GitHub Actions local testing (requires act: https://github.com/nektos/act)
ci-local: ## Run GitHub Actions workflows locally
	act -j test

# Help command
help: ## Display this help message
	@echo "AWS MCP Server Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'