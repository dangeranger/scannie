# List available project tasks.
default:
    @just --list

# Run Ruff lint checks.
lint:
    uv run ruff check .

# Format Python files with Ruff.
format:
    uv run ruff format .

# Check Python formatting without changing files.
format-check:
    uv run ruff format --check .

# Apply safe Ruff lint fixes and format Python files.
fix:
    uv run ruff check --fix .
    uv run ruff format .

# Typecheck source and tests with ty.
typecheck:
    uv run ty check src tests

# Run the test suite.
test:
    uv run pytest

# Run the full local quality gate.
check: format-check lint typecheck test

# Install git pre-commit hooks.
hooks-install:
    uv run pre-commit install

# Run all configured pre-commit hooks against the repository.
hooks-run:
    uv run pre-commit run --all-files
