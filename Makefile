# Charter developer tasks. Run `make help` for the list.

.DEFAULT_GOAL := help

.PHONY: help build test lint crd docs docs-serve docs-clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

build: ## Build the controller
	cargo build --locked

test: ## Run unit tests
	cargo test --locked

lint: ## Format check and clippy, as in CI
	cargo fmt --check
	cargo clippy --all-targets --locked -- -D warnings

crd: ## Regenerate deploy/crd.yaml from src/crd.rs
	cargo run --locked -q -- crd > deploy/crd.yaml

docs: ## Build the documentation site into docs/site (strict)
	@command -v poetry >/dev/null 2>&1 || { echo "Poetry not found: https://python-poetry.org/docs/#installation"; exit 1; }
	cd docs && poetry install --no-interaction --quiet --no-root
	cd docs && poetry run mkdocs build

docs-serve: ## Serve the docs with live reload on http://127.0.0.1:8000
	@command -v poetry >/dev/null 2>&1 || { echo "Poetry not found: https://python-poetry.org/docs/#installation"; exit 1; }
	cd docs && poetry install --no-interaction --quiet --no-root
	cd docs && poetry run mkdocs serve --livereload

docs-clean: ## Remove docs build output and virtualenv
	rm -rf docs/site docs/.venv
