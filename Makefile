.PHONY: help test lint format-check check

help:
	@echo "Available targets:"
	@echo "  test          Run pytest"
	@echo "  lint          Run ruff lint checks"
	@echo "  format-check  Run ruff format check"
	@echo "  check         Run all checks"

test:
	python -m pytest

lint:
	python -m ruff check .

format-check:
	python -m ruff format --check .

check: lint format-check test

