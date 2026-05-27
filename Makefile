.PHONY: install test lint typecheck clean precommit

install:
	pip install -e ".[dev]"
	pre-commit install

test:
	python -m pytest tests/ -v --cov=promptarmor --cov-report=term-missing

lint:
	ruff check .

lint-fix:
	ruff check --fix .

typecheck:
	mypy src/promptarmor/

precommit:
	pre-commit run --all-files

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov dist build *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

all: install lint typecheck test
