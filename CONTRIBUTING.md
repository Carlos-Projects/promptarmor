# Contributing

## Development Setup

```bash
git clone https://github.com/Carlos-Projects/promptarmor.git
cd promptarmor
pip install -e ".[dev]"
```

## Workflow

1. Create a branch: `git checkout -b feature/my-feature`
2. Make your changes
3. Run checks: `ruff check . && python -m pytest tests/ -v`
4. Add tests for new functionality
5. Commit using conventional commits: `git commit -m "type(scope): description"`
6. Push and open a PR

## Before You Start

Install pre-commit hooks:

```bash
pre-commit install
```

## Quality Gates

Before submitting a PR, ensure:

- `ruff check .` — passes with no errors
- `mypy src/promptarmor/` — passes with no errors
- `python -m pytest tests/ -v --cov=promptarmor` — all tests pass, coverage ≥80%
- Tests added for new features or bug fixes
- Type hints on all public functions

## Code Style

- Line length: 120 characters
- Ruff enforces imports, naming, and formatting
- Type hints required for all public functions and methods
- Use dataclasses for data containers
- Use `make` for common commands (see [Makefile](Makefile))

## Project Structure

```
src/promptarmor/
├── cli.py                    # Typer CLI entry point
├── proxy.py                  # Starlette proxy server
├── models.py                 # Data models (dataclasses)
├── filters/                  # Security filters
│   ├── injection_detector.py # Pattern-based injection detection
│   ├── self_reflection.py    # Logical self-reflection guard
│   ├── latent_whitelist.py   # Benign latent space whitelist
│   ├── context_sanitizer.py  # Context cleaning
│   └── output_validator.py   # Response validation
├── policies/                 # Policy engine & tools
│   ├── engine.py             # Policy evaluation engine
│   ├── yaml_loader.py        # YAML policy loading
│   └── generator.py          # MCPGuard policy generation
├── adapters/                  # LLM provider adapters
│   ├── openai.py
│   ├── anthropic.py
│   ├── local_llm.py
│   └── generic.py
├── reporters/                 # Event reporters
│   ├── console.py            # Rich console output
│   ├── json.py               # JSON report generation
│   └── html.py               # HTML report generation
└── utils/
    └── crypto.py             # Hashing & fingerprinting
```

## Pull Request Process

1. Use the PR template
2. Keep PRs focused on a single change
3. Reference related issues
4. Squash commits before merging
