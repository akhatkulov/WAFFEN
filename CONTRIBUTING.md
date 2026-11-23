# Contributing to WAFFEN

## Development Setup

```bash
git clone https://github.com/akhatkulov/WAFFEN.git
cd WAFFEN
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest  # all 1931+ tests should pass
```

## Running Tests

```bash
.venv/bin/pytest tests/                    # full suite (~20s)
.venv/bin/pytest tests/test_beam.py -v     # specific file
.venv/bin/pytest -k "test_name"            # specific test
.venv/bin/pytest tests/ -x                 # stop on first failure
```

## Code Style

- **stdlib-only** — no external dependencies in core (`waffen/`)
- Type hints on public functions
- Docstring on every module and class
- No comments unless the *why* is non-obvious

## Adding a Mutator

1. Create your function in `waffen/mutate/<category>.py`
2. Register it via `REGISTRY` (see existing mutators for the pattern)
3. Set `classes={"SQL Injection"}` or whichever attack class applies
4. For multi-variant mutators: set `multi=True` and implement `apply_multi()`
5. Add tests in `tests/test_<category>.py`
6. Run `pytest` — all tests must pass

## Adding a Transform

1. Add a `RequestTransform(...)` to the `TRANSFORMS` list in `waffen/core/transforms.py`
2. The `.build(target, payload)` method returns a `curl` argv list
3. Add tests verifying the argv structure

## Adding a Plugin

Plugins live in `~/.waffen/plugins/`. Scaffold one:

```bash
waffen plugin create my-bypass
```

This creates `~/.waffen/plugins/my-bypass/__init__.py` with the registration template.

## PR Process

1. Fork the repo
2. Create a feature branch from `main`
3. Write tests for your changes
4. Run the full test suite
5. Submit a PR with a clear description of what and why

## Reporting Security Issues

See [SECURITY.md](SECURITY.md) — do **not** open a public issue for security vulnerabilities.
