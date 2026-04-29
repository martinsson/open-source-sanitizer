# Copilot Instructions

## Code quality gate

After modifying any Python file under `src/`, run the quality check before considering the task complete:

```bash
uv run flake8 src/
```

The project enforces:
- Max function length: 30 lines (`CFQ001`)
- Max cognitive complexity: 10 (`CCR001`)
- Max local variables per function: 7 (`WPS210`)
- Max parameters: 4 (`WPS211`)
- Max file length: 150 lines (checked separately in `.claude/hooks/check-quality.sh`)
- Max 7 `.py` files per directory

If violations are found, fix them before finishing — extract helper functions, introduce dataclasses to bundle arguments, or split large files into sub-packages.

## Project structure

- `src/oss_sanitizer/` — main package (≤7 .py files)
- `src/oss_sanitizer/config/` — config sub-package
- `src/oss_sanitizer/scanners/` — scanner modules (≤7 .py files)
- `src/oss_sanitizer/scanners/pom/` — Maven POM parsing sub-package
- `tests/` — pytest tests

## Running tests

```bash
uv run pytest
```

All tests must pass before submitting changes.

## Code review priorities

When reviewing pull requests, focus on issues in this order:

1. **Security** — hardcoded credentials or tokens, use of `eval`/`exec` on external input, path traversal, unsafe deserialization (`pickle` without signing), missing input validation on data from external sources (files, HTTP, env vars).
2. **Correctness** — logic errors, unhandled exceptions on expected code paths, incorrect type assumptions, off-by-one, missed edge cases (empty list, `None`, zero).
3. **Test coverage** — flag any new public function or code branch that has no corresponding test. Tests live under `tests/` and use `pytest`.
4. **Complexity violations** — any function exceeding 30 lines, cognitive complexity above 10, or more than 4 parameters (these are also caught by flake8, but call them out if visible in the diff).

Do **not** comment on formatting or style issues that flake8 already enforces — those are blocked by the lint workflow.
