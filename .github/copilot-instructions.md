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
