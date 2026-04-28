# Development Guidelines

## Code Quality

Code style and design quality are enforced by **flake8**. It is enforce by a commit hook

## Test-Driven Workflow

Before modifying any code, agents must first design the tests that will verify the change. This means:

1. Write or update tests to cover the intended behavior.
2. Confirm the tests fail for the right reason before implementing.
3. Implement the code change.
4. Confirm all tests pass.

**Total test coverage is expected.** Every code path should be exercised by the test suite.

If any code is found to be untested, **do not silently ignore it** — report it to the user and wait for a decision before proceeding.
