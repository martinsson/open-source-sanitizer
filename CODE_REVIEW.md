# Code Review — 2026-04-01

## Critical

### C1: LLM provider polymorphism
**Location:** `scanners/algorithms.py:50-81`
**Issue:** Two separate code paths for Anthropic vs OpenAI-compatible.
**Analysis:** Disagree with "remove one provider" — user explicitly asked for both. But the branching is awkward. Since both are configured via `base_url`/`api_key`/`model`, we could route everything through the OpenAI client (Anthropic has an OpenAI-compatible proxy). Alternatively, keep both but accept it as intentional dual-provider support — it's 30 lines, not an abstraction layer.
**Action:** Keep as-is. The complexity is bounded and intentional.

### C2: Hand-rolled XML parser fragility
**Location:** `scanners/urls.py:53-118`
**Issue:** Regex-based tag stack can silently corrupt on malformed XML.
**Analysis:** Valid concern. Already addressed in PLAN.md Step 2 (PomModel replaces this with proper ET parsing).
**Action:** Deferred to PomModel refactoring.

### C3: Hostname pattern dedup bug
**Location:** `scanners/urls.py:218-253`
**Issue:** Two patterns matching same text at same position both get added.
**Analysis:** Legitimate. Easy fix: deduplicate by `(start, text)` after overlap filtering.
**Action:** Fix now.

## Important

### I1: Config setattr merging
**Location:** `config.py:114-135`
**Issue:** Typos in YAML silently add bogus attributes via `setattr()`.
**Analysis:** Real risk. Simple fix: validate keys against dataclass fields.
**Action:** Fix now.

### I2: Encoding detection (non-UTF-8 files)
**Location:** `scanner.py:29-37`
**Issue:** Only UTF-8 and Latin-1 fallback. Windows CP-1252 or other encodings silently skipped.
**Analysis:** `charset-normalizer` is already a transitive dep of `requests`. Low cost to add.
**Action:** Defer — low priority vs false positive reduction.

### I3: Commit sort order not guaranteed
**Location:** `scanner.py:105-122`
**Issue:** Comment says "newest-first" but `iter_commits` order isn't contractual.
**Analysis:** Easy one-liner fix.
**Action:** Fix now.

### I4: Secret pattern false positives
**Location:** `scanners/secrets.py:24-45`
**Issue:** Loose patterns like `password="developer"` will fire. High false positive rate.
**Analysis:** Valid but lower priority than hostname false positives. Can add entropy checks later.
**Action:** Defer.

### I5: Dependency scope filtering
**Location:** `scanners/dependencies.py:158-223`
**Issue:** `test` and `provided` scope deps flagged same as `compile`.
**Analysis:** Good catch. Should lower score for non-shipping scopes rather than skip.
**Action:** Fix now — mark scope in report, reduce score for test/provided.

## Minor

### M3: Unused detect-secrets dependency
**Action:** Remove from pyproject.toml.

### M5: YAML encoding — use utf-8-sig for BOM handling
**Action:** Fix now.

### M6: Timestamp should include seconds
**Action:** Fix now.

### M7: Skip comment lines in .env/.properties
**Action:** Fix now.

### N3: --generate-config double-escaping
**Action:** Fix now.

## Hostname False Positives (from real scan)

The real scan of `urbafc-commun` shows massive hostname false positives:
- `ci-dessous` — French text "ci-dessous" (meaning "below") matches `ci-*` pattern
- `ci-base-jobs.yml` — CI filename, not a hostname
- `mapstruct-test` — Maven module name
- `api-cas-general.png` — image filename
- `api-rejeu.png` — image filename
- `jenkins-env.png`, `jenkins-release.png` — image filenames
- `git-release` — anchor in asciidoc
- `process-test-classes`, `test-jar`, `integration-test` — Maven lifecycle phases
- `app-utils.version` — Maven property name
- `gina-dev` — keystore filename reference

These are all matching the pattern `\b(?:srv|server|db|app|web|api|proxy|...)[-_][a-zA-Z0-9]...`
because words like `api`, `app`, `ci`, `git`, `jenkins`, `test` are in the prefix list.

**Root cause:** The hostname prefix list is too broad. Words like `api`, `app`, `ci`, `git` appear
constantly in source code in non-hostname contexts (filenames, Maven phases, French text, anchors).
