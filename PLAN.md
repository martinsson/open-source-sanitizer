# Refactoring Plan: PomModel, Context Scoring, Templating, Tests

## Context

Code review identified 4 improvements. Two modules (`urls.py` and `dependencies.py`) independently parse/understand POM files. The XML scoring logic in `urls.py` applies Maven-specific heuristics to all XML files, which is wrong. The report uses verbose `lines.append`. There are no tests despite manual test scenarios existing.

The `PomModel` is the keystone: it unifies POM knowledge, is consumed by both dependency analysis and URL/hostname scoring, and makes the "package descriptor, not XML" distinction natural.

---

## Execution Order

### Step 1: Golden Master Tests (safety net)

**New files:**
- `tests/fixtures/sample_app.py` — Python file with secrets, internal URL, hostname, tax function
- `tests/fixtures/sample_pom.xml` — POM with internal deps, external deps, own module, properties with URL/hostname, repository URL
- `tests/test_scanners_golden.py` — approval tests for `secrets.scan_content()`, `urls.scan_content()` (both .py and pom.xml inputs), `dependencies.parse_pom()`
- `tests/test_report_golden.py` — full report golden master
- `tests/conftest.py` — shared Config fixture, `FIXTURES` path

**Approach:** Run each scanner on fixtures, serialize with `dataclasses.asdict()` to JSON, save as `expected_*.json`. Tests compare actual vs expected. Add `--update-golden` via a conftest flag for regeneration.

**Modify:** `pyproject.toml` — add `pytest>=7.0` as dev dependency.

---

### Step 2: PomModel (shared structured POM representation)

**New file:** `src/oss_sanitizer/scanners/pom_model.py`

```
SectionRole(Enum): SKIP, HIGH, MEDIUM, DEFAULT

PomSection: tag_path, line_start, line_end, role

PomDependency: group_id, artifact_id, version, scope, line_number

PomModel:
  - path, group_id, artifact_id, version
  - parent_group_id, parent_artifact_id, parent_version
  - properties: dict[str, str]
  - dependencies: list[PomDependency]
  - sections: list[PomSection]
  - score_factor_for_line(line_number) -> float | None
  - resolve_property(value) -> str | None
```

**Two-pass parsing** (merges existing approaches):
1. `xml.etree.ElementTree` — extract structure (deps, parent, properties, groupId)
2. Regex line walk — build `PomSection` list with line ranges and roles

**Role mapping** (moves from `urls.py` constants into `pom_model.py`):
- SKIP: `dependency`, `dependencies`, `parent`, `exclusion` + leaf tags (groupId, artifactId, version, scope, etc.)
- HIGH: `repository`, `snapshotRepository`, `distributionManagement`, `scm`, `ciManagement`
- MEDIUM: `properties`, `configuration`, `profile`, `build`, `plugin`
- DEFAULT: everything else

**Protocol for future Gradle support:**
```python
class DescriptorModel(Protocol):
    path: str
    def score_factor_for_line(self, line_number: int) -> float | None: ...
```

**Modify `dependencies.py`:** `parse_pom()` delegates to `PomModel`; `find_internal_dependencies()` first pass uses `model.group_id` / `model.parent_group_id` instead of re-parsing.

**Modify `urls.py`:** Replace `_build_xml_score_map()` with `model.score_factor_for_line()`. Add optional `descriptor_model` param to `scan_content()` but also auto-construct when detecting POM files.

**Verify:** Golden master tests still pass.

---

### Step 3: Package Descriptor Context (not XML)

**Modify `urls.py`:**
- Replace `_is_xml_file()` with `_is_package_descriptor()` — checks `basename == "pom.xml"` (not extension)
- Remove all `_XML_*` constants (now in `pom_model.py`)
- Generic `.xml`, `.xsd`, `.wsdl` files get full score (1.0) — the intended correction
- Update explanation strings: "XML context" → "POM context"

**Add test:** `tests/fixtures/sample_config.xml` — a generic Spring XML config with an internal URL, verify it gets full score (not reduced).

**Behavioral change:** Generic XML files go from 0.5 to 1.0 scoring. This is intentional and correct.

---

### Step 4: Jinja2 Templating

**Add dependency:** `jinja2>=3.1` in `pyproject.toml`

**New files:**
- `src/oss_sanitizer/templates/report.md.j2` — main report template with `summary_table` macro
- `src/oss_sanitizer/templates/dependencies.md.j2` — internal dependencies section

**Modify `report.py`:** Replace `lines.append` body with:
```python
env = Environment(loader=PackageLoader("oss_sanitizer", "templates"), ...)
template = env.get_template("report.md.j2")
return template.render(report=report, grouped=grouped, ...)
```

**Modify `dependencies.py`:** Remove `render_dependency_report()` — template handles it.

**Verify:** Report golden master test catches any whitespace differences. Expect a few iterations to match exactly.

---

### TODO: Make --no-llm the default

Currently the tool tries to contact an LLM by default. `--no-llm` should be the default behavior, with an explicit `--llm` flag to opt in. This avoids surprising failures when no LLM is configured.

---

## Verification

After each step:
1. `uv run pytest tests/` — all golden master tests pass
2. `uv run oss-sanitizer /tmp/test-repo --no-llm` — manual smoke test
3. Commit

After all steps:
- Run on sample Maven project to verify POM scoring + dependency detection
- Run on non-POM XML file to verify full scoring (no more reduced factor)
- Compare final report output with pre-refactoring output

## Files Summary

| New | Modified |
|-----|----------|
| `src/oss_sanitizer/scanners/pom_model.py` | `src/oss_sanitizer/scanners/urls.py` |
| `src/oss_sanitizer/templates/report.md.j2` | `src/oss_sanitizer/scanners/dependencies.py` |
| `src/oss_sanitizer/templates/dependencies.md.j2` | `src/oss_sanitizer/report.py` |
| `tests/test_scanners_golden.py` | `pyproject.toml` |
| `tests/test_report_golden.py` | |
| `tests/conftest.py` | |
| `tests/fixtures/*` (6-8 files) | |
