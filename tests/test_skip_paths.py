"""Tests for skip_paths coverage across all supported ecosystems."""

from __future__ import annotations

import pytest

from oss_sanitizer.config import Config
from oss_sanitizer.scanner_history import should_skip


def test_default_skip_paths_covers_all_ecosystems():
    config = Config()
    expected = [
        # version control
        ".git/",
        # python
        "node_modules/",
        "__pycache__/",
        ".venv/",
        "venv/",
        ".tox/",
        # java
        ".gradle/",
        ".mvn/",
        "target/",
        # php
        "vendor/",
        # js/ts
        "bower_components/",
        ".next/",
        ".nuxt/",
    ]
    for entry in expected:
        assert entry in config.patterns.skip_paths, f"Missing from skip_paths: {entry!r}"


@pytest.mark.parametrize("path,label", [
    # python
    ("venv/lib/python3.12/site-packages/requests/__init__.py", "python bare venv"),
    (".tox/py312/lib/site-packages/pytest/__init__.py",        "python tox env"),
    # java
    ("target/classes/com/example/App.class",                   "java maven output root"),
    ("module-a/target/surefire-reports/test.xml",              "java maven sub-module"),
    # js/ts
    ("bower_components/jquery/dist/jquery.js",                 "js bower packages"),
    (".next/server/app/page.js",                               "nextjs build cache"),
    (".nuxt/dist/server/index.js",                             "nuxtjs build cache"),
    # regressions — entries already present before this change
    ("node_modules/lodash/index.js",                           "js node_modules"),
    (".venv/lib/python3.12/site-packages/click/__init__.py",   "python dotted venv"),
    ("vendor/symfony/framework/Controller.php",                "php composer vendor"),
    (".gradle/caches/modules-2/files/foo.jar",                 "java gradle cache"),
    (".git/objects/pack/pack-abc.idx",                         "git objects"),
])
def test_should_skip_third_party_paths(path, label):
    assert should_skip(path, Config()), f"Expected skip for {label}: {path!r}"


@pytest.mark.parametrize("path", [
    "src/main/java/com/example/App.java",
    "src/components/EnvManager.ts",
    "docs/targets.md",
    "src/venv_bootstrap.sh",
    "app/models/vendor_invoice.py",
    "scripts/build_release.sh",
])
def test_should_not_skip_legitimate_paths(path):
    assert not should_skip(path, Config()), f"Falsely skipped: {path!r}"
