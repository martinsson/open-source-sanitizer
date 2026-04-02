# oss-sanitizer

[![CI](https://github.com/republique-et-canton-de-geneve/open-source-sanitizer/actions/workflows/ci.yml/badge.svg)](https://github.com/republique-et-canton-de-geneve/open-source-sanitizer/actions/workflows/ci.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=republique-et-canton-de-geneve_open-source-sanitizer&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=republique-et-canton-de-geneve_open-source-sanitizer)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Source code compliance scanner for the [Geneva Open Source Charter](https://github.com/republique-et-canton-de-geneve/strategie-open-source/blob/main/charte_open_source.md).

Scans a Git repository before open-source publication and reports:

- **Secrets & credentials** — API keys, tokens, passwords, private keys (via [detect-secrets](https://github.com/Yelp/detect-secrets))
- **Internal URLs** — references to `*.etat-ge.ch`, `*.ge.ch`, and similar domains
- **Internal hostnames** — server names, environment-suffixed names (`myapp-prod`), private IP ranges
- **Internal Maven dependencies** — `ch.ge.*` / `ch.etat-ge.*` group IDs that are external to the scanned project
- **Sensitive government algorithms** — optional LLM-based review for tax, benefit, or permit logic

---

## Requirements

- Python 3.11 or later
- [Git](https://git-scm.com/) (the repository being scanned must be a Git repo)

---

## Installation

The recommended way is [uv](https://docs.astral.sh/uv/), a fast Python package manager:

```bash
# Install uv (see https://docs.astral.sh/uv/getting-started/installation/)
# macOS / Linux:
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell):
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Then install oss-sanitizer:
uv tool install git+https://github.com/republique-et-canton-de-geneve/open-source-sanitizer
```

Alternatively, with plain pip:

```bash
pip install git+https://github.com/republique-et-canton-de-geneve/open-source-sanitizer
```

---

## Usage

```bash
# Scan a repository (working tree only)
oss-sanitizer /path/to/repo

# Scan including full git history (unique blobs)
oss-sanitizer /path/to/repo --history

# Write the report to a file instead of stdout
oss-sanitizer /path/to/repo -o report.md

# Enable LLM-based sensitive algorithm detection (off by default)
oss-sanitizer /path/to/repo --llm -c oss-sanitizer.yaml

# Use a custom configuration file
oss-sanitizer /path/to/repo -c oss-sanitizer.yaml

# Print a sample configuration and exit
oss-sanitizer /path/to/repo --generate-config
```

The tool exits with code `0` when no findings are detected, and `2` when findings exist — useful for CI pipelines.

---

## Windows notes

The report contains Unicode characters. If the output looks garbled in PowerShell or Command Prompt, force UTF-8 encoding before running:

**PowerShell:**
```powershell
$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8
oss-sanitizer C:\path\to\repo -o report.md
```

**Command Prompt:**
```cmd
chcp 65001
oss-sanitizer C:\path\to\repo -o report.md
```

Writing to a file (`-o report.md`) avoids the encoding issue entirely and is the recommended approach on Windows.

> **Tip:** PowerShell 7+ (`pwsh`) handles UTF-8 correctly by default and is recommended over the built-in Windows PowerShell 5.

---

## Configuration

Generate a starter configuration file:

```bash
oss-sanitizer /path/to/repo --generate-config > oss-sanitizer.yaml
```

Key configuration sections:

```yaml
# LLM for sensitive algorithm detection (only used with --llm flag)
llm:
  provider: openai          # "openai" (default, also works with Ollama) or "anthropic"
  base_url: http://localhost:11434/v1   # Ollama endpoint
  api_key: unused
  model: llama3

# Scoring weights — higher = more severe in the report
scoring:
  secret: 10.0
  internal_url: 7.0
  internal_hostname: 6.0
  sensitive_algorithm: 8.0

# Detection patterns
patterns:
  internal_url_domains:
    - '\.etat-ge\.ch'
    - '\.ge\.ch'

  hostname_patterns:
    - '\bsrv[-_][a-zA-Z0-9][-a-zA-Z0-9_.]*\b'

  # Hostnames to never flag (exact substrings or regex with ^ / $)
  hostname_allowlist:
    - "^spring-boot-"
    - "-plugin$"

  # URLs to never flag
  url_allowlist:
    - 'https?://(?:www\.)?github\.com'

  skip_extensions:
    - ".png"
    - ".lock"

  skip_paths:
    - ".git/"
    - "node_modules/"
```

---

## Domain allowlist and blacklist

The repository ships a public domain allowlist (`public_domains_allowlist.yaml`) covering known public Geneva State websites (ge.ch, geneve.ch, hug.ch, unige.ch, …). These URLs are never flagged as internal.

For your organisation's actual internal domains, create a **gitignored** blacklist:

```bash
cp internal_domains_blacklist.yaml.example internal_domains_blacklist.yaml
# Edit internal_domains_blacklist.yaml with your real domains — do not commit it
```

The blacklist supports the same `internal_url_domains`, `hostname_patterns`, and `hostname_allowlist` keys as the main config.

---

## What the report looks like

The tool writes a Markdown report with:

1. A summary table (category / count / risk score)
2. Detailed findings per category with file path, line number, code snippet, and explanation
3. Internal Maven dependencies split into shipping (compile/runtime) and non-shipping (test/provided)
4. The summary table repeated at the bottom for quick reference

Exit code `2` signals findings exist, making it easy to fail a CI step:

```yaml
# GitHub Actions example
- name: OSS compliance scan
  run: oss-sanitizer . -o compliance-report.md
  # exits 2 if findings exist — adjust if you want the step to be advisory only
```

---

## LLM-based algorithm detection

Algorithm detection is **disabled by default**. Enable it with `--llm` and a config file pointing to your LLM endpoint:

```bash
# Using a local Ollama model
oss-sanitizer /path/to/repo --llm -c oss-sanitizer.yaml

# Using Anthropic
oss-sanitizer /path/to/repo --llm -c oss-sanitizer.yaml
# (set provider: anthropic and api_key in the config)
```

Tested with:
- [Ollama](https://ollama.com/) (`qwen2.5-coder:14b`, `llama3`, and others)
- Anthropic Claude (requires API key with credits)
- Any OpenAI-compatible endpoint

---

## Development

```bash
git clone https://github.com/republique-et-canton-de-geneve/open-source-sanitizer
cd open-source-sanitizer

# Install uv if needed, then:
uv sync --extra dev

# Run tests
uv run pytest

# Run with coverage
uv run pytest --cov=oss_sanitizer
```
