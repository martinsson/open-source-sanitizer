# oss-sanitizer

Source code compliance scanner for the [Geneva Open Source Charter](https://github.com/republique-et-canton-de-geneve/strategie-open-source/blob/main/charte_open_source.md).

Scans Git repositories for secrets, internal URLs, internal hostnames, and sensitive government algorithms before open-source publication.

## Installation

```bash
uv sync
```

## Usage

```bash
# Scan a repository (working tree only)
oss-sanitizer /path/to/repo

# Scan including full git history
oss-sanitizer /path/to/repo --history

# Save report to file
oss-sanitizer /path/to/repo -o report.md

# Skip LLM-based algorithm detection
oss-sanitizer /path/to/repo --no-llm

# Use custom configuration
oss-sanitizer /path/to/repo -c oss-sanitizer.yaml

# Generate a sample configuration file
oss-sanitizer --generate-config > oss-sanitizer.yaml
```
