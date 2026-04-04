"""Argument parser and sample config printer for oss-sanitizer CLI."""

from __future__ import annotations

import argparse

from .config import Config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oss-sanitizer",
        description="Scan a Git repository for compliance with the Geneva Open Source Charter.",
    )
    parser.add_argument("repo", help="Path to the Git repository to scan.")
    parser.add_argument("-c", "--config", help="Path to YAML configuration file.", default=None)
    parser.add_argument("--history", action="store_true", help="Scan the full git history (unique blobs).")
    parser.add_argument("-o", "--output", help="Output file for the Markdown report (default: stdout).", default=None)
    parser.add_argument("--llm", action="store_true", help="Enable LLM-based sensitive algorithm detection (disabled by default).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument("--generate-config", action="store_true", help="Print a sample YAML configuration and exit.")
    parser.add_argument("--allowlist", help="Path to public domains allowlist YAML (default: bundled file).", default=None)
    parser.add_argument("--blacklist", help="Path to internal domains blacklist YAML.", default=None)
    return parser


def print_sample_config() -> None:
    """Print a sample YAML configuration file."""
    import yaml
    config = Config()
    data = {
        "llm": {
            "base_url": config.llm.base_url,
            "api_key": config.llm.api_key,
            "model": config.llm.model,
            "max_tokens": config.llm.max_tokens,
            "temperature": config.llm.temperature,
        },
        "scoring": {
            "secret": config.scoring.secret,
            "internal_url": config.scoring.internal_url,
            "internal_hostname": config.scoring.internal_hostname,
            "sensitive_algorithm": config.scoring.sensitive_algorithm,
        },
        "patterns": {
            "internal_url_domains": config.patterns.internal_url_domains,
            "hostname_patterns": config.patterns.hostname_patterns,
            "url_allowlist": config.patterns.url_allowlist[:4],
            "skip_extensions": [".png", ".jpg", ".zip", ".lock"],
            "skip_paths": [".git/", "node_modules/", "__pycache__/"],
        },
        "max_file_size_kb": config.max_file_size_kb,
    }
    print("# oss-sanitizer configuration")
    print("# Save as oss-sanitizer.yaml and pass with -c flag")
    print()
    print(yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True), end="")
