"""CLI entry point for oss-sanitizer."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn

from .config import Config
from .scanner import scan
from .report import render_markdown

console = Console(stderr=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="oss-sanitizer",
        description="Scan a Git repository for compliance with the Geneva Open Source Charter.",
    )
    parser.add_argument(
        "repo",
        help="Path to the Git repository to scan.",
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to YAML configuration file.",
        default=None,
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="Scan the full git history (unique blobs).",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file for the Markdown report (default: stdout).",
        default=None,
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM-based sensitive algorithm detection.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )
    parser.add_argument(
        "--generate-config",
        action="store_true",
        help="Print a sample YAML configuration and exit.",
    )

    args = parser.parse_args(argv)

    if args.generate_config:
        _print_sample_config()
        return 0

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    # Load config
    if args.config:
        config = Config.from_yaml(Path(args.config))
    else:
        config = Config()

    if args.history:
        config.scan_history = True

    # Disable LLM scanner if requested
    if args.no_llm:
        # Set scoring weight to 0 so the scanner is effectively skipped
        config.scoring.sensitive_algorithm = 0.0

    repo_path = Path(args.repo).resolve()
    if not (repo_path / ".git").exists():
        console.print(f"[red]Error:[/red] {repo_path} is not a Git repository.")
        return 1

    # Run scan with progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("Scanning...", total=None)

        def on_progress(current: int, total: int, item: str):
            progress.update(task_id, total=total, completed=current, description=f"Scanning: {item[:50]}")

        report = scan(repo_path, config, progress_callback=on_progress)

    # Generate report
    markdown = render_markdown(report)

    if args.output:
        Path(args.output).write_text(markdown)
        console.print(f"[green]Report written to {args.output}[/green]")
    else:
        # Write to stdout (not stderr where Rich console goes)
        sys.stdout.write(markdown)
        sys.stdout.write("\n")

    # Print summary to stderr
    console.print(f"\n[bold]Findings:[/bold] {len(report.findings)}")
    console.print(f"[bold]Total risk score:[/bold] {report.total_score:.1f}")

    return 0 if len(report.findings) == 0 else 2


def _print_sample_config():
    print("""\
# oss-sanitizer configuration
# Save as oss-sanitizer.yaml and pass with -c flag

llm:
  base_url: "http://localhost:11434/v1"  # OpenAI-compatible endpoint
  api_key: "unused"                       # API key if required
  model: "llama3"                         # Model name
  max_tokens: 1024
  temperature: 0.1

scoring:
  secret: 10.0              # Weight for secret findings
  internal_url: 7.0         # Weight for internal URL findings
  internal_hostname: 6.0    # Weight for internal hostname findings
  sensitive_algorithm: 8.0  # Weight for sensitive algorithm findings

patterns:
  internal_url_domains:
    - "\\\\.etat-ge\\\\.ch"
    - "\\\\.ge\\\\.ch"
    - "\\\\.geneve\\\\.ch"
    - "\\\\.gva\\\\.ch"
    - "\\\\.admin\\\\.ch"

  hostname_patterns:
    - "\\\\b(?:srv|server|db|app|web|api|proxy|ldap)[-_][a-zA-Z0-9][-a-zA-Z0-9_.]*\\\\b"
    - "\\\\b[a-zA-Z]+-(?:prod|staging|dev|test|uat|preprod|int|recette)\\\\b"
    - "\\\\b(?:10|172\\\\.(?:1[6-9]|2[0-9]|3[01])|192\\\\.168)\\\\.\\\\d{1,3}\\\\.\\\\d{1,3}\\\\b"

  url_allowlist:
    - "https?://(?:www\\\\.)?github\\\\.com"
    - "https?://(?:www\\\\.)?opensource\\\\.org"
    - "https?://(?:www\\\\.)?creativecommons\\\\.org"
    - "https?://(?:www\\\\.)?apache\\\\.org"

  skip_extensions:
    - ".png"
    - ".jpg"
    - ".zip"
    - ".lock"

  skip_paths:
    - ".git/"
    - "node_modules/"
    - "__pycache__/"

max_file_size_kb: 512
""")


if __name__ == "__main__":
    sys.exit(main())
