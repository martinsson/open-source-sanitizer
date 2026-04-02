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
        "--llm",
        action="store_true",
        help="Enable LLM-based sensitive algorithm detection (disabled by default).",
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
    parser.add_argument(
        "--allowlist",
        help="Path to public domains allowlist YAML (default: bundled file).",
        default=None,
    )
    parser.add_argument(
        "--blacklist",
        help="Path to internal domains blacklist YAML.",
        default=None,
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

    # LLM scanner is off by default; only enable when explicitly requested
    if not args.llm:
        config.scoring.sensitive_algorithm = 0.0

    # Load allowlist and blacklist
    tool_dir = Path(__file__).resolve().parent.parent.parent
    allowlist_path = Path(args.allowlist) if args.allowlist else tool_dir / "public_domains_allowlist.yaml"
    blacklist_path = Path(args.blacklist) if args.blacklist else tool_dir / "internal_domains_blacklist.yaml"
    config.load_allowlist(allowlist_path)
    config.load_blacklist(blacklist_path)

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
        Path(args.output).write_text(markdown, encoding="utf-8")
        console.print(f"[green]Report written to {args.output}[/green]")
    else:
        # Write to stdout as UTF-8 (Windows defaults to cp1252)
        sys.stdout.buffer.write(markdown.encode("utf-8"))
        sys.stdout.buffer.write(b"\n")

    # Print summary to stderr
    console.print(f"\n[bold]Findings:[/bold] {len(report.findings)}")
    console.print(f"[bold]Total risk score:[/bold] {report.total_score:.1f}")

    return 0 if len(report.findings) == 0 else 2


def _print_sample_config():
    """Print a sample YAML configuration file."""
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
            "url_allowlist": config.patterns.url_allowlist[:4],  # Just the core ones
            "skip_extensions": [".png", ".jpg", ".zip", ".lock"],
            "skip_paths": [".git/", "node_modules/", "__pycache__/"],
        },
        "max_file_size_kb": config.max_file_size_kb,
    }
    import yaml
    print("# oss-sanitizer configuration")
    print("# Save as oss-sanitizer.yaml and pass with -c flag")
    print()
    print(yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True), end="")


if __name__ == "__main__":
    sys.exit(main())
