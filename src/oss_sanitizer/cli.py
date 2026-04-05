"""CLI entry point for oss-sanitizer."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn

from .cli_args import build_parser, print_sample_config
from .config import Config
from .report import render_markdown
from .scanner import scan

console = Console(stderr=True)

LLM_DISABLED_SCORE = 0.0  # noqa: WPS358
PROGRESS_ITEM_TRUNCATE = 50


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.generate_config:
        print_sample_config()
        return 0

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    config = _load_config(args)

    repo_path = Path(args.repo).resolve()
    if not (repo_path / ".git").exists():
        console.print(f"[red]Error:[/red] {repo_path} is not a Git repository.")
        return 1

    report = _run_scan_with_progress(repo_path, config)
    markdown = render_markdown(report)
    _write_output(markdown, args)

    console.print(f"\n[bold]Findings:[/bold] {len(report.findings)}")
    console.print(f"[bold]Total risk score:[/bold] {report.total_score:.1f}")
    return 0 if len(report.findings) == 0 else 2


def _load_config(args) -> Config:
    config = Config.from_yaml(Path(args.config)) if args.config else Config()
    if args.history:
        config.scan_history = True
    if not args.llm:
        config.scoring.sensitive_algorithm = LLM_DISABLED_SCORE
    tool_dir = Path(__file__).resolve().parent.parent.parent
    allowlist_path = Path(args.allowlist) if args.allowlist else tool_dir / "public_domains_allowlist.yaml"
    blacklist_path = Path(args.blacklist) if args.blacklist else tool_dir / "internal_domains_blacklist.yaml"
    config.load_allowlist(allowlist_path)
    config.load_blacklist(blacklist_path)
    return config


def _run_scan_with_progress(repo_path, config):
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("Scanning...", total=None)

        def on_progress(current: int, total: int, item: str):
            progress.update(task_id, total=total, completed=current, description=f"Scanning: {item[:PROGRESS_ITEM_TRUNCATE]}")

        return scan(repo_path, config, progress_callback=on_progress)


def _write_output(markdown: str, args) -> None:
    if args.output:
        Path(args.output).write_text(markdown, encoding="utf-8")
        console.print(f"[green]Report written to {args.output}[/green]")
    else:
        sys.stdout.buffer.write(markdown.encode("utf-8"))
        sys.stdout.buffer.write(b"\n")


if __name__ == "__main__":
    sys.exit(main())
