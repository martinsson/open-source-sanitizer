"""LLM-based sensitive algorithm detection."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from ..config import Config
from ..models import Finding, FindingType
from .algo_prompt import SYSTEM_PROMPT

logger = logging.getLogger(__name__)

MAX_LLM_CONTENT_LENGTH = 8000
MIN_FILE_LINES = 10
DEFAULT_CONFIDENCE = 0.5
WHOLE_FILE_PREVIEW_LINES = 10

_SKIP_FILENAMES = frozenset({
    "package.json", "pom.xml", "build.gradle", "Makefile",
    "Dockerfile", ".gitignore", "requirements.txt", "pyproject.toml",
    "tsconfig.json", "webpack.config", ".eslintrc",
})


@dataclass
class _AlgoContext:
    file_path: str
    base_score: float
    commit_sha: str | None
    lines: list[str]


def _call_llm(config: Config, user_message: str) -> dict:
    """Call the configured LLM provider and return parsed JSON."""
    if config.llm.provider == "anthropic":
        import anthropic
        client = anthropic.Anthropic(api_key=config.llm.api_key)
        response = client.messages.create(
            model=config.llm.model,
            max_tokens=config.llm.max_tokens,
            temperature=config.llm.temperature,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )
        return json.loads(response.content[0].text)

    from openai import OpenAI
    client = OpenAI(base_url=config.llm.base_url, api_key=config.llm.api_key)
    response = client.chat.completions.create(
        model=config.llm.model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
        max_tokens=config.llm.max_tokens,
        temperature=config.llm.temperature,
        response_format={"type": "json_object"},
    )
    return json.loads(response.choices[0].message.content)


def _should_skip_file(file_path: str, lines: list[str]) -> bool:
    return len(lines) < MIN_FILE_LINES or any(file_path.endswith(n) for n in _SKIP_FILENAMES)


def _build_section_finding(ctx: _AlgoContext, section: dict, confidence: float) -> Finding:
    line_start = section.get("line_start", 1)
    line_end = section.get("line_end", min(line_start + 5, len(ctx.lines)))
    snippet_lines = ctx.lines[max(0, line_start - 1):line_end]
    snippet = "\n".join(f"{line_start + i:>4} | {l}" for i, l in enumerate(snippet_lines))
    return Finding(
        finding_type=FindingType.SENSITIVE_ALGORITHM,
        description=f"Potentially sensitive algorithm (confidence: {confidence:.0%})",
        file_path=ctx.file_path,
        line_number=line_start,
        score=ctx.base_score,
        snippet=snippet,
        explanation=section.get("reason", ""),
        commit_sha=ctx.commit_sha,
    )


def _build_whole_file_finding(ctx: _AlgoContext, explanation: str, confidence: float) -> Finding:
    preview = ctx.lines[:WHOLE_FILE_PREVIEW_LINES]
    snippet = "\n".join(f"{i + 1:>4} | {l}" for i, l in enumerate(preview))
    if len(ctx.lines) > WHOLE_FILE_PREVIEW_LINES:
        snippet += f"\n     ... ({len(ctx.lines) - WHOLE_FILE_PREVIEW_LINES} more lines)"
    return Finding(
        finding_type=FindingType.SENSITIVE_ALGORITHM,
        description=f"Potentially sensitive algorithm (confidence: {confidence:.0%})",
        file_path=ctx.file_path,
        line_number=1,
        score=ctx.base_score,
        snippet=snippet,
        explanation=explanation or "LLM flagged this file as containing sensitive logic.",
        commit_sha=ctx.commit_sha,
    )


def _build_findings(ctx: _AlgoContext, result: dict) -> list[Finding]:
    confidence = result.get("confidence", DEFAULT_CONFIDENCE)
    sections = result.get("sensitive_sections", [])
    if sections:
        return [_build_section_finding(ctx, s, confidence) for s in sections]
    return [_build_whole_file_finding(ctx, result.get("explanation", ""), confidence)]


def _run_llm_scan(content: str, file_path: str, config: Config, commit_sha: str | None) -> list[Finding]:
    try:
        result = _call_llm(config, f"File: {file_path}\n\n```\n{content[:MAX_LLM_CONTENT_LENGTH]}\n```")
    except Exception as e:
        logger.warning(f"LLM analysis failed for {file_path}: {e}")
        return []
    if not result.get("is_sensitive", False):
        return []
    confidence = result.get("confidence", DEFAULT_CONFIDENCE)
    ctx = _AlgoContext(
        file_path=file_path,
        base_score=confidence * config.scoring.sensitive_algorithm,
        commit_sha=commit_sha,
        lines=content.splitlines(),
    )
    return _build_findings(ctx, result)


def scan_for_sensitive_algorithms(
    content: str,
    file_path: str,
    config: Config,
    commit_sha: str | None = None,
) -> list[Finding]:
    """Use LLM to assess if code contains sensitive government algorithms."""
    if not config.scoring.sensitive_algorithm or _should_skip_file(file_path, content.splitlines()):
        return []
    return _run_llm_scan(content, file_path, config, commit_sha)
