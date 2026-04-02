"""LLM-based sensitive algorithm detection."""

from __future__ import annotations

import json
import logging

from ..config import Config
from ..models import Finding, FindingType

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are a code auditor for the Republic and Canton of Geneva (Switzerland).
Your task is to evaluate whether a source code file contains **sensitive government algorithms** —
business logic specific to government operations that could pose a risk if exposed publicly.

Examples of sensitive algorithms:
- Tax calculation formulas specific to Geneva/Switzerland
- Social benefit eligibility rules and computation
- Permit/license approval decision trees
- Voting/election counting algorithms
- Law enforcement or judicial scoring/decision logic
- Financial audit or fraud detection rules
- Citizen data processing pipelines with specific business rules

Examples of NON-sensitive code (do not flag):
- Generic utility functions (string manipulation, logging, HTTP helpers)
- Standard CRUD operations
- UI rendering code
- Open-source library wrappers
- Configuration/setup code
- Standard authentication flows (OAuth, OIDC)

Respond in JSON with exactly these fields:
{
  "is_sensitive": true/false,
  "confidence": 0.0-1.0,
  "explanation": "Brief explanation of why this code is or isn't sensitive",
  "sensitive_sections": [
    {"line_start": N, "line_end": M, "reason": "..."}
  ]
}

Only set is_sensitive=true if you have reasonable confidence the code implements
government-specific business logic, not just because it processes data.
"""


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
    else:
        from openai import OpenAI

        client = OpenAI(
            base_url=config.llm.base_url,
            api_key=config.llm.api_key,
        )
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


def scan_for_sensitive_algorithms(
    content: str,
    file_path: str,
    config: Config,
    commit_sha: str | None = None,
) -> list[Finding]:
    """Use LLM to assess if code contains sensitive government algorithms."""
    if config.scoring.sensitive_algorithm == 0.0:
        return []

    # Skip very short files
    lines = content.splitlines()
    if len(lines) < 10:
        return []

    # Skip files that are clearly not code with business logic
    skip_names = [
        "package.json", "pom.xml", "build.gradle", "Makefile",
        "Dockerfile", ".gitignore", "requirements.txt", "pyproject.toml",
        "tsconfig.json", "webpack.config", ".eslintrc",
    ]
    if any(file_path.endswith(name) for name in skip_names):
        return []

    try:
        # Truncate large files to stay within token limits
        truncated = content[:8000] if len(content) > 8000 else content
        user_message = f"File: {file_path}\n\n```\n{truncated}\n```"

        result = _call_llm(config, user_message)

    except Exception as e:
        logger.warning(f"LLM analysis failed for {file_path}: {e}")
        return []

    if not result.get("is_sensitive", False):
        return []

    confidence = result.get("confidence", 0.5)
    base_score = confidence * config.scoring.sensitive_algorithm

    findings: list[Finding] = []
    sections = result.get("sensitive_sections", [])

    if sections:
        for section in sections:
            line_start = section.get("line_start", 1)
            line_end = section.get("line_end", min(line_start + 5, len(lines)))
            snippet_lines = lines[max(0, line_start - 1):line_end]
            snippet = "\n".join(
                f"{line_start + i:>4} | {l}"
                for i, l in enumerate(snippet_lines)
            )

            findings.append(
                Finding(
                    finding_type=FindingType.SENSITIVE_ALGORITHM,
                    description=f"Potentially sensitive algorithm (confidence: {confidence:.0%})",
                    file_path=file_path,
                    line_number=line_start,
                    score=base_score,
                    snippet=snippet,
                    explanation=section.get("reason", result.get("explanation", "")),
                    commit_sha=commit_sha,
                )
            )
    else:
        # No specific sections, flag the whole file
        snippet_lines = lines[:10]
        snippet = "\n".join(
            f"{i + 1:>4} | {l}" for i, l in enumerate(snippet_lines)
        )
        if len(lines) > 10:
            snippet += f"\n     ... ({len(lines) - 10} more lines)"

        findings.append(
            Finding(
                finding_type=FindingType.SENSITIVE_ALGORITHM,
                description=f"Potentially sensitive algorithm (confidence: {confidence:.0%})",
                file_path=file_path,
                line_number=1,
                score=base_score,
                snippet=snippet,
                explanation=result.get("explanation", "LLM flagged this file as containing sensitive logic."),
                commit_sha=commit_sha,
            )
        )

    return findings
