"""Regex-based detection of outdated cryptographic algorithms."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..config import Config
from ..models import Finding, FindingType

_SKIP_FILENAMES = frozenset({
    "package.json", "pom.xml", "build.gradle", "Makefile",
    "Dockerfile", ".gitignore", "requirements.txt", "pyproject.toml",
    "tsconfig.json", "webpack.config", ".eslintrc",
})

_AES = "AES-256-GCM"

# Each entry: (compiled regex, algorithm label, suggested replacement)
_RULES: list[tuple[re.Pattern[str], str, str]] = [
    # DES — must not match 'des' inside longer words like 'deserialize', 'describe', 'desktop'
    (
        re.compile(
            r'(?<![a-zA-Z])'
            r'(?:DES\.new|DESKeySpec|DES/|"DES"'
            r"|'des(?:-cbc|-ede|-ofb|-cfb)?'|des-cbc"
            r')',
            re.IGNORECASE,
        ),
        "DES",
        _AES,
    ),
    # Triple-DES / 3DES / DESede
    (
        re.compile(
            r'(?:'
            r'DES3\.new|TripleDES|DESede'
            r'|"DESede(?:/[^"]+)?"|"3DES"'
            r"|'des3'|'des-ede3(?:-cbc|-ofb|-cfb)?'"
            r'|3DES'
            r')',
            re.IGNORECASE,
        ),
        "3DES",
        _AES,
    ),
    # RC4 / ARC4
    (
        re.compile(
            r'(?:'
            r'ARC4\.new|RC4\.new'
            r"|\"RC4\"|'rc4'"
            r'|SecretKeySpec\([^,]+,\s*"RC4"\)'
            r')',
            re.IGNORECASE,
        ),
        "RC4",
        f"ChaCha20-Poly1305 or {_AES}",
    ),
    # RC2
    (
        re.compile(
            r'(?:'
            r"\"RC2\"|'rc2(?:-cbc|-ofb|-cfb)?'"
            r'|SecretKeySpec\([^,]+,\s*"RC2"\)'
            r')',
            re.IGNORECASE,
        ),
        "RC2",
        _AES,
    ),
    # MD5
    (
        re.compile(
            r'(?:'
            r'hashlib\.md5\b'
            r'|MD5\.new\b'
            r"|\"MD5\"|'md5'"
            r'|md5\s*\('
            r')',
            re.IGNORECASE,
        ),
        "MD5",
        "SHA-256 or bcrypt/argon2 for passwords",
    ),
    # SHA-1
    (
        re.compile(
            r'(?:'
            r'hashlib\.sha1\b'
            r'|SHA1\.new\b'
            r"|\"SHA-?1\"|'sha-?1'"
            r')',
            re.IGNORECASE,
        ),
        "SHA-1",
        "SHA-256 or SHA-512",
    ),
    # Blowfish
    (
        re.compile(
            r'(?:'
            r'Blowfish\.new\b'
            r'|"Blowfish"'
            r"|'bf(?:-cbc|-ofb|-cfb)?'"
            r'|SecretKeySpec\([^,]+,\s*"Blowfish"\)'
            r')',
            re.IGNORECASE,
        ),
        "Blowfish",
        _AES,
    ),
]


@dataclass
class _FileCtx:
    file_path: str
    lines: list[str]
    score: float
    commit_sha: str | None


@dataclass
class _MatchCtx:
    algo: str
    replacement: str
    file_path: str
    line_number: int
    line: str
    score: float
    commit_sha: str | None


def _explanation(algo: str, replacement: str) -> str:
    return (
        f"{algo} is an outdated/deprecated cryptographic algorithm. "
        f"Replace it with {replacement}, or inject the algorithm via environment "
        f"configuration so it can be upgraded without code changes."
    )


def _make_finding(ctx: _MatchCtx) -> Finding:
    return Finding(
        finding_type=FindingType.OUTDATED_ALGORITHM,
        description=f"Outdated cryptographic algorithm: {ctx.algo}",
        file_path=ctx.file_path,
        line_number=ctx.line_number,
        score=ctx.score,
        snippet=f"{ctx.line_number:>4} | {ctx.line}",
        explanation=_explanation(ctx.algo, ctx.replacement),
        commit_sha=ctx.commit_sha,
    )


def _scan_rule(fctx: _FileCtx, pattern: re.Pattern[str], algo: str, replacement: str) -> list[Finding]:
    results = []
    for lineno, line in enumerate(fctx.lines, start=1):
        if pattern.search(line):
            mctx = _MatchCtx(algo, replacement, fctx.file_path, lineno, line, fctx.score, fctx.commit_sha)
            results.append(_make_finding(mctx))
    return results


def scan_for_outdated_crypto(
    content: str,
    file_path: str,
    config: Config,
    commit_sha: str | None = None,
) -> list[Finding]:
    """Detect usage of known outdated cryptographic algorithms via regex."""
    if not config.scoring.outdated_crypto:
        return []
    if any(file_path.endswith(name) for name in _SKIP_FILENAMES):
        return []

    fctx = _FileCtx(file_path, content.splitlines(), config.scoring.outdated_crypto, commit_sha)
    findings: list[Finding] = []
    for pattern, algo, replacement in _RULES:
        findings.extend(_scan_rule(fctx, pattern, algo, replacement))
    return findings
