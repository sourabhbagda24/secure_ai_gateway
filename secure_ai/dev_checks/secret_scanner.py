"""Find hard-coded secrets in source files."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("llm_api_key", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_\-]{20,}")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("hardcoded_credential", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*['\"][^'\"\s]{8,}['\"]")),
]
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".pytest_cache"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".zip", ".pyc", ".pdf", ".db"}
IGNORE_MARKER = "secret-scan: ignore"


@dataclass
class SecretFinding:
    path: str
    line: int
    kind: str


def scan_text(text: str, path: str = "<text>") -> list[SecretFinding]:
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if IGNORE_MARKER in line:
            continue
        for kind, rx in _PATTERNS:
            if rx.search(line):
                out.append(SecretFinding(path, n, kind))
    return out


def scan_path(root, exclude: tuple[str, ...] = ()) -> list[SecretFinding]:
    root = Path(root)
    findings = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix.lower() in SKIP_SUFFIXES:
            continue
        rel = p.relative_to(root)
        if set(rel.parts) & SKIP_DIRS or any(rel.parts[0] == e for e in exclude):
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        findings += scan_text(text, str(rel))
    return findings
