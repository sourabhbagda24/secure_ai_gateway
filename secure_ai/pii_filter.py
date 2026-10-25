"""PII + secret detection and redaction (used on input, output, logs, memory)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field


def _luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number][::-1]
    total = sum(d if i % 2 == 0 else (d * 2 - 9 if d * 2 > 9 else d * 2)
                for i, d in enumerate(digits))
    return total % 10 == 0


def _card_check(m: re.Match) -> bool:
    digits = re.sub(r"\D", "", m.group())
    return 13 <= len(digits) <= 19 and _luhn_ok(digits)


# (kind, regex, optional validator) - ORDER MATTERS (specific before generic)
_RULES: list[tuple[str, re.Pattern, object]] = [
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"), None),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), None),
    ("API_KEY", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_\-]{20,}"), None),
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}"), None),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), None),
    ("SECRET_ASSIGNMENT", re.compile(r"(?i)\b(?:api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*['\"]?[^\s'\"]{8,}"), None),
    ("CREDIT_CARD", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), _card_check),
    ("SSN", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"), None),
    ("AADHAAR", re.compile(r"(?<!\d)[2-9]\d{3}\s?\d{4}\s?\d{4}(?!\d)"), None),
    ("PAN", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), None),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None),
    ("PHONE", re.compile(r"(?<![\w])(?:\+91[\s-]?|0)?[6-9]\d{9}(?!\d)"), None),
]

SECRET_KINDS = frozenset({"PRIVATE_KEY", "AWS_ACCESS_KEY", "API_KEY", "GITHUB_TOKEN",
                          "JWT", "SECRET_ASSIGNMENT"})
SENSITIVE_ID_KINDS = frozenset({"CREDIT_CARD", "SSN", "AADHAAR", "PAN"})
ALL_KINDS = frozenset(k for k, _, _ in _RULES)


@dataclass
class RedactionResult:
    text: str
    findings: dict[str, int] = field(default_factory=dict)


def redact(text: str, kinds: frozenset[str] | set[str] | None = None) -> RedactionResult:
    kinds = ALL_KINDS if kinds is None else kinds
    findings: dict[str, int] = {}
    for kind, rx, check in _RULES:
        if kind not in kinds:
            continue

        def repl(m: re.Match, kind=kind, check=check) -> str:
            if check is not None and not check(m):
                return m.group()
            findings[kind] = findings.get(kind, 0) + 1
            return f"[REDACTED:{kind}]"

        text = rx.sub(repl, text)
    return RedactionResult(text, findings)


def find_secrets(text: str) -> list[str]:
    return sorted(redact(text, SECRET_KINDS).findings)


def has_secret(text: str) -> bool:
    return bool(find_secrets(text))
