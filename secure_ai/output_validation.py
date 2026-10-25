"""Output validation: leak detection, exfil stripping, citation grounding,
PII/secret filtering and safe rendering. LLM output is UNTRUSTED input to the next system."""
from __future__ import annotations

import html
import re
from dataclasses import dataclass, field

from .pii_filter import redact

_EXFIL_IMG = re.compile(r"!\[[^\]]*\]\(\s*https?://[^)\s]+\s*\)")
_CITATION = re.compile(r"\[doc:([\w\-]+)\]")
_DANGEROUS = [
    ("script_tag", re.compile(r"<\s*script\b", re.I)),
    ("javascript_uri", re.compile(r"javascript\s*:", re.I)),
    ("inline_event_handler", re.compile(r"\bon\w+\s*=", re.I)),
    ("shell_pipe_download", re.compile(r"(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh", re.I)),
    ("destructive_shell", re.compile(r"\brm\s+-rf\b", re.I)),
    ("destructive_sql", re.compile(r"\bdrop\s+table\b", re.I)),
]


@dataclass
class OutputResult:
    text: str
    blocked: bool = False
    reason: str | None = None
    findings: list[str] = field(default_factory=list)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def detect_prompt_leak(text: str, canary: str, system_prompt: str) -> bool:
    n = _norm(text)
    if canary and _norm(canary) in n:
        return True
    return any(len(line.strip()) >= 30 and _norm(line) in n for line in system_prompt.splitlines())


def validate_output(text: str, *, canary: str, system_prompt: str, max_chars: int,
                    render_html: bool = False, retrieved_ids: set[str] | None = None,
                    tool_used: bool = False) -> OutputResult:
    findings: list[str] = []
    if detect_prompt_leak(text, canary, system_prompt):                 # LLM07
        return OutputResult("", True, "system_prompt_leak", ["system_prompt_leak"])

    findings += [f"dangerous:{name}" for name, rx in _DANGEROUS if rx.search(text)]

    if _EXFIL_IMG.search(text):                                          # zero-click exfiltration
        text = _EXFIL_IMG.sub("[external image removed]", text)
        findings.append("external_image_removed")

    if retrieved_ids is not None:                                        # LLM09 misinformation
        cited = set(_CITATION.findall(text))
        unknown = cited - retrieved_ids
        if unknown:
            text = _CITATION.sub(lambda m: m.group() if m.group(1) in retrieved_ids else "", text)
            text += "\n(Note: some citations could not be verified and were removed.)"
            findings.append("unverified_citation")
        elif retrieved_ids and not cited and not tool_used:
            text += "\n(Note: this answer is not tied to a source document; please verify.)"
            findings.append("ungrounded_answer")

    red = redact(text)                                                   # LLM02
    text = red.text
    findings += [f"output_redacted:{k}" for k in sorted(red.findings)]

    if render_html:                                                      # LLM05
        text = html.escape(text, quote=True)
    if len(text) > max_chars:
        text = text[:max_chars] + "...[truncated]"
        findings.append("truncated")
    return OutputResult(text, False, None, findings)
