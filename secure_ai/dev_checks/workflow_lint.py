"""Tiny CI/CD (GitHub Actions) linter for the classic pipeline mistakes."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .secret_scanner import scan_text


@dataclass
class WorkflowFinding:
    level: str      # error | warning
    message: str
    line: int = 0


def lint_workflow(text: str) -> list[WorkflowFinding]:
    out: list[WorkflowFinding] = []
    lines = text.splitlines()
    if not re.search(r"^permissions\s*:", text, re.M):
        out.append(WorkflowFinding("error", "no top-level 'permissions:' (token defaults may be too broad)"))
    for n, line in enumerate(lines, 1):
        if "pull_request_target" in line and not line.strip().startswith("#"):
            out.append(WorkflowFinding("error", "pull_request_target runs with secrets on untrusted PR code", n))
        m = re.search(r"uses:\s*([\w.\-]+/[\w.\-/]+)@(\S+)", line)
        if m and not re.fullmatch(r"[0-9a-f]{40}", m.group(2)):
            out.append(WorkflowFinding("warning", f"action '{m.group(1)}@{m.group(2)}' not pinned to a commit SHA", n))
        if re.search(r"(curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh", line):
            out.append(WorkflowFinding("error", "pipes a download straight into a shell", n))
        if re.search(r"\$\{\{\s*github\.event\.[^}]*(title|body|head_ref|message|comment)", line):
            out.append(WorkflowFinding("warning", "untrusted event data in a step - pass it via env, not inline", n))
    out += [WorkflowFinding("error", f"hard-coded secret ({f.kind})", f.line) for f in scan_text(text)]
    return out
