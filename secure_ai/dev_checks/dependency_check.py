"""Dependency hygiene: pinned versions + advisory matching.

The bundled advisories file is an EXAMPLE format. In real projects also run `pip-audit`
(or Dependabot / OSV-Scanner), which use live vulnerability databases."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass


@dataclass
class DepIssue:
    package: str
    level: str      # "error" | "warning"
    message: str


def _vt(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def parse_requirements(text: str):
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line and not line.startswith(("-", "http")):
            yield line


def check_requirements(text: str, advisories: dict | None = None) -> list[DepIssue]:
    """advisories: {"package": [{"fixed_in": "2.0.1", "id": "EXAMPLE-1", "summary": "..."}]}"""
    advisories = advisories or {}
    issues = []
    for line in parse_requirements(text):
        m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(==|>=|<=|~=|>|<|!=)?\s*([\w.*+\-]*)", line)
        if not m:
            issues.append(DepIssue(line, "error", "unparseable requirement"))
            continue
        name, op, version = m.group(1).lower(), m.group(2), m.group(3)
        if op != "==" or "*" in version:
            issues.append(DepIssue(name, "error", "not pinned to an exact version (use ==)"))
            continue
        for adv in advisories.get(name, []):
            if _vt(version) < _vt(adv["fixed_in"]):
                issues.append(DepIssue(name, "error",
                                       f"{adv['id']}: {adv['summary']} (fixed in {adv['fixed_in']})"))
    return issues


def load_advisories(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
