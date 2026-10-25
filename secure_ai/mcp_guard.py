"""MCP / third-party tool guard: tool poisoning, rug-pulls and tool shadowing."""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field

from .errors import MCPViolation
from .injection_detector import scan_untrusted

_EXTRA = [
    ("hidden_important_tag", re.compile(r"<\s*(?:important|system|instructions?)\b", re.I)),
    ("sensitive_path_access", re.compile(r"(?:~|/)\.ssh\b|id_rsa|\.env\b|/etc/passwd|\.aws/credentials", re.I)),
    ("pre_call_instruction", re.compile(r"before (?:using|calling|running) this tool", re.I)),
    ("secrecy_instruction", re.compile(r"do not (?:mention|tell|reveal|disclose)|don't (?:mention|tell)", re.I)),
]


@dataclass(frozen=True)
class MCPToolDefinition:
    server: str
    name: str
    description: str
    input_schema: dict = field(default_factory=dict)

    def fingerprint(self) -> str:
        canon = json.dumps({"server": self.server, "name": self.name,
                            "description": self.description, "schema": self.input_schema},
                           sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canon.encode()).hexdigest()


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _strings(v)


class MCPGuard:
    def __init__(self, allowed_servers: set[str], threshold: int = 2):
        self.allowed_servers = set(allowed_servers)
        self.threshold = threshold
        self._pins: dict[tuple[str, str], str] = {}
        self._name_owner: dict[str, str] = {}

    def review(self, d: MCPToolDefinition) -> list[str]:
        findings: list[str] = []
        for text in [d.description, *_strings(d.input_schema)]:
            if any(unicodedata.category(c) == "Cf" and c not in "\u200c\u200d" or 0xE0000 <= ord(c) <= 0xE007F
                   for c in text):
                findings.append("hidden_characters")
            findings += [f"injection:{m}" for m in scan_untrusted(text, self.threshold).matches]
            findings += [name for name, rx in _EXTRA if rx.search(text)]
        return sorted(set(findings))

    def approve(self, d: MCPToolDefinition) -> str:
        if d.server not in self.allowed_servers:
            raise MCPViolation(f"server '{d.server}' is not allowlisted")
        owner = self._name_owner.get(d.name)
        if owner and owner != d.server:
            raise MCPViolation(f"tool '{d.name}' would shadow the one from '{owner}'")
        findings = self.review(d)
        if findings:
            raise MCPViolation("suspicious tool definition", findings=findings)
        self._name_owner[d.name] = d.server
        self._pins[(d.server, d.name)] = d.fingerprint()
        return self._pins[(d.server, d.name)]

    def verify(self, d: MCPToolDefinition) -> None:
        """Call before every session/use: detects a definition that changed after approval."""
        pin = self._pins.get((d.server, d.name))
        if pin is None:
            raise MCPViolation("tool was never approved")
        if pin != d.fingerprint():
            raise MCPViolation("tool definition changed after approval (rug pull)")
