"""Tool registry = least privilege for agents.

Every call goes through: allowlist -> permission check -> argument schema ->
custom validator -> human approval (high risk) -> execution -> output scan."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .auth import Identity, authorize
from .errors import ApprovalRequired, SecurityError, ToolError
from .injection_detector import scan_untrusted

MAX_TOOL_OUTPUT = 2000
Approver = Callable[[str, dict, Identity], bool]


@dataclass
class ToolContext:
    identity: Identity
    approved: bool = False


@dataclass
class Tool:
    name: str
    description: str
    func: Callable[[dict, ToolContext], Any]
    permission: str
    risk: str = "low"                                  # low | medium | high
    schema: dict[str, type] | None = None              # required args -> type
    validator: Callable[[dict], None] | None = None


@dataclass
class ToolResult:
    name: str
    output: str
    approved: bool = False
    flagged: bool = False


class ToolRegistry:
    def __init__(self, untrusted_threshold: int = 2):
        self._tools: dict[str, Tool] = {}
        self.threshold = untrusted_threshold

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def names(self) -> list[str]:
        return sorted(self._tools)

    def describe(self) -> str:
        """Human/LLM-readable tool list used in the system prompt."""
        lines = []
        for t in sorted(self._tools.values(), key=lambda t: t.name):
            args = ", ".join(f'"{k}": {v.__name__}' for k, v in (t.schema or {}).items())
            lines.append(f"- {t.name} {{{args}}}: {t.description}")
        return "\n".join(lines)

    @staticmethod
    def _check_args(tool: Tool, args: object) -> None:
        if not isinstance(args, dict):
            raise ToolError("arguments must be an object")
        schema = tool.schema or {}
        extra = set(args) - set(schema)
        if extra:                                       # blocks parameter-injection
            raise ToolError(f"unexpected arguments: {sorted(extra)}")
        for key, typ in schema.items():
            if key not in args:
                raise ToolError(f"missing argument '{key}'")
            value = args[key]
            if not isinstance(value, typ) or (typ is int and isinstance(value, bool)):
                raise ToolError(f"argument '{key}' must be {typ.__name__}")

    def execute(self, name: str, args: dict, identity: Identity,
                approver: Approver | None = None) -> ToolResult:
        tool = self._tools.get(name)
        if tool is None:
            raise ToolError(f"unknown tool '{name}'")               # 1. allowlist
        authorize(identity, tool.permission)                        # 2. permission
        self._check_args(tool, args)                                # 3. schema
        if tool.validator:
            tool.validator(args)                                    # 4. custom validation
        approved = False
        if tool.risk == "high":                                     # 5. human-in-the-loop
            if approver is None or not approver(tool.name, dict(args), identity):
                raise ApprovalRequired(f"'{name}' is high-risk and needs human approval")
            approved = True
        try:                                                        # 6. execute
            out = tool.func(args, ToolContext(identity, approved))
        except SecurityError:
            raise
        except Exception as exc:  # noqa: BLE001 - never leak internals
            raise ToolError(f"tool failed: {type(exc).__name__}") from exc
        out = str(out)[:MAX_TOOL_OUTPUT]
        flagged = scan_untrusted(out, self.threshold).blocked      # 7. output is untrusted
        if flagged:
            out = "[tool output withheld: it contained instruction-like content]"
        return ToolResult(name, out, approved, flagged)