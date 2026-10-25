"""Typed security errors. Every error carries a short machine-readable `code`
which the gateway returns as `blocked_by` and writes into the audit log."""


class SecurityError(Exception):
    code = "security"

    def __init__(self, message: str = "", **details):
        super().__init__(message or self.code)
        self.details = details


class AuthError(SecurityError):
    code = "authentication"


class AuthzError(SecurityError):
    code = "authorization"


class RateLimitError(SecurityError):
    code = "rate_limit"


class BudgetExceeded(SecurityError):
    code = "budget_exceeded"


class ValidationError(SecurityError):
    code = "input_validation"


class InjectionDetected(SecurityError):
    code = "prompt_injection"


class ToolError(SecurityError):
    code = "tool_blocked"


class ApprovalRequired(ToolError):
    code = "approval_required"


class SandboxViolation(ToolError):
    code = "sandbox_violation"


class MCPViolation(SecurityError):
    code = "mcp_violation"


class MemoryPoisoning(SecurityError):
    code = "memory_poisoning"


class KillSwitchActive(SecurityError):
    code = "kill_switch"


class AccountSuspended(SecurityError):
    code = "suspended"


class ConsentRequired(SecurityError):
    code = "consent_required"


class SupplyChainError(SecurityError):
    code = "supply_chain"
