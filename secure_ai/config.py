from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass

log = logging.getLogger("secure_ai")


def load_secret() -> bytes:
    """Signing secret comes from the environment - NEVER from source code."""
    raw = os.environ.get("AI_GATEWAY_SECRET")
    if raw:
        if len(raw) < 16:
            raise ValueError("AI_GATEWAY_SECRET must be at least 16 characters")
        return raw.encode()
    log.warning("AI_GATEWAY_SECRET not set: using an ephemeral random secret "
                "(issued tokens stop working when the process restarts).")
    return secrets.token_bytes(32)


@dataclass
class Settings:
    max_input_chars: int = 4000
    max_output_chars: int = 4000
    rate_limit_per_minute: int = 20
    daily_token_budget: int = 20_000        # "denial of wallet" protection
    injection_threshold: int = 3            # score that blocks a *user* message
    untrusted_threshold: int = 2            # stricter: docs / tool output / memory
    max_tool_calls: int = 3                 # per request (excessive agency)
    max_violations: int = 3                 # then the account is auto-suspended
    violation_window_s: int = 600
    require_consent: bool = False           # compliance (DPDP / GDPR style)
    render_html: bool = False               # escape output for HTML rendering
    kill_switch: bool = False               # incident response: stop everything
