#!/usr/bin/env python3
"""Run every attack against (a) an insecure baseline and (b) the SecureAIGateway.
Exit code 1 if any attack succeeds against the secure gateway."""
import sys

from redteam.attacks import ATTACKS
from redteam.baseline import NaiveGateway
from secure_ai.demo_world import build_world


def run_one(attack, secure: bool):
    w = build_world()                       # fresh state per attack
    target = w.gateway if secure else NaiveGateway(w)
    resp = target.handle(w.tok(attack.user), attack.message, approver=attack.approver)
    return attack.success(resp, w), resp


def main() -> int:
    print(f"{'ATTACK':<26}{'OWASP':<8}{'INSECURE BASELINE':<20}{'SECURE GATEWAY':<18}DEFENDED BY")
    print("-" * 100)
    baseline_hits = secure_hits = 0
    for a in ATTACKS:
        vulnerable, _ = run_one(a, secure=False)
        breached, resp = run_one(a, secure=True)
        baseline_hits += vulnerable
        secure_hits += breached
        layer = (resp.blocked_by or (resp.tool_blocks[0]["code"] if resp.tool_blocks else "")
                 or a.hint or (resp.findings[0] if resp.findings else "-"))
        print(f"{a.id:<26}{a.owasp:<8}{'VULNERABLE' if vulnerable else 'not exploited':<20}"
              f"{'BREACHED !!!' if breached else 'blocked':<18}{layer}")
    print("-" * 100)
    print(f"Attacks that worked on the insecure baseline: {baseline_hits}/{len(ATTACKS)}")
    print(f"Attacks that worked on the secure gateway   : {secure_hits}/{len(ATTACKS)}")
    return 1 if secure_hits else 0


if __name__ == "__main__":
    sys.exit(main())
