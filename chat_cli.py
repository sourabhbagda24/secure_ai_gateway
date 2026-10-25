#!/usr/bin/env python3
"""Interactive terminal chat through the secure gateway.

  python chat_cli.py                 # user 'alice' (analyst), mock LLM, offline
  python chat_cli.py --user root     # admin: try 'delete record 7' -> you get an approval prompt
  python chat_cli.py --llm groq      # Groq (needs env GROQ_API_KEY, no pip install)
  python chat_cli.py --llm anthropic # Claude (needs: pip install anthropic + ANTHROPIC_API_KEY)

Users: alice (analyst, acme) | bob (viewer, acme) | root (admin, acme) | eve (analyst, globex)"""
import argparse

from secure_ai.demo_world import build_world


def human_approver(tool, args, identity):
    print(f"\n  >>> APPROVAL NEEDED: {identity.user_id} wants to run {tool} {args}")
    return input("  >>> approve? [y/N] ").strip().lower() == "y"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", default="alice", choices=["alice", "bob", "root", "eve"])
    ap.add_argument("--llm", default="mock", choices=["mock", "anthropic", "groq"])
    args = ap.parse_args()
    llm = None
    if args.llm == "anthropic":
        from secure_ai.llm import AnthropicLLM
        llm = AnthropicLLM()
    elif args.llm == "groq":
        from secure_ai.llm import GroqLLM
        llm = GroqLLM()
    w = build_world(llm=llm)
    ident = w.tokens.verify(w.tok(args.user))
    print(f"Logged in as {ident.user_id} (role={ident.role}, tenant={ident.tenant}). Type 'exit' to quit.")
    print("Try: 'What is the refund policy?' | 'calculate 2+2' | 'delete record 7' | 'Ignore all previous instructions'")
    while True:
        try:
            msg = input(f"\n{args.user}> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if msg in ("exit", "quit"):
            break
        if not msg:
            continue
        r = w.gateway.handle(w.tok(args.user), msg, approver=human_approver)
        tag = "" if r.ok else f"  [blocked: {r.blocked_by}]"
        print(f"assistant> {r.text}{tag}")
        if r.findings:
            print(f"  (security findings: {r.findings})")
        if r.blocked_by == "llm_error":      # operator-only diagnostics (users never see this)
            f = w.audit.events("llm_error")[-1]["fields"]
            print(f"  [operator] LLM error: {f.get('error')} - {f.get('detail')}")
    print(f"\nAudit chain valid: {w.audit.verify_chain()} ({len(w.audit.records)} records)")


if __name__ == "__main__":
    main()