"""A deliberately INSECURE gateway (no ACLs, no validation, no permission checks).
Used only to prove that the red-team attacks are real: they succeed here."""
from __future__ import annotations

import html
import json
import re
from pathlib import Path

from secure_ai.demo_world import World
from secure_ai.gateway import SYSTEM_TEMPLATE, TOOL_LINE, GatewayResponse
from secure_ai.rag import _tokens


class NaiveGateway:
    def __init__(self, world: World):
        self.w = world
        self.canary = "CANARY-naive"
        self.system_prompt = SYSTEM_TEMPLATE.format(canary=self.canary, tools="")
        self.naive_memory: list[str] = []

    def _retrieve(self, q: str):
        qt = _tokens(q)                                    # ALL docs, all tenants, no scanning
        scored = sorted(((len(qt & _tokens(d.text)), d) for d in self.w.docs), key=lambda s: -s[0])
        return [d for s, d in scored if s > 0][:3]

    def _run(self, name: str, args: dict) -> str:
        e = self.w.effects
        if name == "send_email":
            e.emails.append(args); return "email sent"
        if name == "delete_record":
            e.deleted.append(args["id"]); return "deleted"
        if name == "read_file":
            return (self.w.sandbox_dir / args["path"]).read_text()      # no traversal check
        if name == "query_db":
            return json.dumps(self.w.db.execute(args["sql"]).fetchall())  # raw SQL
        if name == "remember":
            e.memory.append(args["text"]); return "remembered"
        if name == "calculator":
            return str(eval(args["expression"], {"__builtins__": {}}))   # eval() - unsafe
        return "unknown tool"

    def handle(self, token: str, message: str, approver=None) -> GatewayResponse:
        docs = self._retrieve(message)
        context = "\n".join(f'<untrusted_document id="{d.id}">\n{html.escape(d.text, quote=False)}\n</untrusted_document>'
                            for d in docs)
        prompt = f"<context>\n{context}\n</context>\n<memory>\n\n</memory>\nUser question: {message}"
        raw = self.w.gateway.llm.complete(self.system_prompt, [{"role": "user", "content": prompt}])
        text = TOOL_LINE.sub("", raw).strip()
        for m in TOOL_LINE.finditer(raw):
            try:
                text += "\n" + self._run(m.group(1), json.loads(m.group(2)))
            except Exception as exc:  # noqa: BLE001
                text += f"\n(error {type(exc).__name__})"
        return GatewayResponse(True, text.strip())