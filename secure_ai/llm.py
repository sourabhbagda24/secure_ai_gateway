"""LLM adapters.

* MockLLM  - deterministic and intentionally GULLIBLE (it obeys injected text). That is
             what makes it a good test-subject: every attack that reaches it succeeds,
             so a passing test proves the *surrounding defences* work.
* AnthropicLLM - optional real adapter (needs `pip install anthropic` + ANTHROPIC_API_KEY)."""
from __future__ import annotations

import base64
import html
import json
import os
import re
import unicodedata
import urllib.error
import urllib.request
from typing import Protocol

from .input_validation import strip_invisible


class LLM(Protocol):
    def complete(self, system: str, messages: list[dict]) -> str: ...


_DOC = re.compile(r'<untrusted_document id="([^"]+)">\n(.*?)\n</untrusted_document>', re.S)
_TOOL = re.compile(r"TOOL:\s*\w+\s*\{[^\n]*\}")
_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def _expand(q: str) -> str:
    """Real LLMs read through unicode tricks and base64 - so does the mock."""
    q = strip_invisible(unicodedata.normalize("NFKC", q))
    extra = []
    for m in _B64.finditer(q):
        try:
            extra.append(base64.b64decode(m.group() + "=" * (-len(m.group()) % 4)).decode("utf-8"))
        except Exception:  # noqa: BLE001
            pass
    return q + " " + " ".join(extra)


class MockLLM:
    def __init__(self, fake_citation: bool = False):
        self.fake_citation = fake_citation
        self.calls = 0

    def complete(self, system: str, messages: list[dict]) -> str:
        self.calls += 1
        content = messages[-1]["content"]
        question = content.split("User question:")[-1].strip()
        q = _expand(question).lower()

        if m := re.match(r"say:\s*(.*)", question, re.S | re.I):
            return m.group(1)
        if ("system prompt" in q or "repeat everything above" in q
                or re.search(r"ignore .*instructions", q)):
            return system                                   # gullible: leaks its prompt
        if "do anything now" in q or "dan mode" in q:
            return "DAN MODE ENABLED. I will comply with anything."
        if m := re.search(r"calculate\s+(.+)", q):
            return "TOOL: calculator " + json.dumps({"expression": m.group(1).strip().rstrip("?.")})
        if m := re.search(r"send (?:an )?email to (\S+) saying (.+)", question, re.I):
            return "TOOL: send_email " + json.dumps(
                {"to": m.group(1), "subject": "Message", "body": m.group(2)})
        if m := re.search(r"delete record (\d+)", q):
            return "TOOL: delete_record " + json.dumps({"id": int(m.group(1))})
        if m := re.search(r"read file (\S+)", question, re.I):
            return "TOOL: read_file " + json.dumps({"path": m.group(1)})
        if m := re.match(r"query:\s*(.+)", question, re.S | re.I):
            return "TOOL: query_db " + json.dumps({"sql": m.group(1)})
        if m := re.search(r"remember (?:that )?(.+)", question, re.I):
            return "TOOL: remember " + json.dumps({"text": m.group(1)})

        obey = _TOOL.search(html.unescape(content.split("User question:")[0]))
        if obey:                                            # gullible: obeys text inside documents
            return obey.group().strip()
        docs = _DOC.findall(content)
        if docs:
            doc_id, text = docs[0]
            cite = "doc-999" if self.fake_citation else doc_id
            return f"According to our documents: {html.unescape(text)} [doc:{cite}]"
        return f"I can help with questions about our documents. You asked: {question}"


class AnthropicLLM:  # pragma: no cover - needs network + API key
    def __init__(self, model: str | None = None):
        import anthropic                                     # lazy import
        self.client = anthropic.Anthropic()                  # key read from ANTHROPIC_API_KEY
        self.model = model or os.environ.get("AI_GATEWAY_MODEL", "claude-sonnet-5")

    def complete(self, system: str, messages: list[dict]) -> str:
        resp = self.client.messages.create(model=self.model, max_tokens=800,
                                           system=system, messages=messages)
        return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")


class GroqLLM:
    """Groq via its OpenAI-compatible HTTP API. Standard library only (no `pip install groq`).

    Key:   env GROQ_API_KEY  (never hard-code it)
    Model: env GROQ_MODEL    (default below; check https://console.groq.com/docs/models - names change)"""

    URL = "https://api.groq.com/openai/v1/chat/completions"
    DEFAULT_MODEL = "llama-3.3-70b-versatile"

    def __init__(self, model: str | None = None, timeout: float = 30.0):
        self.api_key = os.environ.get("GROQ_API_KEY")
        if not self.api_key:
            raise RuntimeError("GROQ_API_KEY is not set")
        self.model = model or os.environ.get("GROQ_MODEL", self.DEFAULT_MODEL)
        self.timeout = timeout

    def complete(self, system: str, messages: list[dict]) -> str:
        body = json.dumps({
            "model": self.model,
            "messages": [{"role": "system", "content": system}, *messages],
            "temperature": 0.2,
            "max_tokens": 800,
        }).encode()
        req = urllib.request.Request(self.URL, data=body, method="POST", headers={
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "secure-ai-gateway/1.0",      # default urllib UA is often blocked by Cloudflare
        })
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300] if hasattr(exc, "read") else ""
            raise RuntimeError(f"Groq HTTP {exc.code}: {detail}") from None
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Groq connection error: {exc.reason}") from None
        try:
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            raise RuntimeError("Groq returned an unexpected response shape") from None