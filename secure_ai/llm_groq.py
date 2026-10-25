"""Groq LLM client for the Secure AI Gateway."""
from __future__ import annotations

import os

from groq import Groq

from .llm import LLM


class GroqLLM(LLM):
    """Real LLM via Groq API."""

    def __init__(self, model: str = "openai/gpt-oss-120b", api_key: str | None = None):
        key = api_key or os.getenv("GROQ_API_KEY")
        if not key:
            raise ValueError(
                "GROQ_API_KEY not set. Get a free key at https://console.groq.com/keys"
            )
        self.client = Groq(api_key=key)
        self.model = model

    def complete(self, system: str, messages: list[dict]) -> str:
        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": system}, *messages],
                temperature=0.1,
                max_tokens=1024,
            )
            return resp.choices[0].message.content or ""
        except Exception as exc:
            return f"[LLM error: {type(exc).__name__}]"