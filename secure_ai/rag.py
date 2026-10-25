"""RAG with per-document access control, tenant isolation and poisoning defence.

Key ideas
1. ACL / tenant filters run BEFORE ranking (never retrieve first, filter later).
2. Documents are scanned for injected instructions at ingest (quarantine) AND again at
   retrieval (defence in depth).
3. Retrieved text is escaped and wrapped in <untrusted_document> tags: it is data."""
from __future__ import annotations

import html
import re
from dataclasses import dataclass, field

from .auth import Identity, authorize
from .injection_detector import scan_untrusted

_STOP = {"a", "an", "the", "is", "are", "was", "what", "who", "how", "do", "does", "of",
         "to", "in", "on", "for", "and", "or", "me", "my", "s", "about", "tell", "please", "our"}


def _tokens(text: str) -> set[str]:
    return {t for t in re.findall(r"\w+", text.lower()) if t not in _STOP}


@dataclass(frozen=True)
class Document:
    id: str
    text: str
    tenant: str
    allowed_roles: frozenset = frozenset({"viewer", "analyst", "admin"})
    source: str = "internal"


@dataclass
class RetrievedChunk:
    doc_id: str
    text: str
    score: int


def wrap_untrusted(chunk: RetrievedChunk) -> str:
    return (f'<untrusted_document id="{html.escape(chunk.doc_id)}">\n'
            f"{html.escape(chunk.text, quote=False)}\n</untrusted_document>")


class SecureRAG:
    def __init__(self, untrusted_threshold: int = 2, max_chunk_chars: int = 800):
        self.threshold = untrusted_threshold
        self.max_chunk_chars = max_chunk_chars
        self._docs: dict[str, Document] = {}
        self.quarantined: dict[str, list[str]] = {}
        self.last_flagged: list[str] = []

    def add(self, doc: Document, scan: bool = True) -> bool:
        """Returns False if the document was quarantined (possible poisoning)."""
        if scan:
            result = scan_untrusted(doc.text, self.threshold)
            if result.blocked:
                self.quarantined[doc.id] = result.matches
                return False
        self._docs[doc.id] = doc
        return True

    def search(self, query: str, identity: Identity, k: int = 3) -> list[RetrievedChunk]:
        authorize(identity, "rag:read")
        self.last_flagged = []
        q = _tokens(query)
        candidates = [d for d in self._docs.values()
                      if d.tenant == identity.tenant and identity.role in d.allowed_roles]
        scored = sorted(((len(q & _tokens(d.text)), d) for d in candidates),
                        key=lambda s: (-s[0], s[1].id))
        out: list[RetrievedChunk] = []
        for score, doc in scored:
            if score == 0 or len(out) >= k:
                continue
            if scan_untrusted(doc.text, self.threshold).blocked:      # retrieval-time re-check
                self.last_flagged.append(doc.id)
                continue
            out.append(RetrievedChunk(doc.id, doc.text[: self.max_chunk_chars], score))
        return out
