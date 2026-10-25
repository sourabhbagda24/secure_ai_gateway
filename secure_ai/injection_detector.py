"""Heuristic prompt-injection / jailbreak detector.

IMPORTANT: this is a first line of defence, not a silver bullet. Heuristics can be
bypassed and can have false positives. Combine with least-privilege tools, output
validation, human approval and (in production) a model-based classifier."""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

from .input_validation import strip_invisible

USER_THRESHOLD = 3       # user messages
UNTRUSTED_THRESHOLD = 2  # documents, tool output, memory, MCP descriptions

_RULES = [
    ("override_instructions", 3, r"\b(?:ignore|disregard|forget|override|bypass|skip)\b.{0,60}\b(?:instructions?|rules?|prompts?|guidelines?|guardrails?|restrictions?|polic(?:y|ies)|directives?)\b"),
    ("persona_switch", 3, r"\b(?:you are now|from now on you are|act as|pretend to be|roleplay as)\b.{0,40}\b(?:dan|unrestricted|unfiltered|jailbroken|evil|uncensored)\b"),
    ("jailbreak_dan", 3, r"\bdo anything now\b|\bdan mode\b"),
    ("jailbreak_keyword", 2, r"\b(?:developer mode|god mode|jailbreak(?:ed)?)\b"),
    ("prompt_extraction", 3, r"\b(?:reveal|show|print|display|repeat|output|leak|dump|disclose|tell me|give me)\b.{0,40}\b(?:system|initial|hidden|secret|original|internal)\b.{0,15}\b(?:prompt|instructions?|message|rules)\b"),
    ("prompt_extraction_q", 3, r"\bwhat (?:is|are|were) your (?:system|initial|original|hidden) (?:prompt|instructions?)\b"),
    ("remove_safety", 2, r"\b(?:without|no|remove|disable|turn off)\b.{0,20}\b(?:restrictions?|filters?|guardrails?|safety|censorship|limitations?)\b"),
    ("no_rules_pretend", 3, r"\bpretend\b.{0,40}\b(?:no|without)\b.{0,20}\b(?:rules|restrictions|limits|guidelines)\b"),
    ("role_delimiter_spoof", 2, r"<\|?(?:im_start|im_end|system|endoftext)\|?>|\[/?(?:system|inst)\]|#{2,}\s*system\b"),
    ("boundary_spoof", 3, r"</?\s*(?:context|untrusted_document|memory|instructions?)\b[^>]*>"),
    ("new_instructions", 2, r"\bnew (?:system )?instructions?\s*:"),
    ("concealment", 3, r"\b(?:do not|don't|never)\b.{0,20}\b(?:tell|inform|notify|alert|show|mention)\b.{0,20}\b(?:the )?user\b"),
    ("exfil_target", 2, r"\b(?:exfiltrate|send|forward|post|upload|email)\b.{0,60}\b(?:to|at)\b.{0,40}(?:https?://|[\w.+-]+@[\w-]+\.[\w.-]+)"),
    ("exfil_keyword", 3, r"\bexfiltrat\w*"),
    ("markdown_image_exfil", 3, r"!\[[^\]]*\]\(https?://[^)\s]*\?[^)\s]*\)"),
    ("tool_call_syntax", 3, r"\btool\s*:\s*\w+\s*\{"),
]
_COMPILED = [(n, w, re.compile(p, re.I)) for n, w, p in _RULES]
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


@dataclass
class ScanResult:
    score: int
    matches: list[str]
    threshold: int

    @property
    def blocked(self) -> bool:
        return self.score >= self.threshold


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = strip_invisible(text).lower()
    return re.sub(r"\s+", " ", text)


def _decoded_variants(text: str):
    for m in _B64.finditer(text):
        chunk = m.group()
        try:
            raw = base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if " " in decoded and sum(c.isprintable() for c in decoded) / len(decoded) > 0.95:
            yield decoded


def scan(text: str, threshold: int = USER_THRESHOLD, _depth: int = 0) -> ScanResult:
    norm = normalize(text)
    variants = [norm]
    leet = norm.translate(_LEET)
    if leet != norm:
        variants.append(leet)
    hits: dict[str, int] = {}
    for variant in variants:
        for name, weight, rx in _COMPILED:
            if name not in hits and rx.search(variant):
                hits[name] = weight
    if _depth == 0:                              # hidden payloads: base64 inside the text
        for decoded in _decoded_variants(text):
            sub = scan(decoded, threshold, _depth=1)
            if sub.matches:
                for name in sub.matches:
                    hits.setdefault(f"encoded:{name}", 3)
                hits.setdefault("encoded_payload", 1)
    return ScanResult(score=sum(hits.values()), matches=sorted(hits), threshold=threshold)


def scan_untrusted(text: str, threshold: int = UNTRUSTED_THRESHOLD) -> ScanResult:
    """Documents/tool outputs should contain DATA, not instructions - so we are stricter."""
    return scan(text, threshold)
