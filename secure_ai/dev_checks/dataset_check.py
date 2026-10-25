"""Training-data poisoning / privacy checks for labelled text datasets."""
from __future__ import annotations

import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from ..injection_detector import scan_untrusted
from ..input_validation import strip_invisible
from ..pii_filter import redact


@dataclass
class DatasetIssue:
    kind: str
    row: int
    detail: str = ""


@dataclass
class DatasetReport:
    issues: list[DatasetIssue] = field(default_factory=list)

    def kinds(self) -> set[str]:
        return {i.kind for i in self.issues}

    @property
    def clean(self) -> bool:
        return not self.issues


def check_dataset(rows: list[dict], max_label_share: float = 0.9) -> DatasetReport:
    """rows: [{"text": str, "label": str}, ...]"""
    rep = DatasetReport()
    seen: dict[str, int] = {}
    labels_by_text: dict[str, set] = defaultdict(set)
    for i, row in enumerate(rows):
        text, label = row.get("text", ""), row.get("label")
        norm = re.sub(r"\s+", " ", text).strip().lower()
        if norm in seen:
            rep.issues.append(DatasetIssue("duplicate", i, f"same as row {seen[norm]}"))
        seen.setdefault(norm, i)
        labels_by_text[norm].add(label)
        if scan_untrusted(text).blocked:
            rep.issues.append(DatasetIssue("injection_content", i, "instruction-like text in training data"))
        if strip_invisible(text) != text:
            rep.issues.append(DatasetIssue("hidden_characters", i))
        pii = redact(text).findings
        if pii:
            rep.issues.append(DatasetIssue("pii_present", i, ",".join(sorted(pii))))
    for norm, labs in labels_by_text.items():
        if len(labs) > 1:
            rep.issues.append(DatasetIssue("label_conflict", seen[norm], f"labels {sorted(map(str, labs))}"))
    counts = Counter(r.get("label") for r in rows)
    if rows and max(counts.values()) / len(rows) > max_label_share:
        rep.issues.append(DatasetIssue("label_imbalance", -1, str(dict(counts))))
    lengths = [len(r.get("text", "")) for r in rows]
    if len(lengths) >= 10:
        mean, sd = statistics.mean(lengths), statistics.pstdev(lengths) or 1
        for i, n in enumerate(lengths):
            if (n - mean) / sd > 4:
                rep.issues.append(DatasetIssue("length_outlier", i, f"{n} chars"))
    return rep
