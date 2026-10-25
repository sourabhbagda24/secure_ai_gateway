"""Model / artifact supply-chain checks: hash pinning, safe formats, trusted sources."""
from __future__ import annotations

import hashlib
from pathlib import Path
from urllib.parse import urlparse

from ..errors import SupplyChainError

# pickle-based formats can execute arbitrary code when loaded
UNSAFE_SUFFIXES = {".pkl", ".pickle", ".joblib", ".pt", ".pth", ".ckpt"}
SAFE_SUFFIXES = {".safetensors", ".onnx", ".gguf", ".json", ".txt"}


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def verify_artifact(path, manifest: dict[str, str], allow_unsafe_formats: bool = False) -> str:
    """manifest = {"model.safetensors": "<sha256>"}. Raises SupplyChainError on any problem."""
    p = Path(path)
    if p.suffix.lower() in UNSAFE_SUFFIXES and not allow_unsafe_formats:
        raise SupplyChainError(f"{p.suffix} is a pickle-based format; use safetensors/ONNX/GGUF")
    expected = manifest.get(p.name)
    if not expected:
        raise SupplyChainError(f"{p.name} is not in the trusted manifest")
    if sha256_file(p) != expected.lower():
        raise SupplyChainError(f"checksum mismatch for {p.name}")
    return expected


def check_source_url(url: str, allowed_hosts: set[str]) -> None:
    u = urlparse(url)
    if u.scheme != "https":
        raise SupplyChainError("model downloads must use https")
    if (u.hostname or "").lower() not in {h.lower() for h in allowed_hosts}:
        raise SupplyChainError(f"host '{u.hostname}' is not an approved model source")
