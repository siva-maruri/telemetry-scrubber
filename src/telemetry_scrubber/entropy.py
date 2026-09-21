"""High-entropy string detection for secrets the regexes don't know about."""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field

_CANDIDATE = re.compile(r"[A-Za-z0-9+/_=-]{20,}")
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")

# Attributes whose values are high entropy by design. We allowlist by key, not by
# shape: a W3C trace id is 32 hex chars, but so are plenty of vendor API keys.
DEFAULT_ALLOW_KEYS = frozenset(
    {
        "trace_id",
        "span_id",
        "parent_span_id",
        "traceparent",
        "tracestate",
        "http.request.header.traceparent",
        "vcs.revision",
        "git.commit.sha",
        "container.image.id",
        "k8s.pod.uid",
    }
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


@dataclass
class EntropyDetector:
    hex_threshold: float = 3.0
    b64_threshold: float = 4.5
    min_hex_len: int = 32
    allow_keys: frozenset[str] = field(default_factory=lambda: DEFAULT_ALLOW_KEYS)
    allow_key_suffixes: tuple[str, ...] = (".sha256", ".digest", ".checksum")

    def key_allowed(self, key: str | None) -> bool:
        if not key:
            return False
        k = key.lower()
        return k in self.allow_keys or k.endswith(self.allow_key_suffixes)

    def find(self, text: str, key: str | None = None) -> Iterator[tuple[int, int]]:
        if self.key_allowed(key):
            return
        for m in _CANDIDATE.finditer(text):
            token = m.group(0)
            if _UUID.match(token) or not self._looks_secret(token):
                continue
            yield m.start(), m.end()

    def _looks_secret(self, token: str) -> bool:
        if _HEX.match(token):
            return len(token) >= self.min_hex_len and shannon_entropy(token) >= self.hex_threshold
        # Identifiers like "order-service-canary-west" are long but never mix
        # digits with both cases. Requiring all three drops most of that noise.
        has_digit = any(c.isdigit() for c in token)
        has_upper = any(c.isupper() for c in token)
        has_lower = any(c.islower() for c in token)
        if not (has_digit and has_upper and has_lower):
            return False
        return shannon_entropy(token) >= self.b64_threshold
