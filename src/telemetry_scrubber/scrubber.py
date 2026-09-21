from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, TypeVar

from .detectors import SECRET, Detector, default_detectors
from .entropy import EntropyDetector
from .tokens import Tokenizer

T = TypeVar("T")

# Headers and attributes that are never worth inspecting, just drop the value.
DEFAULT_DROP_KEYS = frozenset(
    {
        "http.request.header.authorization",
        "http.request.header.cookie",
        "http.response.header.set-cookie",
        "http.request.header.x-api-key",
        "db.connection_string",
    }
)

# Identifiers analysts still need to group by. Tokenized as a whole value.
DEFAULT_TOKENIZE_KEYS = frozenset({"enduser.id", "user.id", "user.email", "customer.id"})

# PII detectors whose matches get tokenized instead of redacted (when a tokenizer
# is configured). Cards and SSNs are always redacted, nobody should be joining on those.
DEFAULT_TOKENIZE_DETECTORS = frozenset({"email", "phone"})


@dataclass(frozen=True)
class Finding:
    detector: str
    action: str
    key: str | None


@dataclass
class Scrubber:
    detectors: list[Detector] = field(default_factory=default_detectors)
    entropy: EntropyDetector | None = field(default_factory=EntropyDetector)
    tokenizer: Tokenizer | None = None
    drop_keys: frozenset[str] = DEFAULT_DROP_KEYS
    tokenize_keys: frozenset[str] = DEFAULT_TOKENIZE_KEYS
    tokenize_detectors: frozenset[str] = DEFAULT_TOKENIZE_DETECTORS
    stats: Counter[tuple[str, str]] = field(default_factory=Counter)

    def scrub_text(self, text: str, key: str | None = None) -> tuple[str, list[Finding]]:
        k = key.lower() if key else None
        if k in self.drop_keys or k in self.tokenize_keys:
            return self._scrub_by_key(text, k, key)

        # Redacting one match can expose another: a phone number right before a PEM header
        # fails its boundary check on the "-", and passes once the header is gone. So rescan
        # until nothing changes. Only strings that had a finding pay for the extra pass.
        out, findings = self._scan(text, key)
        new = findings
        for _ in range(2):
            if not new:
                break
            out, new = self._scan(out, key)
            findings = findings + new
        return self._record(out, findings)

    def _scrub_by_key(self, text: str, k: str | None, key: str | None) -> tuple[str, list[Finding]]:
        if k in self.drop_keys:
            return self._record("[REDACTED]", [Finding("drop_key", "redact", key)])
        # Fail closed: without a key we can't tokenize, so the value goes.
        if self.tokenizer is None:
            return self._record("[REDACTED]", [Finding("tokenize_key", "redact", key)])
        return self._record(self.tokenizer.token(text, k or ""), [Finding("tokenize_key", "tokenize", key)])

    def _scan(self, text: str, key: str | None) -> tuple[str, list[Finding]]:
        hits: list[tuple[int, int, str, str]] = []
        for det in self.detectors:
            if not det.could_match(text):
                continue
            for start, end in det.find(text):
                hits.append((start, end, det.name, det.kind))

        # Among named detectors, longest match wins (a bearer header can wrap a JWT).
        hits.sort(key=lambda h: (h[0], -(h[1] - h[0])))
        kept, last_end = [], -1
        for h in hits:
            if h[0] >= last_end:
                kept.append(h)
                last_end = h[1]

        # Entropy only fills gaps. Its candidates are greedy ("sig=AbC..." instead of
        # just the value), so letting it compete would mangle output the regexes
        # already handle cleanly.
        if self.entropy:
            for start, end in self.entropy.find(text, key):
                if all(end <= s or start >= e for s, e, _, _ in kept):
                    kept.append((start, end, "high_entropy", SECRET))
            kept.sort()
        if not kept:
            return text, []

        out, findings = text, []
        for start, end, name, kind in reversed(kept):
            if kind != SECRET and name in self.tokenize_detectors and self.tokenizer:
                repl, action = self.tokenizer.token(text[start:end], name), "tokenize"
            else:
                repl, action = f"[REDACTED:{name}]", "redact"
            out = out[:start] + repl + out[end:]
            findings.append(Finding(name, action, key))
        return out, findings[::-1]

    def scrub_value(self, value: Any, key: str | None = None) -> tuple[Any, list[Finding]]:
        if isinstance(value, str):
            return self.scrub_text(value, key)
        if isinstance(value, Mapping):
            return self.scrub_mapping(value)
        if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
            out, findings = [], []
            for item in value:
                new, f = self.scrub_value(item, key)
                out.append(new)
                findings.extend(f)
            return (tuple(out) if isinstance(value, tuple) else out), findings
        return value, []

    def scrub_mapping(self, attrs: Mapping[str, Any]) -> tuple[dict[str, Any], list[Finding]]:
        out: dict[str, Any] = {}
        findings: list[Finding] = []
        for k, v in attrs.items():
            new, f = self.scrub_value(v, k)
            out[k] = new
            findings.extend(f)
        return out, findings

    def _record(self, value: T, findings: list[Finding]) -> tuple[T, list[Finding]]:
        for f in findings:
            self.stats[(f.detector, f.action)] += 1
        return value, findings
