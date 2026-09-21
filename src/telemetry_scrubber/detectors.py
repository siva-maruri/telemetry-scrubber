"""Regex detectors for PII and secrets that show up in spans and logs."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

PII = "pii"
SECRET = "secret"


def luhn_ok(candidate: str) -> bool:
    digits = [int(c) for c in candidate if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def card_spans(run: str) -> list[tuple[int, int]]:
    """Card numbers inside a run of digit groups, e.g. "4111 1111 1111 1111 0".

    The run regex is greedy, so a card followed by another digit group used to be checked
    as one 17-digit number, fail Luhn, and slip through. Cards are made of whole groups,
    so try every contiguous span of groups with 13-19 digits, longest first. A run with no
    separators is a single group, which keeps long numeric ids from being carved up into
    windows that pass Luhn by chance.
    """
    groups = [(m.start(), m.end()) for m in re.finditer(r"\d+", run)]
    spans: list[tuple[int, int]] = []
    i = 0
    while i < len(groups):
        for j in range(len(groups) - 1, i - 1, -1):
            digits = "".join(run[s:e] for s, e in groups[i : j + 1])
            if 13 <= len(digits) <= 19 and luhn_ok(digits):
                spans.append((groups[i][0], groups[j][1]))
                i = j + 1
                break
        else:
            i += 1
    return spans


def international_phone_spans(candidate: str) -> list[tuple[int, int]]:
    """E.164 says 15 digits at most, and nothing real is shorter than 8 with a country code."""
    digits = sum(c.isdigit() for c in candidate)
    return [(0, len(candidate))] if 8 <= digits <= 15 else []


@dataclass(frozen=True)
class Detector:
    name: str
    kind: str
    pattern: re.Pattern[str]
    # Optional: narrow a regex match to the parts that really are a hit (offsets relative
    # to the match). Used for cards, where the regex finds digit runs and Luhn decides.
    refine: Callable[[str], list[tuple[int, int]]] | None = None
    # Cheap pre-check. Most attribute values can't possibly match, and skipping the full
    # pattern for them is most of the scrubber's throughput (see bench/).
    hint: str | re.Pattern[str] | None = None

    def could_match(self, text: str) -> bool:
        if self.hint is None:
            return True
        if isinstance(self.hint, str):
            return self.hint in text
        return self.hint.search(text) is not None

    def find(self, text: str) -> Iterator[tuple[int, int]]:
        # If the pattern has a group named "v", only that part gets replaced.
        # Keeps things like "sig=" or "AccountKey=" readable in the output.
        for m in self.pattern.finditer(text):
            if self.refine is not None:
                for start, end in self.refine(m.group(0)):
                    yield m.start() + start, m.start() + end
                continue
            if "v" in self.pattern.groupindex:
                yield m.start("v"), m.end("v")
            else:
                yield m.start(), m.end()


def default_detectors() -> list[Detector]:
    return [
        Detector("email", PII, re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), hint="@"),
        Detector(
            "ssn",
            PII,
            re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)"),
            hint=re.compile(r"\d{3}-\d{2}-"),
        ),
        # US format without a country code. Needs a separator before the last four digits,
        # otherwise every 10-digit id in a URL gets flagged.
        Detector(
            "phone",
            PII,
            re.compile(r"(?<![\d-])(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]\d{4}(?![\d-])"),
            hint=re.compile(r"\d{3}[\s.-]\d{4}"),
        ),
        # Anything written with a leading + and a country code: +44 20 7946 0958,
        # +91 98765 43210, +49 (0)30 123456. The + is what keeps this from matching every
        # long number; without it, only the US pattern above applies.
        Detector(
            "phone_intl",
            PII,
            re.compile(r"(?<![\w+])\+\d(?:[\s.-]?\(?\d+\)?){2,7}(?!\d)"),
            refine=international_phone_spans,
            hint="+",
        ),
        Detector(
            "card",
            PII,
            re.compile(r"(?<!\d)\d(?:[ -]?\d){12,}(?!\d)"),
            refine=card_spans,
            hint=re.compile(r"(?:\d[ -]?){3}\d"),
        ),
        Detector(
            "jwt",
            SECRET,
            re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
            hint="eyJ",
        ),
        Detector(
            "aws_access_key",
            SECRET,
            re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
            hint=re.compile(r"AKIA|ASIA"),
        ),
        Detector(
            "azure_sas_sig",
            SECRET,
            re.compile(r"(?i)\bsig=(?P<v>[A-Za-z0-9%+/=]{20,})"),
            hint=re.compile(r"(?i)sig="),
        ),
        Detector(
            "azure_account_key",
            SECRET,
            re.compile(r"(?i)\b(?:AccountKey|SharedAccessKey)=(?P<v>[A-Za-z0-9+/=]{20,})"),
            hint=re.compile(r"(?i)key="),
        ),
        Detector(
            "bearer_token",
            SECRET,
            re.compile(r"(?i)\bbearer\s+(?P<v>[A-Za-z0-9._~+/-]{20,}=*)"),
            hint=re.compile(r"(?i)bearer"),
        ),
        Detector(
            "private_key",
            SECRET,
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?(?:-----END[^-]*-----|$)"),
            hint="PRIVATE KEY",
        ),
    ]
