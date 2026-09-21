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


@dataclass(frozen=True)
class Detector:
    name: str
    kind: str
    pattern: re.Pattern
    validate: Callable[[str], bool] | None = None

    def find(self, text: str) -> Iterator[tuple[int, int]]:
        # If the pattern has a group named "v", only that part gets replaced.
        # Keeps things like "sig=" or "AccountKey=" readable in the output.
        for m in self.pattern.finditer(text):
            if self.validate and not self.validate(m.group(0)):
                continue
            if "v" in self.pattern.groupindex:
                yield m.start("v"), m.end("v")
            else:
                yield m.start(), m.end()


def default_detectors() -> list[Detector]:
    return [
        Detector("email", PII, re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
        Detector(
            "ssn",
            PII,
            re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)"),
        ),
        # US numbers only for now. Needs a separator before the last four digits,
        # otherwise every 10-digit id in a URL gets flagged.
        Detector(
            "phone",
            PII,
            re.compile(r"(?<![\d-])(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]\d{4}(?![\d-])"),
        ),
        Detector("card", PII, re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), validate=luhn_ok),
        Detector(
            "jwt",
            SECRET,
            re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        ),
        Detector(
            "aws_access_key",
            SECRET,
            re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
        ),
        Detector("azure_sas_sig", SECRET, re.compile(r"(?i)\bsig=(?P<v>[A-Za-z0-9%+/=]{20,})")),
        Detector(
            "azure_account_key",
            SECRET,
            re.compile(r"(?i)\b(?:AccountKey|SharedAccessKey)=(?P<v>[A-Za-z0-9+/=]{20,})"),
        ),
        Detector(
            "bearer_token",
            SECRET,
            re.compile(r"(?i)\bbearer\s+(?P<v>[A-Za-z0-9._~+/-]{20,}=*)"),
        ),
        Detector(
            "private_key",
            SECRET,
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?(?:-----END[^-]*-----|$)"),
        ),
    ]
