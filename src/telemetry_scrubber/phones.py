"""Local-format phone numbers (no + country code), validated with libphonenumber.

Regex alone can't tell `020 7946 0958` (a London number) from an order id, which is why the
default detectors only catch numbers written with a leading +. If you know which countries
your users are in, this detector checks candidate digit runs against those regions' real
numbering plans and only flags valid numbers. Needs the [phones] extra.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from .detectors import PII, Detector

# Digit runs with the usual separators, at least 7 characters. Deliberately loose: the
# numbering-plan check below is what decides.
_CANDIDATE = re.compile(r"(?<![\w+])\(?\d[\d\s().-]{5,}\d(?![\w])")


def local_phone_detector(regions: Sequence[str]) -> Detector:
    """Detector for national-format numbers in the given ISO 3166 regions, e.g. ["GB", "IN"]."""
    import phonenumbers
    from phonenumbers import Leniency, PhoneNumberMatcher

    regions = [r.upper() for r in regions]
    for region in regions:
        if region not in phonenumbers.SUPPORTED_REGIONS:
            raise ValueError(f"unknown region {region!r}")

    def spans(candidate: str) -> list[tuple[int, int]]:
        found: list[tuple[int, int]] = []
        for region in regions:
            # VALID alone is too loose for some plans: Indian landlines accept most 10-11
            # digit strings, so "2026-000184" passes. STRICT_GROUPING also requires the digits
            # to be grouped the way that country writes numbers, which ids never are.
            for m in PhoneNumberMatcher(candidate, region, leniency=Leniency.STRICT_GROUPING):
                if all(m.end <= s or m.start >= e for s, e in found):
                    found.append((m.start, m.end))
        return sorted(found)

    return Detector("phone_local", PII, _CANDIDATE, refine=spans)
