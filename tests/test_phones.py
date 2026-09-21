import pytest

pytest.importorskip("phonenumbers")

from telemetry_scrubber import Scrubber, Tokenizer, default_detectors  # noqa: E402
from telemetry_scrubber.phones import local_phone_detector  # noqa: E402


def scrubber(*regions):
    return Scrubber(detectors=[*default_detectors(), local_phone_detector(regions)])


@pytest.mark.parametrize(
    "regions,text,expected",
    [
        (["GB"], "call 020 7946 0958 about the refund", "call [REDACTED:phone_local] about the refund"),
        (["IN"], "customer 098765 43210 called", "customer [REDACTED:phone_local] called"),
        (["DE"], "Tel 030 123456", "Tel [REDACTED:phone_local]"),
        (
            ["GB", "IN"],
            "uk 020 7946 0958, in 098765 43210",
            "uk [REDACTED:phone_local], in [REDACTED:phone_local]",
        ),
    ],
)
def test_local_numbers_in_configured_regions(regions, text, expected):
    assert scrubber(*regions).scrub_text(text)[0] == expected


@pytest.mark.parametrize(
    "text",
    [
        "order 12345678 shipped",
        "build 2026.09.14 finished in 1234 ms",
        "GET /api/v2/orders/4155550 200",
        "invoice INV-2026-000184",
    ],
)
def test_ids_and_dates_are_not_phone_numbers(text):
    assert scrubber("GB", "IN", "DE").scrub_text(text) == (text, [])


def test_only_configured_regions_are_checked():
    # A London number isn't valid in the German numbering plan.
    assert scrubber("DE").scrub_text("call 020 7946 0958")[0] == "call 020 7946 0958"


def test_local_numbers_are_tokenized_like_other_phones():
    s = Scrubber(
        detectors=[*default_detectors(), local_phone_detector(["GB"])], tokenizer=Tokenizer(b"k" * 32)
    )
    assert s.scrub_text("call 020 7946 0958")[0].startswith("call tok_v1_")


def test_unknown_region_rejected():
    with pytest.raises(ValueError):
        local_phone_detector(["XX"])
