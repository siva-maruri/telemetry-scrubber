"""Property-based checks. These cover the things example tests can't: the pre-check hints
never change results, scrubbing is stable when applied twice, and planted secrets never
survive no matter what text surrounds them."""

import dataclasses

from hypothesis import given, settings
from hypothesis import strategies as st

from telemetry_scrubber import Scrubber, Tokenizer, default_detectors

FRAGMENTS = [
    "sig=",
    "AccountKey=",
    "Bearer ",
    "eyJ",
    "AKIA",
    "ASIA",
    "@",
    "-",
    " ",
    ".",
    "/",
    "?",
    "&",
    "=",
    "4111 1111 1111 1111",
    "5500-0000-0000-0004",
    "123-45-6789",
    "(415) 555-0132",
    "-----BEGIN PRIVATE KEY-----",
    "jane.doe@example.com",
    "trace_id",
    "0123456789abcdef",
]

text = st.lists(
    st.one_of(st.sampled_from(FRAGMENTS), st.text(alphabet="aZ09-_+/=. @%", min_size=1, max_size=24)),
    max_size=12,
).map("".join)

TOK = Tokenizer(b"k" * 32)
with_hints = Scrubber(tokenizer=TOK)
without_hints = Scrubber(
    tokenizer=TOK,
    detectors=[dataclasses.replace(d, hint=None) for d in default_detectors()],
)


@settings(max_examples=400, deadline=None)
@given(text, st.sampled_from([None, "log.body", "url.full", "trace_id"]))
def test_hints_never_change_the_result(value, key):
    assert with_hints.scrub_text(value, key) == without_hints.scrub_text(value, key)


@settings(max_examples=300, deadline=None)
@given(text)
def test_scrubbing_twice_changes_nothing(value):
    once, _ = with_hints.scrub_text(value)
    twice, findings = with_hints.scrub_text(once)
    assert twice == once
    assert findings == []


@settings(max_examples=300, deadline=None)
@given(
    text,
    text,
    st.sampled_from(
        [
            "jane.doe@example.com",
            "AKIAIOSFODNN7EXAMPLE",
            "4111 1111 1111 1111",
            "sig=Xy7Qp9LmN2vR5tK8wZ3aB6cD1eF4gH0%3D",
        ]
    ),
)
def test_planted_secret_never_survives(before, after, secret):
    # Separators around the plant so it isn't glued into a longer, different token. The
    # surrounding text can contain the same characters glued to other digits or letters
    # (then it isn't that secret any more), so compare counts: the planted copy must go.
    value = secret.split("=", 1)[-1]
    raw = f"{before} {secret} {after}"
    out, _ = with_hints.scrub_text(raw)
    assert out.count(value) < raw.count(value)
