import secrets

from telemetry_scrubber import EntropyDetector, shannon_entropy


def found(det, text, key=None):
    return [text[s:e] for s, e in det.find(text, key)]


def test_entropy_bounds():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert round(shannon_entropy("abcd"), 3) == 2.0


def test_random_secret_flagged():
    det = EntropyDetector()
    token = secrets.token_urlsafe(32)
    # token_urlsafe can, very rarely, produce no digit; retry to keep the test stable
    while not any(c.isdigit() for c in token):
        token = secrets.token_urlsafe(32)
    assert found(det, f"x-internal-key: {token}") == [token]


def test_trace_id_allowed_by_key_not_by_shape():
    det = EntropyDetector()
    trace_id = secrets.token_hex(16)
    assert found(det, trace_id, key="trace_id") == []
    # same shape under an unrelated key is treated as a possible API key
    assert found(det, trace_id, key="config.value") == [trace_id]


def test_hash_suffix_allowed():
    det = EntropyDetector()
    assert found(det, secrets.token_hex(32), key="artifact.sha256") == []


def test_identifiers_and_uuids_not_flagged():
    det = EntropyDetector()
    for text in [
        "checkout-service-7f9c8d6b5-x2k9p",
        "application/vnd.api+json",
        "OrderFulfillmentServiceHandler",
        "3f2b8c1e-9a4d-4e6b-8f7a-1c2d3e4f5a6b",
    ]:
        assert found(det, text) == [], text
