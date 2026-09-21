from telemetry_scrubber import Scrubber, Tokenizer

TOK = Tokenizer(b"k" * 32)


def test_redacts_without_tokenizer():
    s = Scrubber()
    out, findings = s.scrub_text("login failed for jane@example.com")
    assert out == "login failed for [REDACTED:email]"
    assert [f.detector for f in findings] == ["email"]


def test_tokenizes_pii_but_never_cards():
    s = Scrubber(tokenizer=TOK)
    out, _ = s.scrub_text("jane@example.com paid with 4111111111111111")
    assert out.startswith("tok_v1_")
    assert out.endswith("[REDACTED:card]")


def test_same_email_same_token_across_fields():
    s = Scrubber(tokenizer=TOK)
    a, _ = s.scrub_text("jane@example.com", "messaging.destination")
    b, _ = s.scrub_text("contact jane@example.com", "log.body")
    assert b.endswith(a)


def test_drop_and_tokenize_keys():
    s = Scrubber(tokenizer=TOK)
    attrs = {
        "http.request.header.authorization": "Basic dXNlcjpwYXNz",
        "enduser.id": "cust-88213",
        "http.route": "/api/orders/{id}",
    }
    out, _ = s.scrub_mapping(attrs)
    assert out["http.request.header.authorization"] == "[REDACTED]"
    assert out["enduser.id"].startswith("tok_v1_")
    assert out["http.route"] == "/api/orders/{id}"


def test_overlap_prefers_longest_match():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    out, findings = Scrubber().scrub_text(f"Bearer {jwt}")
    assert jwt not in out
    assert len(findings) == 1


def test_sas_url_keeps_structure():
    url = "https://acct.blob.core.windows.net/c/b?sv=2022-11-02&sig=AbCdEf1234567890abcdefGHIJKL%3D&se=2026"
    out, _ = Scrubber().scrub_text(url, "url.full")
    assert "sig=[REDACTED:azure_sas_sig]" in out
    assert out.startswith("https://acct.blob.core.windows.net/c/b?sv=2022-11-02&")


def test_nested_and_non_string_values():
    s = Scrubber()
    out, findings = s.scrub_value({"a": ["x@y.com", 3], "b": {"c": True}, "d": ("ok", "p@q.io")})
    assert out == {"a": ["[REDACTED:email]", 3], "b": {"c": True}, "d": ("ok", "[REDACTED:email]")}
    assert len(findings) == 2


def test_stats_count_findings():
    s = Scrubber()
    s.scrub_text("a@b.com c@d.com")
    assert s.stats[("email", "redact")] == 2


def test_clean_text_untouched():
    text = "GET /api/v2/orders/{id} 200 in 34ms region=westus2 pod=checkout-7f9c8d6b5-x2k9p"
    assert Scrubber().scrub_text(text) == (text, [])


def test_tokenize_keys_fail_closed_without_key():
    out, findings = Scrubber().scrub_mapping({"enduser.id": "cust-88213"})
    assert out == {"enduser.id": "[REDACTED]"}
    assert findings[0].action == "redact"
