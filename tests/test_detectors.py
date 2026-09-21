import pytest

from telemetry_scrubber import luhn_ok
from telemetry_scrubber.detectors import default_detectors

DETECTORS = {d.name: d for d in default_detectors()}


def matches(name, text):
    return [text[s:e] for s, e in DETECTORS[name].find(text)]


@pytest.mark.parametrize(
    "number,ok",
    [
        ("4111111111111111", True),
        ("4111 1111 1111 1111", True),
        ("5500-0000-0000-0004", True),
        ("4111111111111112", False),
        ("1234567890", False),
    ],
)
def test_luhn(number, ok):
    assert luhn_ok(number) is ok


def test_card_needs_luhn():
    assert matches("card", "paid with 4111 1111 1111 1111 today") == ["4111 1111 1111 1111"]
    assert matches("card", "order 4111111111111112 shipped") == []


def test_email():
    text = "GET /users/jane.doe+test@example.co.uk/orders"
    assert matches("email", text) == ["jane.doe+test@example.co.uk"]


def test_ssn_skips_invalid_ranges():
    assert matches("ssn", "ssn=123-45-6789") == ["123-45-6789"]
    assert matches("ssn", "000-12-3456 666-12-3456 900-12-3456") == []


def test_phone_ignores_plain_ids():
    assert matches("phone", "call (415) 555-0132") == ["(415) 555-0132"]
    assert matches("phone", "/orders/4155550132") == []


def test_sas_sig_keeps_param_name():
    url = "https://acct.blob.core.windows.net/c/b?sv=2022-11-02&sig=AbCdEf1234567890abcdefGHIJKL%3D&se=2026"
    assert matches("azure_sas_sig", url) == ["AbCdEf1234567890abcdefGHIJKL%3D"]


def test_connection_string_account_key():
    cs = (
        "DefaultEndpointsProtocol=https;AccountName=x;"
        "AccountKey=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA==;EndpointSuffix=core"
    )
    assert matches("azure_account_key", cs) == ["Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA=="]


def test_aws_key_and_jwt():
    assert matches("aws_access_key", "key AKIAIOSFODNN7EXAMPLE used") == ["AKIAIOSFODNN7EXAMPLE"]
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    assert matches("jwt", f"token={jwt}") == [jwt]
