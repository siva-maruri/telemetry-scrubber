import base64
import sys
import types

import pytest

from telemetry_scrubber import Tokenizer

KEY = b"k" * 32


def test_deterministic_and_versioned():
    t = Tokenizer(KEY, key_version="v2")
    a = t.token("jane@example.com", "email")
    assert a == t.token("jane@example.com", "email")
    assert a.startswith("tok_v2_") and len(a) == len("tok_v2_") + 16


def test_kind_and_key_change_token():
    t = Tokenizer(KEY)
    assert t.token("42", "user.id") != t.token("42", "customer.id")
    assert t.token("42", "user.id") != Tokenizer(b"j" * 32).token("42", "user.id")


def test_short_key_rejected():
    with pytest.raises(ValueError):
        Tokenizer(b"short")


def test_from_env(monkeypatch):
    monkeypatch.setenv("SCRUBBER_TOKEN_KEY", base64.b64encode(KEY).decode())
    monkeypatch.setenv("SCRUBBER_TOKEN_KEY_VERSION", "2026q1")
    assert Tokenizer.from_env().token("x").startswith("tok_2026q1_")


def test_from_key_vault_uses_secret_version(monkeypatch):
    calls = {}

    class FakeSecretClient:
        def __init__(self, vault_url, credential):
            calls["url"] = vault_url

        def get_secret(self, name, version=None):
            calls["name"] = name
            props = types.SimpleNamespace(version="a1b2c3d4e5f60718293a4b5c6d7e8f90")
            return types.SimpleNamespace(value=base64.b64encode(KEY).decode(), properties=props)

    identity = types.ModuleType("azure.identity")
    identity.DefaultAzureCredential = lambda: object()
    kv = types.ModuleType("azure.keyvault.secrets")
    kv.SecretClient = FakeSecretClient
    monkeypatch.setitem(sys.modules, "azure", types.ModuleType("azure"))
    monkeypatch.setitem(sys.modules, "azure.identity", identity)
    monkeypatch.setitem(sys.modules, "azure.keyvault", types.ModuleType("azure.keyvault"))
    monkeypatch.setitem(sys.modules, "azure.keyvault.secrets", kv)

    t = Tokenizer.from_key_vault("https://kv-telemetry.vault.azure.net", "scrubber-token-key")
    assert calls == {"url": "https://kv-telemetry.vault.azure.net", "name": "scrubber-token-key"}
    assert t.key_version == "a1b2c3d4"
