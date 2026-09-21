"""Deterministic tokenization so scrubbed fields can still be joined and counted."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os


class Tokenizer:
    """HMAC-SHA256 tokens, e.g. ``tok_v1_3f9a1c0b7d2e4a6f``.

    Plain SHA-256 of an email is reversible in practice (hash every address you can
    find and compare), so the key matters. The version goes into the token so that
    after a rotation you can tell which key produced which value.
    """

    def __init__(self, key: bytes, key_version: str = "v1", length: int = 16):
        if len(key) < 32:
            raise ValueError("tokenization key should be at least 32 bytes")
        self._key = key
        self.key_version = key_version
        self.length = length

    def token(self, value: str, kind: str = "") -> str:
        msg = f"{kind}:{value}".encode()
        digest = hmac.new(self._key, msg, hashlib.sha256).hexdigest()
        return f"tok_{self.key_version}_{digest[: self.length]}"

    @classmethod
    def from_env(cls, var: str = "SCRUBBER_TOKEN_KEY", version_var: str = "SCRUBBER_TOKEN_KEY_VERSION"):
        raw = os.environ.get(var)
        if not raw:
            raise RuntimeError(f"{var} is not set")
        return cls(base64.b64decode(raw), key_version=os.environ.get(version_var, "v1"))

    @classmethod
    def from_key_vault(cls, vault_url: str, secret_name: str, version: str | None = None):
        """Load the key from Azure Key Vault (base64 secret). Needs the [azure] extra."""
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient

        client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
        secret = client.get_secret(secret_name, version)
        return cls(base64.b64decode(secret.value), key_version=secret.properties.version[:8])
