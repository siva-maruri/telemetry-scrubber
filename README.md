# telemetry-scrubber

Scrubs PII and secrets out of OpenTelemetry spans and log records before they get stored.

Telemetry leaks more than people expect: bearer tokens in captured headers, SAS URLs in
error messages, customer emails in span names because someone templated the route wrong.
Once that lands in a trace store with 90-day retention and broad read access, it's a problem.
This library is the piece that sits in the pipeline and cleans it up.

## What it does

- **Regex detectors** for emails, US phone numbers, SSNs, card numbers (Luhn-checked),
  JWTs, AWS access keys, Azure SAS signatures, storage/Event Hubs connection-string keys,
  bearer tokens, and PEM private keys.
- **Entropy detection** for secrets that don't match a known format (random API keys,
  internal tokens).
- **Redaction** for secrets. Always. There's no reason to keep a partial API key.
- **Tokenization** for PII you still want to group by (emails, user ids). Same input, same
  token, so counts and joins still work on the scrubbed data.
- An OpenTelemetry `SpanExporter` wrapper, a small CLI for JSON-lines dumps, and an
  example Collector config for the pattern-based part.

## Quick start

```bash
pip install -e ".[otel]"
```

```python
from telemetry_scrubber import Scrubber, Tokenizer

scrubber = Scrubber(tokenizer=Tokenizer.from_env())  # key from SCRUBBER_TOKEN_KEY (base64)

scrubber.scrub_text("password reset for jane.doe@contoso.com")
# ('password reset for tok_v1_...', [Finding(detector='email', action='tokenize', key=None)])

scrubber.scrub_mapping(
    {
        "http.request.header.authorization": "Bearer eyJhbGciOi...",
        "url.full": "https://acct.blob.core.windows.net/c/b?sv=2022-11-02&sig=Xy7Q...%3D",
        "enduser.id": "cust-88213",
    }
)
# authorization -> [REDACTED]
# url.full      -> ...&sig=[REDACTED:azure_sas_sig]
# enduser.id    -> tok_v1_...
```

### In an instrumented service

```python
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from telemetry_scrubber.otel import ScrubbingSpanExporter

exporter = ScrubbingSpanExporter(OTLPSpanExporter(), scrubber)
provider.add_span_processor(BatchSpanProcessor(exporter))
```

Span names, attributes, event attributes and status descriptions are scrubbed. Trace and
span ids are left alone so traces still stitch together.

### Key from Azure Key Vault

```python
tok = Tokenizer.from_key_vault("https://<vault>.vault.azure.net", "scrubber-token-key")
```

Uses `DefaultAzureCredential`, so managed identity / workload identity works without any
secret in config. The first 8 chars of the secret version become the token prefix
(`tok_a1b2c3d4_...`), which tells you which key produced a token after a rotation.
Needs `pip install -e ".[azure]"`.

### Collector

`examples/otel-collector/config.yaml` handles the cheap cases in the Collector (drop auth
headers, mask card numbers with the `redaction` processor, strip SAS `sig=` values with
OTTL). Validated against otelcol-contrib 0.161.0. Entropy and tokenization stay in
Python because they need the key and more context than OTTL has.

### Old dumps

```bash
bash scripts/scan_dumps.sh ./dumps            # what would be scrubbed, per file
bash scripts/scan_dumps.sh ./dumps ./clean    # write scrubbed copies
```

## Design notes

**HMAC, not a plain hash.** SHA-256 of an email looks anonymous but isn't: hash a list of
known addresses and compare. HMAC with a key held in Key Vault closes that off. The
detector name is mixed into the input, so the same string under different detectors gets
different tokens.

**Rotation breaks joins across the boundary.** A new key means new tokens. That's the
trade-off for being able to rotate at all. The version prefix at least makes it visible.

**Entropy is allowlisted by attribute key, not by shape.** A W3C trace id is 32 hex chars.
So are a lot of vendor API keys. Allowlisting "32-char hex" would wave those keys through,
so the allowlist is attribute names (`trace_id`, `span_id`, `traceparent`, `*.sha256`,
...). Downside: a trace id pasted into a free-text log body gets redacted. Log it as a
structured attribute instead, which OTel does anyway.

**Entropy only fills gaps.** Its candidate tokens are greedy (it would grab `sig=AbC...`
including the `sig=`), so where a named detector already matched, the named detector wins.

**Base64-looking strings need digits plus upper and lower case** before entropy is even
checked. That removes most of the noise from long identifiers like
`OrderFulfillmentServiceHandler` or pod names.

**Fail closed.** Attributes marked for tokenization are redacted if no key is configured,
rather than passed through in clear.

## Known gaps

- Phone detection is US-only.
- No name or street-address detection. Regex is the wrong tool for that; it would need an
  NER model, which is too slow for this path.
- Log records via the SDK aren't wrapped yet, only spans. The CLI and Collector config
  cover logs for now.
- Thresholds (4.5 bits/char for base64, 3.0 for hex) are starting points taken from common
  secret scanners. Expect to tune them on real traffic.

## Development

```bash
pip install -e ".[dev]"
ruff check . && pytest -q
```
