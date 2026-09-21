# telemetry-scrubber

Scrubs PII and secrets out of OpenTelemetry spans and log records before they get stored.

Telemetry leaks more than people expect: bearer tokens in captured headers, SAS URLs in
error messages, customer emails in span names because someone templated the route wrong.
Once that lands in a trace store with 90-day retention and broad read access, it's a problem.
This library is the piece that sits in the pipeline and cleans it up.

## What it does

- **Regex detectors** for emails, phone numbers (US format, and international with a `+`
  country code), SSNs, card numbers (Luhn-checked),
  JWTs, AWS access keys, Azure SAS signatures, storage/Event Hubs connection-string keys,
  bearer tokens, and PEM private keys.
- **Entropy detection** for secrets that don't match a known format (random API keys,
  internal tokens).
- **Redaction** for secrets. Always. There's no reason to keep a partial API key.
- **Tokenization** for PII you still want to group by (emails, user ids). Same input, same
  token, so counts and joins still work on the scrubbed data.
- OpenTelemetry exporter wrappers for spans and log records, a small CLI for JSON-lines
  dumps, and an example Collector config for the pattern-based part.

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

Log records work the same way:

```python
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from telemetry_scrubber.otel_logs import ScrubbingLogRecordExporter

logger_provider.add_log_record_processor(
    BatchLogRecordProcessor(ScrubbingLogRecordExporter(OTLPLogExporter(), scrubber))
)
```

The body and attributes are scrubbed, including `exception.message` and
`exception.stacktrace`, which is where card numbers and connection strings in error messages
usually end up. The logs SDK is still underscore-prefixed upstream and has changed between
releases; this is written against opentelemetry-sdk 1.44.

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

## Performance

`bench/bench_scrubber.py` scrubs 20,000 span-shaped attribute maps (15 to 18 attributes,
5% carrying a secret or PII). Per-detector pre-checks skip the full regex when a value
can't possibly match (no `@` means no email, no `sig=` means no SAS signature), and the
entropy pass skips anything under 20 characters. When those went in (0.2.0) the median
went from about 115 to about 85 microseconds per span on a single-vCPU sandbox, roughly
11,700 spans per second per core. Run it on your own hardware before sizing anything; the
number moves a lot with how much free text your spans carry.

A property test runs every generated input through the scrubber with and without the
pre-checks and requires identical output, so they can't quietly change what gets caught.

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

**Cards are matched by digit group, not by regex alone.** Property tests found that
`4111 1111 1111 1111 0` slipped through: the regex took all 17 digits, Luhn failed, and
nothing was redacted. Now the regex only finds digit runs, and the card check tries
contiguous groups of 13 to 19 digits inside them. A run with no separators stays one
group, so a 20-digit order id doesn't get carved into windows that pass Luhn by chance.

**Rescan after redacting.** The same tests found that redacting a PEM header could expose
a phone number whose boundary check had failed on the header's dashes. Strings that had a
finding get rescanned (up to two more passes) so scrubbing the output again changes
nothing.

**Fail closed.** Attributes marked for tokenization are redacted if no key is configured,
rather than passed through in clear.

## Known gaps

- International numbers are only caught with a leading `+` and country code. Local formats
  without one (`020 7946 0958`) vary too much by country to match without false positives.
- No name or street-address detection. Regex is the wrong tool for that; it would need an
  NER model, which is too slow for this path.
- Thresholds (4.5 bits/char for base64, 3.0 for hex) are starting points taken from common
  secret scanners. Expect to tune them on real traffic.

## Development

```bash
pip install -e ".[dev]"
ruff check . && mypy && pytest -q
python bench/bench_scrubber.py
```

The package is fully typed (`mypy --strict`, ships `py.typed`).
