# Changelog

## 0.2.0

- Cards: a card number followed by another digit group (`4111 1111 1111 1111 0`) was
  missed. Card detection now checks contiguous digit groups inside a run. Found by the new
  property tests.
- Rescan strings that had a finding, so redacting one match can't expose another and
  scrubbing is stable when applied twice.
- Per-detector pre-checks and a length floor for the entropy pass. About 26% less time per
  span in `bench/`.
- Property-based tests (hypothesis), `mypy --strict`, `py.typed`.

## 0.1.0

- Regex and entropy detection, redaction, HMAC tokenization with Key Vault loading,
  OpenTelemetry span exporter wrapper, CLI, Collector example config.
