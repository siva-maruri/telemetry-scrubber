"""Scrub OpenTelemetry log records before export.

Wraps a LogRecordExporter from the SDK logs API (``opentelemetry.sdk._logs``). That API is
still underscore-prefixed upstream and has changed shape between releases; this is written
against opentelemetry-sdk 1.44.
"""

from __future__ import annotations

from collections.abc import Sequence

from opentelemetry._logs import LogRecord
from opentelemetry.sdk._logs import ReadableLogRecord
from opentelemetry.sdk._logs.export import LogRecordExporter, LogRecordExportResult

from .scrubber import Scrubber


class ScrubbingLogRecordExporter(LogRecordExporter):
    def __init__(self, inner: LogRecordExporter, scrubber: Scrubber | None = None):
        self._inner = inner
        self._scrubber = scrubber or Scrubber()

    def export(self, batch: Sequence[ReadableLogRecord]) -> LogRecordExportResult:
        return self._inner.export([self._scrub(r) for r in batch])

    def shutdown(self) -> None:
        self._inner.shutdown()  # type: ignore[no-untyped-call]  # untyped upstream

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self._inner.force_flush(timeout_millis)

    def _scrub(self, record: ReadableLogRecord) -> ReadableLogRecord:
        lr = record.log_record
        body, _ = self._scrubber.scrub_value(lr.body, "log.body")
        attributes, _ = self._scrubber.scrub_mapping(lr.attributes or {})
        clean = LogRecord(
            timestamp=lr.timestamp,
            observed_timestamp=lr.observed_timestamp,
            context=lr.context,  # carries the trace and span ids
            severity_text=lr.severity_text,
            severity_number=lr.severity_number,
            body=body,
            attributes=attributes,
            event_name=lr.event_name,
            # The exception object is left behind on purpose: the logging handler has
            # already copied its type, message and stack into attributes, which were just
            # scrubbed. Passing the object on would let an exporter re-read the raw message.
        )
        return ReadableLogRecord(
            clean,
            resource=record.resource,
            instrumentation_scope=record.instrumentation_scope,
            limits=record.limits,
        )
