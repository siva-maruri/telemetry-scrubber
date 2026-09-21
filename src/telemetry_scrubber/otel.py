"""Wraps an OpenTelemetry SpanExporter so spans are scrubbed before they leave the process."""

from __future__ import annotations

from collections.abc import Sequence

from opentelemetry.sdk.trace import Event, ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.trace import Status

from .scrubber import Scrubber


class ScrubbingSpanExporter(SpanExporter):
    def __init__(self, inner: SpanExporter, scrubber: Scrubber | None = None):
        self._inner = inner
        self._scrubber = scrubber or Scrubber()

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        return self._inner.export([self._scrub(s) for s in spans])

    def shutdown(self) -> None:
        self._inner.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self._inner.force_flush(timeout_millis)

    def _scrub(self, span: ReadableSpan) -> ReadableSpan:
        s = self._scrubber
        # Span names pick up raw paths ("GET /users/jane@x.com") more often than you'd think.
        name, _ = s.scrub_text(span.name, "span.name")
        attrs, _ = s.scrub_mapping(span.attributes or {})
        events = []
        for e in span.events:
            e_attrs, _ = s.scrub_mapping(e.attributes or {})
            events.append(Event(e.name, e_attrs, e.timestamp))
        status = span.status
        if status.description:
            desc, _ = s.scrub_text(status.description, "status.description")
            status = Status(status.status_code, desc)
        return ReadableSpan(
            name=name,
            context=span.context,
            parent=span.parent,
            resource=span.resource,
            attributes=attrs,
            events=events,
            links=span.links,
            kind=span.kind,
            status=status,
            start_time=span.start_time,
            end_time=span.end_time,
            instrumentation_scope=span.instrumentation_scope,
        )
