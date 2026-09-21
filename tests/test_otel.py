from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import Status, StatusCode

from telemetry_scrubber import Scrubber, Tokenizer
from telemetry_scrubber.otel import ScrubbingSpanExporter


def test_spans_scrubbed_before_export():
    memory = InMemorySpanExporter()
    provider = TracerProvider()
    scrubber = Scrubber(tokenizer=Tokenizer(b"k" * 32))
    provider.add_span_processor(SimpleSpanProcessor(ScrubbingSpanExporter(memory, scrubber)))
    tracer = provider.get_tracer("test")

    with tracer.start_as_current_span("GET /users/jane@example.com") as span:
        span.set_attribute("http.request.header.authorization", "Bearer abc.def.ghi")
        span.set_attribute("enduser.id", "cust-88213")
        span.set_attribute("http.response.status_code", 500)
        span.add_event("retry", {"note": "card 4111111111111111 declined"})
        span.set_status(Status(StatusCode.ERROR, "timeout calling jane@example.com"))
        trace_id = span.get_span_context().trace_id

    (out,) = memory.get_finished_spans()
    assert "jane@example.com" not in out.name
    assert out.attributes["http.request.header.authorization"] == "[REDACTED]"
    assert out.attributes["enduser.id"].startswith("tok_v1_")
    assert out.attributes["http.response.status_code"] == 500
    assert out.events[0].attributes["note"] == "card [REDACTED:card] declined"
    assert "jane@example.com" not in out.status.description
    assert out.context.trace_id == trace_id
