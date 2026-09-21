import logging

import pytest

pytest.importorskip("opentelemetry.sdk._logs")

# The SDK's LoggingHandler is deprecated in favour of opentelemetry-instrumentation-logging,
# but it's the simplest way to produce real log records here.
pytestmark = pytest.mark.filterwarnings("ignore:.*LoggingHandler.*:DeprecationWarning")

from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler  # noqa: E402
from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter, SimpleLogRecordProcessor  # noqa: E402
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402

from telemetry_scrubber import Scrubber, Tokenizer  # noqa: E402
from telemetry_scrubber.otel_logs import ScrubbingLogRecordExporter  # noqa: E402


@pytest.fixture
def emit():
    memory = InMemoryLogRecordExporter()
    provider = LoggerProvider()
    scrubber = Scrubber(tokenizer=Tokenizer(b"k" * 32))
    provider.add_log_record_processor(SimpleLogRecordProcessor(ScrubbingLogRecordExporter(memory, scrubber)))
    logger = logging.getLogger("test_otel_logs")
    logger.handlers[:] = [LoggingHandler(logger_provider=provider)]
    logger.propagate = False
    logger.setLevel(logging.INFO)
    yield logger, memory
    provider.shutdown()


def test_body_and_attributes_scrubbed(emit):
    logger, memory = emit
    logger.warning(
        "upload failed: %s for %s",
        "https://a.blob.core.windows.net/c?sig=Xy7Qp9LmN2vR5tK8wZ3aB6cD1eF4gH0%3D",
        "jane.doe@contoso.com",
        extra={"enduser.id": "cust-88213", "http.request.header.authorization": "Bearer abc"},
    )
    (record,) = memory.get_finished_logs()
    body = record.log_record.body
    attrs = record.log_record.attributes
    assert "sig=[REDACTED:azure_sas_sig]" in body
    assert "jane.doe@contoso.com" not in body and "tok_v1_" in body
    assert attrs["enduser.id"].startswith("tok_v1_")
    assert attrs["http.request.header.authorization"] == "[REDACTED]"
    assert record.log_record.severity_text == "WARN"


def test_exception_message_scrubbed_and_trace_context_kept(emit):
    logger, memory = emit
    tracer = TracerProvider().get_tracer("t")
    with tracer.start_as_current_span("work") as span:
        try:
            raise ValueError("card 4111 1111 1111 1111 declined")
        except ValueError:
            logger.exception("payment failed")
        trace_id = span.get_span_context().trace_id

    (record,) = memory.get_finished_logs()
    attrs = record.log_record.attributes
    assert attrs["exception.message"] == "card [REDACTED:card] declined"
    assert "4111" not in attrs["exception.stacktrace"]
    assert record.log_record.trace_id == trace_id
