"""Rough throughput check for the scrubber on span-shaped attribute maps.

    python bench/bench_scrubber.py

Numbers depend heavily on the machine and on how many attributes are long free text,
so treat them as relative (before/after a change), not as a capacity plan.
"""

import random
import statistics
import string
import time

from telemetry_scrubber import Scrubber, Tokenizer

random.seed(7)


def rand(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(random.choice(alphabet) for _ in range(n))


def clean_span() -> dict:
    # What most spans look like: short enum-ish values, routes, ids, numbers.
    return {
        "http.request.method": "GET",
        "http.route": "/api/v2/orders/{id}",
        "url.path": f"/api/v2/orders/{random.randint(1000, 99999)}",
        "http.response.status_code": 200,
        "server.address": "orders.internal",
        "network.protocol.version": "1.1",
        "user_agent.original": "okhttp/4.12.0",
        "k8s.pod.name": f"orders-{rand(9).lower()}-{rand(5).lower()}",
        "k8s.namespace.name": "checkout",
        "db.system.name": "postgresql",
        "db.query.text": "SELECT id, status, total FROM orders WHERE id = $1",
        "messaging.destination.name": "order-events",
        "trace_id": rand(32, "0123456789abcdef"),
        "thread.name": "worker-3",
        "code.function.name": "OrderService.get_order",
    }


def dirty_span() -> dict:
    span = clean_span()
    span["url.full"] = (
        "https://acct.blob.core.windows.net/exports/o.csv?sv=2022-11-02&sig=" + rand(43) + "%3D"
    )
    span["http.request.header.authorization"] = "Bearer " + rand(120)
    span["exception.message"] = f"card 4111 1111 1111 1111 declined for {rand(6).lower()}@example.com"
    return span


def run(scrubber: Scrubber, spans: list[dict], rounds: int = 5) -> list[float]:
    per_span_us = []
    for _ in range(rounds):
        start = time.perf_counter()
        for span in spans:
            scrubber.scrub_mapping(span)
        per_span_us.append((time.perf_counter() - start) / len(spans) * 1e6)
    return per_span_us


def main() -> None:
    spans = [dirty_span() if i % 20 == 0 else clean_span() for i in range(20_000)]
    for label, scrubber in [
        ("redact only", Scrubber()),
        ("with tokenization", Scrubber(tokenizer=Tokenizer(b"k" * 32))),
    ]:
        times = run(scrubber, spans)
        med = statistics.median(times)
        print(
            f"{label:<18} {med:6.1f} us/span   ~{1e6 / med:,.0f} spans/s per core   (15-18 attrs, 5% dirty)"
        )


if __name__ == "__main__":
    main()
