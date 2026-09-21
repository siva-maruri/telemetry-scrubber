"""Precision and recall of the entropy detector, and how they move with the thresholds.

    python bench/eval_entropy.py                 # synthetic corpus
    python bench/eval_entropy.py labelled.jsonl  # your own sample: {"text": ..., "secret": true|false}

The synthetic corpus is a sanity check, not a verdict: real traffic has its own shapes of
identifiers. Label a few hundred values from your own spans and run it on those before
changing the defaults.
"""

import base64
import json
import random
import string
import sys
import uuid

from telemetry_scrubber import EntropyDetector

rng = random.Random(11)  # fixed seed: the table below should be reproducible


def rand_bytes(n: int) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(n))


def token_urlsafe(n: int) -> str:
    return base64.urlsafe_b64encode(rand_bytes(n)).rstrip(b"=").decode()


def token_hex(n: int) -> str:
    return rand_bytes(n).hex()


WORDS = (
    "order payment refund customer invoice service handler checkout inventory shipment "
    "account session token cache worker queue batch export import report region"
).split()


def secret_values(n: int) -> list[str]:
    makers = [
        lambda: token_urlsafe(rng.choice([18, 24, 32, 40])),  # opaque API tokens
        lambda: token_hex(rng.choice([16, 20, 32])),  # hex keys
        lambda: base64.b64encode(rand_bytes(rng.choice([24, 32, 48]))).decode(),
        lambda: "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(40)),
    ]
    return [rng.choice(makers)() for _ in range(n)]


def benign_values(n: int) -> list[str]:
    def camel() -> str:
        return "".join(w.capitalize() for w in rng.sample(WORDS, rng.randint(3, 5)))

    def pod() -> str:
        name = "-".join(rng.sample(WORDS, 2))
        suffix = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(5))
        return f"{name}-{token_hex(5)[:9]}-{suffix}"

    makers = [
        camel,
        pod,
        lambda: str(uuid.UUID(int=rng.getrandbits(128), version=4)),
        lambda: f"/api/v{rng.randint(1, 3)}/{rng.choice(WORDS)}s/{{id}}/{rng.choice(WORDS)}",
        lambda: (
            f"{rng.choice(WORDS)}_{rng.randint(2019, 2026)}"
            f"_{rng.randint(1, 12):02d}_{rng.randint(1, 28):02d}.parquet"
        ),
        lambda: (
            f"{rng.randint(0, 9)}.{rng.randint(0, 40)}.{rng.randint(0, 20)}-build.{rng.randint(100, 9999)}"
        ),
        lambda: " ".join(rng.sample(WORDS, 6)),
        lambda: f"{rng.choice(WORDS).upper()}_{rng.choice(WORDS).upper()}_TIMEOUT_MS",
        # Hard cases: mixed case plus digits, like real class and client names.
        lambda: f"{camel()}V{rng.randint(2, 12)}",
        lambda: f"Azure{camel()}{rng.randint(2019, 2026)}Client",
        # Git SHAs in free text are benign but look exactly like hex keys. They're flagged
        # unless they sit under an allowlisted attribute such as vcs.revision.
        lambda: f"deployed commit {token_hex(20)}",
    ]
    return [rng.choice(makers)() for _ in range(n)]


def load(path: str | None) -> list[tuple[str, bool]]:
    if path:
        with open(path, encoding="utf-8") as f:
            return [(r["text"], bool(r["secret"])) for r in map(json.loads, f) if r.get("text")]
    return [(v, True) for v in secret_values(1500)] + [(v, False) for v in benign_values(3000)]


def score(det: EntropyDetector, data: list[tuple[str, bool]]) -> tuple[float, float]:
    tp = fp = fn = 0
    for text, is_secret in data:
        flagged = any(True for _ in det.find(text))
        tp += flagged and is_secret
        fp += flagged and not is_secret
        fn += (not flagged) and is_secret
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    return precision, recall


def main() -> None:
    data = load(sys.argv[1] if len(sys.argv) > 1 else None)
    positives = sum(s for _, s in data)
    print(f"{len(data)} values, {positives} secrets\n")
    print(f"{'b64 bits':>8} {'hex bits':>8} {'precision':>10} {'recall':>8}")
    for b64 in (4.0, 4.25, 4.5, 4.75, 5.0):
        for hexb in (2.75, 3.0, 3.25):
            p, r = score(EntropyDetector(b64_threshold=b64, hex_threshold=hexb), data)
            mark = "  <- default" if (b64, hexb) == (4.5, 3.0) else ""
            print(f"{b64:>8} {hexb:>8} {p:>10.3f} {r:>8.3f}{mark}")


if __name__ == "__main__":
    main()
