"""Traffic generator for the monitoring demo: it fills the dashboard and trips the 5XX alarm.

    python scripts/load.py --url <alb_url> --seconds 120 --concurrency 4 --rate 5
    python scripts/load.py --url <alb_url> --errors 10

By default it posts the files in samples/ in rotation to /api/scan, then prints requests
sent, a count per status and per served_by, and p50/p95 latency. With --errors it requests
/simulate-error instead, a deliberate 500. In both modes requests are paced to stay under
--rate requests a second, counted across all threads together (default 5).

A demonstration tool, not a load test: a failed request is counted, never raised and never
retried, because the point is to see failures.
"""

import argparse
import math
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import requests

SAMPLES_DIRECTORY = Path(__file__).resolve().parent.parent / "samples"
SCAN_PATH = "/api/scan"
ERROR_PATH = "/simulate-error"
UPLOAD_FIELD = "file"
TIMEOUT_SECONDS = 10
DEFAULT_SECONDS = 60
# How many requests may be in flight at once. The rate, not this, sets the volume.
DEFAULT_CONCURRENCY = 4
# Requests per second, all threads together. Enough to fill the graphs, far from enough to
# stress two t3.micro or spend their credits; unpaced, four threads keep every worker busy.
DEFAULT_RATE = 5.0
MILLISECONDS_PER_SECOND = 1000
NO_SERVER = "(not reported)"

type Sample = tuple[str, bytes]  # a file's name and content, as requests takes an upload


@dataclass(frozen=True)
class Outcome:
    """How one request went."""

    status: str  # the HTTP status code, or the name of the error that prevented an answer
    served_by: str | None  # the instance that answered, when the answer says so
    seconds: float


class Pacer:
    """Hands out turns to send, evenly spaced, so that all threads together stay under a rate."""

    def __init__(self, rate: float) -> None:
        self._interval = 1 / rate
        self._next_turn = time.monotonic()
        self._lock = threading.Lock()

    def wait(self, deadline: float = math.inf) -> bool:
        """Sleep until the caller's turn to send. False, at once, if it comes after the deadline.

        A turn missed while requests are slow is not saved up, so a slow spell is never
        followed by a burst.
        """
        with self._lock:
            turn = max(self._next_turn, time.monotonic())
            if turn >= deadline:
                return False
            self._next_turn = turn + self._interval
        time.sleep(max(turn - time.monotonic(), 0))
        return True


def main(arguments: list[str] | None = None) -> int:
    """Run the generator from the command line and return the process's exit code."""
    options = _parse(arguments)
    url = options.url.rstrip("/")
    if options.errors:
        outcomes = send_errors(url, options)
        print("status codes:", " ".join(outcome.status for outcome in outcomes))
        return 0
    samples = read_samples(SAMPLES_DIRECTORY)
    if not samples:
        print(f"No sample files in {SAMPLES_DIRECTORY}", file=sys.stderr)
        return 1
    print(summarise(send_scans(url, samples, options)))
    return 0


def read_samples(directory: Path) -> list[Sample]:
    """Return the directory's files in name order, without hidden ones such as .gitkeep.

    Returns [] when the directory has none or does not exist.
    """
    files = sorted(path for path in directory.glob("[!.]*") if path.is_file())
    return [(path.name, path.read_bytes()) for path in files]


def send_errors(url: str, options: argparse.Namespace) -> list[Outcome]:
    """Request the deliberate error options.errors times, at no more than options.rate a second."""
    pacer = Pacer(options.rate)
    outcomes = []
    for _ in range(options.errors):
        pacer.wait()
        outcomes.append(send("GET", url + ERROR_PATH))
    return outcomes


def send_scans(url: str, samples: list[Sample], options: argparse.Namespace) -> list[Outcome]:
    """Post the samples in rotation from options.concurrency threads for options.seconds.

    The threads share one pacer, so together they send no more than options.rate a second.
    """
    deadline = time.monotonic() + options.seconds
    pacer = Pacer(options.rate)

    def post_until_deadline(first: int) -> list[Outcome]:
        # Each thread starts one sample further on, so the rotation is mixed from the start.
        outcomes = []
        while pacer.wait(deadline):
            sample = samples[(first + len(outcomes)) % len(samples)]
            outcomes.append(send("POST", url + SCAN_PATH, sample))
        return outcomes

    with ThreadPoolExecutor(max_workers=options.concurrency) as pool:
        batches = list(pool.map(post_until_deadline, range(options.concurrency)))
    return [outcome for batch in batches for outcome in batch]


def send(method: str, url: str, upload: Sample | None = None) -> Outcome:
    """Send one request and report how it went. A failure is an outcome, never an exception."""
    files = {UPLOAD_FIELD: upload} if upload else None
    started = time.perf_counter()
    try:
        response = requests.request(method, url, files=files, timeout=TIMEOUT_SECONDS)
    except requests.RequestException as error:
        return Outcome(type(error).__name__, None, time.perf_counter() - started)
    return Outcome(str(response.status_code), _served_by(response), time.perf_counter() - started)


def summarise(outcomes: list[Outcome]) -> str:
    """Return the report: requests sent, counts per status and per served_by, p50 and p95."""
    statuses = Counter(outcome.status for outcome in outcomes)
    servers = Counter(outcome.served_by or NO_SERVER for outcome in outcomes)
    lines = [f"requests sent: {len(outcomes)}", "status:"]
    lines += [f"  {status}: {count}" for status, count in sorted(statuses.items())]
    lines += ["served_by:"]
    lines += [f"  {server}: {count}" for server, count in sorted(servers.items())]
    if outcomes:
        ordered = sorted(outcome.seconds * MILLISECONDS_PER_SECOND for outcome in outcomes)
        p50, p95 = (round(percentile(ordered, percent)) for percent in (50, 95))
        lines += [f"latency: p50 {p50} ms, p95 {p95} ms"]
    return "\n".join(lines)


def percentile(ordered: list[float], percent: int) -> float:
    """Return the smallest value that percent% of the ordered, non-empty list does not exceed."""
    rank = math.ceil(percent / 100 * len(ordered))
    return ordered[max(rank, 1) - 1]


def _served_by(response: requests.Response) -> str | None:
    """Return served_by from a JSON answer. None for anything else, such as a 502 page."""
    try:
        body = response.json()
    except ValueError:
        return None
    return body.get("served_by") if isinstance(body, dict) else None


def _parse(arguments: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send demo traffic to the phishing detector.")
    parser.add_argument("--url", required=True, help="address of the service: the alb_url output")
    parser.add_argument("--seconds", type=int, default=DEFAULT_SECONDS)
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("--rate", type=float, default=DEFAULT_RATE, help="most requests a second")
    parser.add_argument("--errors", type=int, default=0, help="send this many /simulate-error")
    options = parser.parse_args(arguments)
    if min(options.seconds, options.concurrency) < 1 or options.errors < 0 or options.rate <= 0:
        parser.error(
            "--seconds, --concurrency must be 1 or more, --errors 0 or more, --rate above 0"
        )
    return options


if __name__ == "__main__":
    sys.exit(main())
