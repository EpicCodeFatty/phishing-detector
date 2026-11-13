"""Tests for the demo traffic generator. No request leaves the machine: requests is faked."""

import argparse

import pytest
import requests

from scripts import load

URL = "http://alb.example"
SAMPLES = [("first.eml", b"one"), ("second.eml", b"two")]


class FakeResponse:
    """What load reads from a response: the status code and the JSON body."""

    def __init__(self, status_code: int, body: object = None) -> None:
        self.status_code = status_code
        self.body = body

    def json(self) -> object:
        if self.body is None:
            raise ValueError("not JSON")
        return self.body


@pytest.fixture
def sent(monkeypatch):
    """Answer every request with a 200 from one instance, and record what was sent."""
    calls = []

    def request(method, url, **options):
        calls.append({"method": method, "url": url, **options})
        return FakeResponse(200, {"served_by": "i-0aaa"})

    monkeypatch.setattr(load.requests, "request", request)
    return calls


class FakeClock:
    """Time that passes only when something sleeps, or a test moves it on."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    """Replace the clock load paces itself by, so pacing is exact and no test really waits."""
    fake = FakeClock()
    monkeypatch.setattr(load.time, "monotonic", fake.monotonic)
    monkeypatch.setattr(load.time, "sleep", fake.sleep)
    return fake


def answer_with(monkeypatch, response: FakeResponse) -> None:
    monkeypatch.setattr(load.requests, "request", lambda *args, **options: response)


def test_send_reports_the_status_and_the_instance_that_answered(sent):
    outcome = load.send("POST", URL + load.SCAN_PATH, SAMPLES[0])

    assert (outcome.status, outcome.served_by) == ("200", "i-0aaa")


def test_send_uploads_the_sample_in_the_field_the_application_reads(sent):
    load.send("POST", URL + load.SCAN_PATH, SAMPLES[0])

    assert sent[0]["files"] == {"file": SAMPLES[0]}


def test_every_request_has_a_timeout(sent):
    load.send("GET", URL + load.ERROR_PATH)

    assert sent[0]["timeout"] == load.TIMEOUT_SECONDS


@pytest.mark.parametrize("error", [requests.ConnectionError, requests.Timeout])
def test_a_failed_request_is_counted_under_the_error_name_not_raised(monkeypatch, error):
    def fail(*args, **options):
        raise error("no answer")

    monkeypatch.setattr(load.requests, "request", fail)

    outcome = load.send("GET", URL)

    assert (outcome.status, outcome.served_by) == (error.__name__, None)


@pytest.mark.parametrize(
    "body",
    [
        None,  # the load balancer's own error page: HTML
        {"error": "Something went wrong"},  # the application's error: JSON without served_by
        ["unexpected"],
    ],
)
def test_an_answer_that_names_no_instance_reports_none(monkeypatch, body):
    answer_with(monkeypatch, FakeResponse(502, body))

    outcome = load.send("GET", URL)

    assert (outcome.status, outcome.served_by) == ("502", None)


def test_scans_rotate_through_the_samples_until_the_time_is_up(sent, clock):
    options = argparse.Namespace(seconds=2, concurrency=1, rate=2)

    outcomes = load.send_scans(URL, SAMPLES, options)

    assert len(outcomes) == 4  # sent at 0, 0.5, 1 and 1.5 seconds
    assert [call["files"]["file"][0] for call in sent] == [
        "first.eml",
        "second.eml",
        "first.eml",
        "second.eml",
    ]
    assert {call["url"] for call in sent} == {URL + "/api/scan"}


def test_turns_are_spaced_evenly_to_stay_under_the_rate(clock):
    pacer = load.Pacer(4)
    turns = []

    for _ in range(5):
        pacer.wait()
        turns.append(clock.now)

    assert turns == [0.0, 0.25, 0.5, 0.75, 1.0]


def test_a_slow_request_is_not_followed_by_a_burst(clock):
    pacer = load.Pacer(4)
    pacer.wait()
    clock.now = 3.0  # the request took three seconds: eleven turns went unused
    turns = []

    for _ in range(3):
        pacer.wait()
        turns.append(clock.now)

    assert turns == [3.0, 3.25, 3.5]


def test_a_turn_that_falls_after_the_deadline_is_refused_without_waiting(clock):
    pacer = load.Pacer(1)

    granted = [pacer.wait(deadline=0.5), pacer.wait(deadline=0.5)]

    assert granted == [True, False]
    assert clock.now == 0.0


def test_all_threads_together_stay_under_the_rate(sent):
    # Real time and real threads. At 20 a second, turns come every 0.05 seconds, so 0.275
    # seconds has room for six, however many threads are sending. The window ends between
    # two turns, so rounding cannot let a seventh in. A pacer per thread would send 24.
    options = argparse.Namespace(seconds=0.275, concurrency=4, rate=20)

    outcomes = load.send_scans(URL, SAMPLES, options)

    assert 1 <= len(outcomes) <= 6


@pytest.mark.parametrize(
    "percent,expected",
    [
        (50, 5.0),
        (95, 10.0),
        (100, 10.0),
        (1, 1.0),
    ],
)
def test_percentile_of_one_to_ten(percent, expected):
    ordered = [float(value) for value in range(1, 11)]

    assert load.percentile(ordered, percent) == expected


def test_percentile_of_a_single_value_is_that_value():
    assert load.percentile([0.25], 95) == 0.25


def test_summary_counts_requests_statuses_and_instances_and_gives_latency():
    outcomes = [
        load.Outcome("200", "i-0aaa", 0.100),
        load.Outcome("200", "i-0bbb", 0.200),
        load.Outcome("200", "i-0aaa", 0.300),
        load.Outcome("ReadTimeout", None, 10.0),
    ]

    summary = load.summarise(outcomes)

    assert summary.splitlines() == [
        "requests sent: 4",
        "status:",
        "  200: 3",
        "  ReadTimeout: 1",
        "served_by:",
        "  (not reported): 1",
        "  i-0aaa: 2",
        "  i-0bbb: 1",
        "latency: p50 200 ms, p95 10000 ms",
    ]


def test_summary_of_no_requests_has_no_latency_line():
    assert load.summarise([]).splitlines() == ["requests sent: 0", "status:", "served_by:"]


def test_errors_mode_requests_the_error_route_and_prints_each_status(monkeypatch, clock, capsys):
    requested = []

    def request(method, url, **options):
        requested.append((method, url))
        return FakeResponse(500, {"error": "Something went wrong"})

    monkeypatch.setattr(load.requests, "request", request)

    exit_code = load.main(["--url", URL + "/", "--errors", "3"])

    assert exit_code == 0
    assert requested == [("GET", URL + "/simulate-error")] * 3
    assert capsys.readouterr().out == "status codes: 500 500 500\n"


def test_errors_mode_says_when_the_server_has_error_simulation_off(monkeypatch, clock, capsys):
    answer_with(monkeypatch, FakeResponse(404, None))

    exit_code = load.main(["--url", URL, "--errors", "2"])

    assert exit_code == 1
    assert capsys.readouterr().out == ("status codes: 404 404\n" + load.SWITCHED_OFF_MESSAGE + "\n")


def test_errors_mode_is_paced_too(sent, clock):
    load.main(["--url", URL, "--errors", "3", "--rate", "2"])

    assert len(sent) == 3
    assert clock.now == 1.0  # sent at 0, 0.5 and 1 second


def test_the_default_rate_is_five_requests_a_second(sent, clock):
    load.main(["--url", URL, "--errors", "2"])

    assert clock.now == pytest.approx(1 / 5)


def test_default_mode_posts_the_repository_samples_and_prints_the_summary(sent, clock, capsys):
    arguments = ["--url", URL, "--seconds", "1", "--concurrency", "1", "--rate", "2"]

    exit_code = load.main(arguments)

    assert exit_code == 0
    assert capsys.readouterr().out.startswith("requests sent: 2\nstatus:\n  200: 2\n")


def test_no_samples_is_an_error_with_a_message(sent, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(load, "SAMPLES_DIRECTORY", tmp_path / "missing")

    exit_code = load.main(["--url", URL])

    assert exit_code == 1
    assert "No sample files" in capsys.readouterr().err
    assert sent == []


@pytest.mark.parametrize(
    "option,value",
    [
        ("--seconds", "0"),
        ("--concurrency", "0"),
        ("--errors", "-1"),
        ("--rate", "0"),
    ],
)
def test_a_count_that_makes_no_sense_is_refused(option, value, capsys):
    with pytest.raises(SystemExit):
        load.main(["--url", URL, option, value])

    assert "must be 1 or more" in capsys.readouterr().err


def test_samples_are_read_in_name_order_without_hidden_files(tmp_path):
    (tmp_path / "second.eml").write_bytes(b"two")
    (tmp_path / "first.eml").write_bytes(b"one")
    (tmp_path / ".gitkeep").write_bytes(b"")
    (tmp_path / "folder").mkdir()

    samples = load.read_samples(tmp_path)

    assert samples == SAMPLES


def test_the_repository_has_samples_to_send():
    names = [name for name, _ in load.read_samples(load.SAMPLES_DIRECTORY)]

    assert "paypal-phish.eml" in names
    assert ".gitkeep" not in names
