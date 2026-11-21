"""Qualify the gateway speed-test deadline with a controlled HTTP(S) server.

Required device inputs are explicit. The harness checks the running build,
starts only transient speed tests, and writes a private report. Self-test
uses loopback and never connects to an ESP.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime
import getpass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import statistics
import threading
import time
import urllib.request

from test_snmp_device import login

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD_SIZE = 128 * 1024
TEST_SECONDS = 3
RESOURCE_FIELDS = ("internal_free", "internal_min", "internal_largest",
                   "psram_free", "psram_largest", "sockets_used")
CASES = ("complete", "late-headers", "silent-body", "trickle")


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        case = self.path.removeprefix("/")
        if case not in CASES:
            self.send_error(404)
            return
        self.connection.settimeout(2)
        try:
            if case == "late-headers" and self.server.stop.wait(13 * self.server.scale):
                return
            self.send_response(200)
            self.send_header("Content-Length", str(PAYLOAD_SIZE))
            self.end_headers()
            if case == "silent-body" and self.server.stop.wait(7 * self.server.scale):
                return
            if case == "trickle":
                for _ in range(PAYLOAD_SIZE // 1024):
                    self.wfile.write(b"\0" * 1024)
                    if self.server.stop.wait(.12 * self.server.scale):
                        return
            else:
                self.wfile.write(b"\0" * PAYLOAD_SIZE)
        except OSError:
            # A deadline or ordinary client disconnect stops the fixture.
            pass

    def log_message(self, *_):
        pass


@contextmanager
def fixture(address, tls=None, scale=1):
    with ThreadingHTTPServer(address, FixtureHandler) as server:
        server.stop = threading.Event()
        server.scale = scale
        if tls:
            server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_port
        finally:
            server.stop.set()
            server.shutdown()
            thread.join()


def status_sample(api):
    reply = api("/api/status", timeout=4)
    return reply["uptime_s"], bool(reply["tailscale"]["connected"])


def resources(api):
    snapshot = api("/api/operations", timeout=4)
    return {key: snapshot[key] for key in RESOURCE_FIELDS if key in snapshot}


def check_result(case, result, wall):
    received, seconds = result["bytes"], result["elapsed_ms"] / 1000
    if case == "complete":
        assert received == PAYLOAD_SIZE and result["http"] == 200
        assert result["result"] == "file complete" and wall < 6
    elif case == "late-headers":
        assert received == 0 and seconds == 0
        assert result["result"] == "response headers timed out" and 9 <= wall <= 12.5
    else:
        assert result["http"] == 200 and result["result"] == "time limit reached"
        assert 2.9 <= seconds <= 3.6 and 2.9 <= wall <= 5
        assert (received == 0 if case == "silent-body" else 0 < received < PAYLOAD_SIZE)


def measure(api, origin, case):
    uptime, tailnet = status_sample(api)
    before = resources(api)
    begin = time.monotonic()
    assert api("/api/diag/speedtest", {"url": f"{origin}/{case}", "seconds": TEST_SECONDS},
               timeout=4)["ok"]
    samples, resource_samples = [], []
    stop_after = 15 if case == "late-headers" else 8
    while time.monotonic() - begin < stop_after:
        started = time.monotonic()
        current_uptime, current_tailnet = status_sample(api)
        samples.append((time.monotonic() - started) * 1000)
        assert current_uptime >= uptime, "Unexpected reboot during a measurement"
        assert not tailnet or current_tailnet, "Tailnet disconnected during a measurement"
        uptime = current_uptime
        report = api("/api/diag/speedtest", timeout=4)
        if not report["running"]:
            wall = time.monotonic() - begin
            try:
                check_result(case, report, wall)
                passed = True
            except AssertionError:
                passed = False
            return {
                "case": case, "passed": passed, "bytes": report["bytes"], "payload_ms": report["elapsed_ms"],
                "wall_ms": round(wall * 1000), "result": report["result"],
                "control_ms_median": round(statistics.median(samples), 1),
                "control_ms_worst": round(max(samples), 1), "control_samples": len(samples),
                "before": before, "during": resource_samples, "after": resources(api),
            }
        if len(samples) % 3 == 1:
            resource_samples.append(resources(api))
        time.sleep(.2)
    raise AssertionError(f"{case}: gateway still reports the speed test running")


def self_test():
    with fixture(("127.0.0.1", 0), scale=.02) as port:
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for case in CASES:
            start = time.monotonic()
            with client.open(f"http://127.0.0.1:{port}/{case}", timeout=2) as response:
                headers = time.monotonic()
                assert response.headers["Content-Length"] == str(PAYLOAD_SIZE)
                assert len(response.read()) == PAYLOAD_SIZE
            if case == "late-headers":
                assert headers - start >= .13
            elif case == "silent-body":
                assert time.monotonic() - headers >= .07
            elif case == "trickle":
                assert time.monotonic() - headers >= .15
    check_result("late-headers", {"bytes": 0, "elapsed_ms": 0,
                 "result": "response headers timed out"}, 10.2)
    check_result("silent-body", {"bytes": 0, "elapsed_ms": 3050, "http": 200,
                 "result": "time limit reached"}, 3.3)
    print("PASS: all controlled response fixtures over loopback")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--allow-device-diagnostics", action="store_true")
    parser.add_argument("--host", type=ipaddress.IPv4Address)
    parser.add_argument("--expect-build")
    parser.add_argument("--bind", type=ipaddress.IPv4Address,
                        help="Owned workstation IPv4 reachable from the ESP")
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--tls-hostname", help="Certificate hostname resolving to --bind")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not (args.allow_device_diagnostics and args.host and args.bind and args.expect_build):
        parser.error("Require --allow-device-diagnostics, --host, --bind and --expect-build")
    if args.bind.is_unspecified or args.bind.is_loopback or args.bind.is_multicast:
        parser.error("A device test requires a specific owned LAN or Tailnet bind address")
    https = bool(args.cert or args.key or args.tls_hostname)
    if https and not (args.cert and args.key and args.tls_hostname):
        parser.error("Verified HTTPS requires --cert, --key and --tls-hostname together")
    tls = None
    if https:
        if socket.gethostbyname(args.tls_hostname) != str(args.bind):
            parser.error("TLS hostname must resolve to the fixture address")
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(args.cert, args.key)
    secret = os.environ.get("TEST_DEVICE_PASSWORD") or getpass.getpass("Device password (not saved): ")
    api = login(str(args.host), password=secret)
    del secret
    identity = api("/api/system")["build_commit"]
    if identity != args.expect_build:
        raise RuntimeError("Running build does not match the candidate")
    folder = ROOT / "build/private-device"
    folder.mkdir(parents=True, exist_ok=True)
    report_path = folder / f"throughput-deadline-{datetime.now():%Y%m%d-%H%M%S-%f}.json"
    report = {"build": identity, "transport": "https" if https else "http",
              "completed": False, "cases": []}
    try:
        with fixture((str(args.bind), 0), tls) as port:
            origin = f"{report['transport']}://{args.tls_hostname if https else args.bind}:{port}"
            for case in CASES:
                try:
                    observation = measure(api, origin, case)
                except (OSError, AssertionError, KeyError, ValueError) as error:
                    report["cases"].append({"case": case, "passed": False,
                                            "error_type": type(error).__name__})
                    raise
                report["cases"].append(observation)
                if not observation["passed"]:
                    raise AssertionError(f"{case}: timing or result outside the expected range")
                print(f"PASS {case}: {observation['wall_ms']} ms, {observation['bytes']} bytes", flush=True)
        report["completed"] = True
    finally:
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
