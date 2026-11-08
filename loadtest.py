"""Single-instance load test: full flow (enroll, 2 signed batches, evaluate) over real HTTP.

    python loadtest.py [--sessions 200] [--concurrency 8] [--url http://host:port]

Without --url it starts the app under uvicorn (one process) and tests that. The client is Python, so on a
small machine the client can be the bottleneck: treat the numbers as a floor for one instance, not a
capacity figure. This does NOT test a shared store, several instances or a network. Those are not built.
"""

import argparse
import os
import statistics
import subprocess
import sys
import threading
import time
import urllib.request

import requests

from fortguard.client import HttpTransport
from fortguard.generator import SCENARIOS, build_session

PORT = 8793


def start_server():
    code = ("import uvicorn; from uvicorn.middleware.wsgi import WSGIMiddleware; from fortguard.app import create_app; "
            f"uvicorn.run(WSGIMiddleware(create_app(), workers=16), host='127.0.0.1', port={PORT}, log_level='warning')")
    proc = subprocess.Popen([sys.executable, "-c", code], cwd=os.path.dirname(os.path.abspath(__file__)))
    for _ in range(100):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/healthz", timeout=1)
            return proc
        except Exception:
            time.sleep(0.2)
    proc.kill()
    raise SystemExit("server did not start")


def pct(values, p):
    values = sorted(values)
    return values[min(len(values) - 1, int(len(values) * p / 100))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=200)
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--url")
    args = ap.parse_args()

    proc = None if args.url else start_server()
    base = args.url or f"http://127.0.0.1:{PORT}"
    try:
        now_ms = int(time.time() * 1000)
        print(f"preparing {args.sessions} signed sessions...", flush=True)
        sessions = [build_session(SCENARIOS[i % len(SCENARIOS)], now_ms, seed=i) for i in range(args.sessions)]
        from fortguard.client import enroll_device
        t = HttpTransport(base)
        for s in sessions:
            assert enroll_device(t, s["device"], now_ms)[0] == 201

        lat = {"telemetry": [], "evaluate": []}
        server_ms, errors, lock = [], [], threading.Lock()
        queue = list(sessions)

        def worker():
            http = requests.Session()
            while True:
                with lock:
                    if not queue:
                        return
                    s = queue.pop()
                try:
                    for batch in s["batches"]:
                        t0 = time.perf_counter()
                        r = http.post(base + "/v1/telemetry/stream", json=batch, timeout=30)
                        lat["telemetry"].append((time.perf_counter() - t0) * 1000)
                        if r.status_code != 202:
                            errors.append(("telemetry", r.status_code))
                    t0 = time.perf_counter()
                    r = http.post(base + "/v1/risk/evaluate", json=s["evaluate"], headers={"X-API-Key": t.api_key}, timeout=30)
                    lat["evaluate"].append((time.perf_counter() - t0) * 1000)
                    if r.status_code == 200:
                        server_ms.append(r.json()["latency_ms"])
                    else:
                        errors.append(("evaluate", r.status_code))
                except Exception as exc:  # noqa: BLE001
                    errors.append(("exception", repr(exc)[:60]))

        started = time.perf_counter()
        threads = [threading.Thread(target=worker) for _ in range(args.concurrency)]
        [th.start() for th in threads]
        [th.join() for th in threads]
        wall = time.perf_counter() - started

        total = sum(len(v) for v in lat.values())
        print(f"\n{args.sessions} sessions, concurrency {args.concurrency}, {wall:.1f} s, {total} requests, {len(errors)} errors")
        print(f"throughput: {total / wall:.0f} requests/s, {args.sessions / wall:.1f} full sessions/s")
        for name, values in lat.items():
            print(f"{name:10s} end-to-end ms   p50 {pct(values, 50):7.1f}   p95 {pct(values, 95):7.1f}   p99 {pct(values, 99):7.1f}   max {max(values):7.1f}")
        if server_ms:
            print(f"scoring inside the server (ms)   p50 {pct(server_ms, 50):7.2f}   p95 {pct(server_ms, 95):7.2f}   p99 {pct(server_ms, 99):7.2f}")
        if errors:
            print("errors:", statistics.mode(errors), "...")
    finally:
        if proc:
            proc.terminate()


if __name__ == "__main__":
    main()
