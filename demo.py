"""Run every synthetic scenario through the API and print a table.

    python demo.py                          # in-process, no server needed
    python demo.py --url http://127.0.0.1:8080   # against a running server 

The data is synthetic. A table like this proves the rules and the plumbing work as written. It is
not evidence of how well FortGuard will catch real fraud.
"""

import argparse
import time

from fortguard.app import create_app
from fortguard.client import HttpTransport, InProcessTransport, run_session
from fortguard.generator import ORDER, SCENARIOS, build_session


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", help="base URL of a running server; default is in-process")
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    transport = HttpTransport(args.url) if args.url else InProcessTransport(create_app())
    now_ms = int(time.time() * 1000)
    print(f"{'scenario':<20}{'score':>6}  {'level':<8}{'ok':<4} reasons")
    failures = 0
    for name in SCENARIOS:
        session = build_session(name, now_ms, args.seed)
        status, body = run_session(transport, session)
        if status != 200:
            print(f"{name:<20} HTTP {status}: {body}")
            failures += 1
            continue
        level = body["risk_level"]
        ok = ORDER[session["expected_at_most"]] >= ORDER[level] >= ORDER[session["expected_at_least"]]
        failures += 0 if ok else 1
        reasons = ", ".join(r.replace("REASON_", "") for r in body["reason_codes"]) or "-"
        print(f"{name:<20}{body['risk_score']:>6}  {level:<8}{'yes' if ok else 'NO':<4} {reasons}")
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
