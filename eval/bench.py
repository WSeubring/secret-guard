#!/usr/bin/env python3
"""Hook latency on real traffic: a sample of past prompts and tool calls, one process per event.

usage: eval/bench.py [--n 1000]
"""
import argparse
import json
import os
import random
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import corpus_scan  # noqa: E402
import sg  # noqa: E402


def timed(cmd, data):
    t = time.perf_counter()
    subprocess.run(cmd, input=data, capture_output=True)
    return (time.perf_counter() - t) * 1000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1000)
    args = ap.parse_args()
    events = [json.dumps(ev).encode() for _, ev in corpus_scan.transcript_cases()]
    random.Random(1).shuffle(events)
    events = events[: args.n]

    floor = sorted(timed(["/usr/bin/true"], b"") for _ in range(300))
    ts = sorted(timed([sg.BIN], e) for e in events)
    q = lambda xs, p: xs[min(len(xs) - 1, int(len(xs) * p))]
    print(f"spawn floor (/usr/bin/true)  p50 {q(floor, .5):.2f} ms")
    print(f"secret-guard, {len(ts)} real events  p50 {q(ts, .5):.2f}  p95 {q(ts, .95):.2f}  p99 {q(ts, .99):.2f}  max {ts[-1]:.2f} ms")


if __name__ == "__main__":
    main()
