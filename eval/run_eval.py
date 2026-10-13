#!/usr/bin/env python3
"""Run the labelled eval set through the release binary and report precision/recall.

usage: eval/run_eval.py [--seeds N] [--show N]
"""
import argparse
import collections
import json
import os
import subprocess
import sys
import time

import sg

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "eval", "out")


def text_of(ev):
    return ev.get("prompt") or json.dumps(ev.get("tool_input"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--show", type=int, default=15)
    args = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)

    cases = []
    for seed in range(1, args.seeds + 1):
        out = subprocess.run([sys.executable, os.path.join(ROOT, "eval", "gen_cases.py"), str(seed)],
                             capture_output=True, text=True, check=True).stdout
        for line in out.splitlines():
            c = json.loads(line)
            c["id"] = f"{seed}-{c['id']}"
            cases.append(c)
    with open(os.path.join(OUT, "cases.jsonl"), "w") as f:
        f.writelines(json.dumps(c) + "\n" for c in cases)

    t0 = time.perf_counter()
    results = {c["id"]: r for c, r in zip(cases, sg.run("eval", [c["event"] for c in cases]))}
    elapsed = time.perf_counter() - t0

    stats = collections.defaultdict(lambda: collections.Counter())
    fps, fns = [], []
    for c in cases:
        hit = bool(results[c["id"]]["rules"])
        key = (c["label"], c["family"])
        if c["label"] == "secret":
            stats[key]["tp" if hit else "fn"] += 1
            if not hit:
                fns.append((c, results[c["id"]]))
        else:
            stats[key]["fp" if hit else "tn"] += 1
            if hit:
                fps.append((c, results[c["id"]]))

    tp = sum(s["tp"] for s in stats.values())
    fn = sum(s["fn"] for s in stats.values())
    fp = sum(s["fp"] for s in stats.values())
    tn = sum(s["tn"] for s in stats.values())
    print(f"cases: {len(cases)}  (secret {tp + fn}, clean {fp + tn})   scan time {elapsed * 1000:.0f} ms total")
    print(f"recall    {tp / max(1, tp + fn):.4f}  ({tp}/{tp + fn})")
    print(f"precision {tp / max(1, tp + fp):.4f}  false positives {fp}/{fp + tn}")

    print("\nper family (secret: recall | clean: false positives):")
    for (label, fam), s in sorted(stats.items()):
        if label == "secret" and s["fn"]:
            print(f"  secret {fam:32} recall {s['tp']}/{s['tp'] + s['fn']}")
        if label == "clean" and s["fp"]:
            print(f"  clean  {fam:32} FP {s['fp']}/{s['fp'] + s['tn']}")

    by_kind = collections.Counter((c["label"], c["kind"]) for c, _ in fns)
    if by_kind:
        print("\nmisses by context:", dict(by_kind))
        by_reason = collections.Counter(x for _, r in fns for x in (r["rejected"] or ["no-candidate"]))
        print("misses by rule:reason:", dict(by_reason.most_common()))
    for c, r in fps[: args.show]:
        print(f"\nFP {c['id']} {c['family']}/{c['kind']} rules={r['rules']} secrets={r['secrets']}\n   {text_of(c['event'])[:300]!r}")
    for c, r in fns[: args.show]:
        print(f"\nFN {c['id']} {c['family']}/{c['kind']} rejected={r['rejected']}\n   {text_of(c['event'])[:300]!r}")
    return 1 if fp else 0


if __name__ == "__main__":
    sys.exit(main())
