#!/usr/bin/env python3
"""Score secret-guard (and gitleaks, if installed) on Samsung CredData, a public labelled benchmark.

CredData: 297 public repos, ~74k labelled lines; real credential values are replaced by
realistic fakes. Line-level scoring: a labelled line counts as flagged when a finding
overlaps it. GroundTruth T is a credential; F (false alarm) and X (example, test value)
are not.

setup (once, ~15 GB of clones, ~1 GB of data):
  git clone --depth 1 https://github.com/Samsung/CredData eval/out/creddata
  cd eval/out/creddata && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
  .venv/bin/python download_data.py --data_dir data --jobs 8

usage: eval/creddata.py [--no-gitleaks]
"""
import argparse
import bisect
import collections
import csv
import glob
import json
import os
import shutil
import subprocess
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "target", "release", "secret-guard")
DATA = os.path.join(ROOT, "eval", "out", "creddata")


def load_markup():
    rows = collections.defaultdict(list)
    for meta in glob.glob(os.path.join(DATA, "meta", "*.csv")):
        with open(meta, newline="") as f:
            for r in csv.DictReader(f):
                rows[r["FilePath"]].append((int(r["LineStart"]), int(r["LineEnd"]), r["GroundTruth"], r["Category"]))
    return rows


def ours(paths):
    """{path: set of flagged 1-based line numbers}"""
    payload, texts = [], {}
    for i, p in enumerate(paths):
        with open(os.path.join(DATA, p), "rb") as f:
            raw = f.read()
        text = raw.decode("utf-8", errors="replace")
        texts[i] = text.encode()
        payload.append(json.dumps({"id": i, "event": {"hook_event_name": "UserPromptSubmit", "prompt": text}}))
    out = subprocess.run([BIN, "eval"], input="\n".join(payload) + "\n", capture_output=True, text=True, check=True).stdout
    flagged = {}
    for r in map(json.loads, out.splitlines()):
        data = texts[r["id"]]
        newlines = [i for i, b in enumerate(data) if b == 0x0A]
        lines = set()
        for start, end in r["spans"]:
            first = bisect.bisect_left(newlines, start) + 1
            last = bisect.bisect_left(newlines, max(start, end - 1)) + 1
            lines.update(range(first, last + 1))
        flagged[paths[r["id"]]] = lines
    return flagged


def gitleaks(paths):
    with tempfile.TemporaryDirectory() as tmp:
        report = os.path.join(tmp, "report.json")
        subprocess.run(["gitleaks", "dir", os.path.join(DATA, "data"), "--no-banner", "--redact", "--exit-code", "0",
                        "--report-format", "json", "--report-path", report], capture_output=True, check=True)
        with open(report) as f:
            found = json.load(f)
    flagged = collections.defaultdict(set)
    for leak in found:
        rel = os.path.relpath(leak["File"], DATA)
        flagged[rel].update(range(leak["StartLine"], leak["EndLine"] + 1))
    return {p: flagged.get(p, set()) for p in paths}


def score(name, markup, flagged):
    c = collections.Counter()
    by_cat = collections.defaultdict(collections.Counter)
    unlabelled = 0
    for path, rows in markup.items():
        hit = flagged.get(path, set())
        labelled = set()
        for start, end, truth, category in rows:
            lines = set(range(start, end + 1))
            labelled |= lines
            flagged_row = bool(hit & lines)
            positive = truth == "T"
            c[("tp" if flagged_row else "fn") if positive else ("fp" if flagged_row else "tn")] += 1
            if positive:
                by_cat[category]["tp" if flagged_row else "fn"] += 1
        unlabelled += len(hit - labelled)
    tp, fp, fn, tn = c["tp"], c["fp"], c["fn"], c["tn"]
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    print(f"{name:13} TP {tp:5}  FP {fp:5}  FN {fn:5}  TN {tn:6}  precision {precision:.3f}  recall {recall:.3f}  "
          f"F1 {f1:.3f}  (+{unlabelled} hits on unlabelled lines)")
    return by_cat


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-gitleaks", action="store_true")
    args = ap.parse_args()
    markup = load_markup()
    paths = sorted(p for p in markup if os.path.isfile(os.path.join(DATA, p)))
    markup = {p: markup[p] for p in paths}
    print(f"CredData: {len(paths)} files, {sum(len(r) for r in markup.values())} labelled lines, "
          f"{sum(1 for r in markup.values() for x in r if x[2] == 'T')} credentials\n")
    by_cat = score("secret-guard", markup, ours(paths))
    if not args.no_gitleaks and shutil.which("gitleaks"):
        score("gitleaks", markup, gitleaks(paths))
    print("\nsecret-guard recall per category:")
    for cat, s in sorted(by_cat.items(), key=lambda kv: -(kv[1]["tp"] + kv[1]["fn"])):
        n = s["tp"] + s["fn"]
        print(f"  {cat:40} {s['tp']:5}/{n:<5} {s['tp'] / n:.2f}")


if __name__ == "__main__":
    main()
