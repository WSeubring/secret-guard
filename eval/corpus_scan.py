#!/usr/bin/env python3
"""Run the detector over real data to hunt false positives. Prints redacted hits only; the binary redacts, so secrets never reach Python.

Sources:
  repos        every tracked text file in git repos under ~/Development, as a Write call
  transcripts  user prompts and tool_use inputs from ~/.claude/projects/**/*.jsonl

usage: eval/corpus_scan.py [repos|transcripts]... [--limit-per-rule N]
"""
import argparse
import collections
import glob
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("SG_BIN") or os.path.join(ROOT, "target", "release", "secret-guard")
HOME = os.path.expanduser("~")


def repo_cases():
    seen = set()
    for dirpath, dirnames, _ in os.walk(os.path.join(HOME, "Development")):
        if dirpath.count(os.sep) - HOME.count(os.sep) > 6:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", "worktrees", "target", "vendor", ".venv", "tmp")]
        if ".git" not in os.listdir(dirpath):
            continue
        try:
            files = subprocess.run(["git", "-C", dirpath, "ls-files", "-z"], capture_output=True, check=True).stdout.split(b"\0")
        except subprocess.CalledProcessError:
            continue
        for rel in files:
            if not rel:
                continue
            path = os.path.join(dirpath, rel.decode(errors="replace"))
            real = os.path.realpath(path)
            if real in seen or not os.path.isfile(real) or os.path.getsize(real) > 512_000:
                continue
            seen.add(real)
            try:
                data = open(real, "rb").read()
            except OSError:
                continue
            if b"\0" in data:
                continue
            text = data.decode("utf-8", errors="replace")
            yield path, {"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"file_path": path, "content": text}}


def transcript_cases():
    for path in glob.glob(os.path.join(HOME, ".claude", "projects", "**", "*.jsonl"), recursive=True):
        try:
            lines = open(path, errors="replace").read().splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines):
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            msg = rec.get("message") or {}
            content = msg.get("content")
            where = f"{path}:{i + 1}"
            if rec.get("type") == "user" and not rec.get("isMeta"):
                if isinstance(content, str):
                    yield where, {"hook_event_name": "UserPromptSubmit", "prompt": content}
                elif isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            yield where, {"hook_event_name": "UserPromptSubmit", "prompt": block.get("text", "")}
            elif rec.get("type") == "assistant" and isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_use":
                        yield where, {"hook_event_name": "PreToolUse", "tool_name": block.get("name"), "tool_input": block.get("input") or {}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sources", nargs="*", default=["repos", "transcripts"])
    ap.add_argument("--limit-per-rule", type=int, default=40)
    args = ap.parse_args()

    gens = {"repos": repo_cases, "transcripts": transcript_cases}
    for src in args.sources:
        cases = list(gens[src]())
        payload = "".join(json.dumps({"id": n, "event": ev}) + "\n" for n, (_, ev) in enumerate(cases))
        out = subprocess.run([BIN, "corpus"], input=payload, capture_output=True, text=True, check=True).stdout
        hits = collections.defaultdict(list)
        total_bytes = sum(len(json.dumps(ev)) for _, ev in cases)
        for r in map(json.loads, out.splitlines()):
            where, _ = cases[r["id"]]
            for h in r["hits"]:
                hits[h["rule"]].append((where, f"{h['field']}: {h['context']}"))
        n = sum(len(v) for v in hits.values())
        print(f"\n=== {src}: {len(cases)} items, {total_bytes / 1e6:.1f} MB, {n} hits")
        for rule, items in sorted(hits.items(), key=lambda kv: -len(kv[1])):
            print(f"\n--- {rule}: {len(items)}")
            uniq = list(dict.fromkeys(items))
            for where, ctx in uniq[: args.limit_per_rule]:
                print(f"  {where.replace(HOME, '~')}\n      {ctx}")


if __name__ == "__main__":
    main()
