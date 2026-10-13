"""The secret-guard binary for the eval scripts. SG_BIN overrides the path, to compare builds."""
import json
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("SG_BIN") or os.path.join(ROOT, "target", "release", "secret-guard")


def run(mode, events):
    """`secret-guard <mode>` (eval or corpus) over hook events; one parsed result per event, in order."""
    payload = "".join(json.dumps({"id": i, "event": ev}) + "\n" for i, ev in enumerate(events))
    out = subprocess.run([BIN, mode], input=payload, capture_output=True, text=True, check=True).stdout
    by_id = {r["id"]: r for r in map(json.loads, out.splitlines())}
    return [by_id[i] for i in range(len(events))]
