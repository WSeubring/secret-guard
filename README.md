# secret-guard

Claude Code hook that blocks secrets in user prompts (`UserPromptSubmit`) and in
every tool call (`PreToolUse`, all tools including MCP). It also scans the files that
reach the model without passing through a tool input: the target of a `Read` or
`Artifact` call, and files `@`-mentioned in a prompt (missing, binary and >2 MB files
are skipped). Written in Rust for speed: a typical call costs about 1.2x-2x spawning an
empty process (`eval/bench.py` prints both).

## What happens when

The hook blocks only what would force a token rotation: a secret value that would reach
the model (and so the LLM provider). Block messages name the rule, the length and a
salted fingerprint, never any characters of the secret.

**You paste a secret in a prompt.** The prompt is dropped before it is sent; you see:

```
secret-guard: prompt blocked, it contains what looks like a secret:
  - github-token in prompt: 40 chars [fingerprint db10c472a441b73f]
Remove it (point to an env var or file instead) and resend.
False positive? Add the fingerprint to ~/.config/secret-guard/allowlist.txt.
```

**You `@`-mention a file that holds a secret** (`why does @.env not load?`). Claude Code
would attach the file without a tool call, so the prompt itself is blocked:

```
  - github-token in file /home/me/app/.env: 40 chars [fingerprint db10c472a441b73f]
```

**The agent reads that file** (`Read`, or `Artifact` publishing it). The call is blocked
before the file is loaded, and the agent is told how to proceed:

```
secret-guard: blocked Read call, the file it would load contains what looks like a secret:
  - github-token in file /home/me/app/.env: 40 chars [fingerprint db10c472a441b73f]
Do not load files that hold secret values. Read only what you need without the values
(e.g. `cut -d= -f1 .env` for the names), or ask the user. ...
```

**The agent puts a secret in a tool call** (a Bash command, a file write, a Slack
message), e.g. `psql postgres://app:<password>@db.prod:5432/app`:

```
secret-guard: blocked Bash call, its input contains what looks like a secret:
  - url-credentials in command: 13 chars [fingerprint 2367ddcf86875a5b]
Do not put secret values in tool calls. Reference them indirectly (env var, file, secret
manager) so the value never appears in the call. ...
```

**Base64 hides the value** (a k8s `data:` entry under a neutral key, a
`.dockerconfigjson`, `echo <b64> | base64 -d`). It is decoded and rescanned; same block:

```
  - github-token in content: 40 chars [fingerprint db10c472a441b73f]
```

**The agent references a secret instead of writing it**
(`export GITHUB_TOKEN="$(cat ~/.config/gh-token)"`, `${{ secrets.X }}`, `op://vault/item`,
a SealedSecret, a helm `checksum/secret`): allowed, nothing shown.

**The agent edits a file to remove a secret.** `Edit.old_string` is not scanned, so the
value can be taken out; the replacement text is scanned as usual.

**The hook itself fails.** Unreadable input is allowed and logged. A scanner error is
allowed with a note to the model (`additionalContext`) to keep secret values out of tool
calls and output. Only a found secret blocks.

**Not covered: a tool prints a secret.** Hooks run before a tool or after it; output such
as `cat .env`, `kubectl get secret -o yaml` or `printenv` is already in the conversation
by the time any hook sees it. Only commands that put the value in their own input are
blocked.

## Why not gitleaks

Measured on this machine:

| | gitleaks 8 (`stdin`) | secret-guard |
|---|---|---|
| Latency per call | ~29 ms | ~1.3 ms |
| Helm `checksum/secret: <sha256>` | false positive | clean |
| Password forms (DB URL, `DB_PASSWORD=`, prose, `mysql -p`, `curl -u`, YAML) | 0 / 6 detected | 6 / 6 |
| Reads hook JSON | needs a wrapper | native |

## Detection

1. **Provider rules**: distinctive prefixes (GitHub, GitLab, Slack, AWS, Anthropic,
   OpenAI, DigitalOcean, Docker Hub, Tailscale, Grafana, 1Password, JWT, PEM and
   base64-wrapped PEM keys, ~50 total). Placeholder tails (`xxxx`, `your-…`,
   runs, sequences) are ignored.
2. **Context rules**: `key = value` assignments, CLI flags, `Authorization`
   headers, URL credentials, `curl -u`, `mysql -p`, `sshpass -p`, and prose
   ("my password is …", "het wachtwoord is …"). The value must look random and not
   be a reference (`$VAR`, `${{ secrets.X }}`, `op://…`), template, identifier,
   path, MR ref, hash, email, sealed/sops blob or placeholder.

3. **Base64**: runs of 24+ base64 chars that decode to text are rescanned with all
   rules, two levels deep (a `.dockerconfigjson` hides `auth` inside base64 inside
   base64). Binary payloads (images, SealedSecrets) do not decode to text and are skipped.

Not scanned on purpose: `Edit.old_string` (the secret is already in the file),
credentials in `localhost`/`127.0.0.1` URLs.

## Install

```bash
cargo build --release
install -m 755 target/release/secret-guard ~/.local/bin/secret-guard
```

`~/.claude/settings.json`:

```json
"UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "~/.local/bin/secret-guard", "timeout": 5 }] }],
"PreToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "~/.local/bin/secret-guard", "timeout": 5 }] }]
```

## Escape hatches

- False positive: add the printed fingerprint to `~/.config/secret-guard/allowlist.txt`.
  Fingerprints are salted (`~/.config/secret-guard/salt`), so they do not allow an
  offline guess of a weak password.
- `! touch ~/.config/secret-guard/disabled` disables the hook at once; delete the file to
  re-enable. `SECRET_GUARD_DISABLE=1` in Claude Code's environment does the same at start.
- Errors are logged to `~/.config/secret-guard/errors.log`; they never block.

## Evaluation

```bash
cargo test --release                 # regressions, classifier reasons, hook decision, 20k random unicode inputs
python3 eval/run_eval.py             # labelled set, 3 seeds
python3 eval/corpus_scan.py          # your own repos + Claude transcripts, redacted output (local only)
python3 eval/bench.py                # hook latency on your own transcript events (SG_BIN=... to compare builds)
```

The hook is a fresh process per call, so compile cost matters more than search speed:

- Each rule compiles lazily, only when one of its needles occurs in the text (plain
  `str::contains`; building an Aho-Corasick automaton cost more than it saved).
  Needles include the char the pattern requires next (`token=`, not `token`).
- The context rules (`src/patterns.rs`) are precompiled by `build.rs` into dense DFAs,
  embedded in the binary and loaded zero-copy. The DFA says whether the rule can match
  at all; the capture regex is only compiled when it can. Provider rules are not
  gated: their DFAs blow up (`[A-Za-z0-9]{35}` unanchored) and they compile fast.
- glibc is linked statically (`.cargo/config.toml`), which skips the dynamic loader:
  ~0.5 ms off every call.
- Patterns avoid large `{n,m}` upper bounds, which multiply compile time; length limits
  are enforced in code instead.

Every rejected candidate carries a `Reason` (`Placeholder`, `Reference`, `LocalUrl`, ...).
`run_eval.py` groups misses by `rule:reason`; `explain_text` / `explain_event` give the
same trace for a single input.

`eval/gen_cases.py` builds fake credentials at runtime from a seed, so the repo
holds no secret-looking literals. Clean cases include provider placeholders,
references and templates, SealedSecrets, sops, helm checksums, digests, UUIDs,
public keys and certificates, code that handles secrets, prose about secrets,
and a regression family of every false positive found in real data.

False positives found in real data go in `tests/fixtures/clean-regressions.jsonl`
(one JSON string per line; `{hex40}`, `{hex64}`, `{urlsafe20}`, `{port}` are filled
at runtime). `cargo test` and `eval/gen_cases.py` both read it.

Results on the labelled set (3 seeds):

| Set | Size | Result |
|---|---|---|
| Secret cases | 6,894 | recall 99.93 % |
| Clean cases | 10,260 | 0 false positives |

The remaining misses are random passwords that look like a placeholder, reference or
code (a placeholder word such as `baz`, a leading `!`, an embedded `==`).
