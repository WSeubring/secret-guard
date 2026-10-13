# secret-guard

Claude Code hook that keeps secrets away from the model and the LLM provider. It blocks
secrets in user prompts (`UserPromptSubmit`) and in every tool call (`PreToolUse`, all
tools including MCP), and redacts them from every tool result (`PostToolUse`) before the
model sees it. Files that leave without a tool result are scanned up front: files
`@`-mentioned in a prompt and `Artifact` publishes (missing, binary and >2 MB files are
skipped). Written in Rust for speed: a typical call costs about 1.2x-2x spawning an
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

**The agent reads that file** (`Read`, `cat .env`, `grep TOKEN .env`). The call runs and
the result is redacted before the model sees it (see "Any tool output" below), so the
agent can still work with the rest of the file. Publishing it with `Artifact` sends it
off the machine, so that call is blocked:

```
secret-guard: blocked Artifact call, the file it would load contains what looks like a secret:
  - github-token in file /home/me/app/.env: 40 chars [fingerprint db10c472a441b73f]
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

**A command exists to print secret values** (`kubectl get secret -o yaml`, `op read …`,
`gh auth token`, `env | grep TOKEN`, `echo $DB_PASSWORD`). Redaction only catches values
the scanner recognises, and these print nothing else, so the call is blocked before it
runs:

```
secret-guard: blocked Bash call, `kubectl get secret -o yaml` would print secret values
into the conversation, and anything printed there has to be rotated. Keep the values out
of the output: pipe them into the command that needs them, use them inside $(...),
redirect to a file, or print names only (`jq 'keys'`, `cut -d= -f1`, `grep -c`). ...
```

Handling values without printing them is allowed: piping into a consumer
(`| kubeseal`, `| docker login --password-stdin`, `| sha256sum`, any unknown command),
`$(...)`, `> file`, names or counts only (`jq '.data | keys'`, `cut -d= -f1`,
`awk -F= '{print $1}'`, `grep -c`), masking (`sed 's/=.*/=<set>/'`), and `sed -i`.

**Any tool output contains a secret** (a file read, a script, app logs, an MCP reply, a
fetched page). The `PostToolUse` hook rewrites the result before the model sees it
(`updatedToolOutput`), keeping its JSON shape and replacing each value:

```
GITHUB_TOKEN=[secret-guard: github-token redacted]
```

and tells the agent that values were redacted. The command itself has already run;
only what reaches the model changes. `secret-guard redact` applies the same filter to a
stream (`some-command | secret-guard redact`).

## Why not gitleaks

Measured on this machine:

| | gitleaks 8 (`stdin`) | secret-guard |
|---|---|---|
| Latency per call | ~29 ms | ~0.7 ms |
| Helm `checksum/secret: <sha256>` | false positive | clean |
| Password forms (DB URL, `DB_PASSWORD=`, prose, `mysql -p`, `curl -u`, YAML) | 0 / 6 detected | 6 / 6 |
| Reads hook JSON | needs a wrapper | native |
| [CredData](#public-benchmark-creddata) precision / recall | 0.856 / 0.450 | 0.898 / 0.304 |

## Detection

1. **Provider rules**: distinctive prefixes (GitHub, GitLab, Slack, AWS, Anthropic,
   OpenAI, DigitalOcean, Docker Hub, Tailscale, Grafana, 1Password, JWT, PASETO,
   NKEY seeds, JWK private members, PEM and base64-wrapped PEM keys, ~60 total). Placeholder tails (`xxxx`, `your-…`,
   runs, sequences) are ignored.
2. **Context rules**: `key = value` assignments, CLI flags, `Bearer`, `Basic`,
   `ApiKey` and NTLM credentials, docker config `auth`, URL credentials, `curl -u`,
   `CURLOPT_USERPWD`, `mysql -p`, `sshpass -p`, PowerShell `ConvertTo-SecureString '…'`, and prose
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
"PreToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "~/.local/bin/secret-guard", "timeout": 5 }] }],
"PostToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "~/.local/bin/secret-guard", "timeout": 5 }] }]
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
| Secret cases | 7,914 | recall 99.79 % |
| Clean cases | 11,340 | 0 false positives |

The remaining misses are random passwords that look like a placeholder, reference or
code (a placeholder word such as `baz`, a leading `!`, an embedded `==`).

The labelled set is written alongside the rules, so it measures regressions rather than
real-world recall. For that, see the public benchmark below.

### Public benchmark: CredData

[Samsung CredData](https://github.com/Samsung/CredData) is a labelled dataset of 297
public repositories (19.5M lines, 67,896 labelled lines, 15,753 credentials) with the
real values replaced by realistic fakes. Scored per labelled line with
`eval/creddata.py` (setup steps in its docstring); `--quick` scores a per-category
sample in seconds.

| Scanner | Precision | Recall | F1 | Hits on unlabelled lines |
|---|---|---|---|---|
| secret-guard | **0.898** | 0.304 | 0.454 | 126 |
| gitleaks 8 | 0.856 | **0.450** | **0.590** | 488 |

Recall is lower by design. Most remaining misses are values that are not worth blocking
in a prompt or tool call, or that cannot be told apart from test data:

- UUIDs, nonces and salts labelled as credentials (`_postman_id`, OAuth nonces).
- Short or dictionary-like passwords: CredData replaces each character with a random
  one of the same class, so `postgres` becomes `xkqjzmwp`, which looks like a word to
  a classifier that rejects words.
- A bare `key = <value>` without `api`/`secret`/`private` in the name: accepting it
  added more false positives than credentials.
- Credentials in `localhost` URLs, exempt on purpose.
- Encrypted keys (PASERK `seal`, `-pw`, `-wrap`), which do not need rotating on their own.
