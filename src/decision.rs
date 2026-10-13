//! What the hook does with a Claude Code event: allow, steer, block or redact it.

use crate::hook::Event;
use crate::{hidden, mask, raw_secret_output, scan_text, Finding};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cell::LazyCell;
use std::collections::HashSet;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

/// Allowlist state, loaded only when the event has findings.
pub struct Policy {
    /// Per-machine salt so a printed fingerprint cannot be used to brute-force a weak password offline.
    pub salt: Vec<u8>,
    pub allowlist: HashSet<String>,
    /// Shown to the user so they know where to add a fingerprint.
    pub allowlist_path: String,
}

impl Policy {
    /// Allowlisted fingerprints are false positives the user has accepted.
    pub fn reports(&self, f: &Finding) -> bool {
        !self.allowlist.contains(&fingerprint(&self.salt, &f.secret))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Let the call through, and tell the model this (hook JSON `additionalContext`).
    Steer(String),
    /// Exit 2 with this message on stderr.
    Block(String),
    /// Replace the tool's result with this one (`PostToolUse` `updatedToolOutput`), and tell the model why.
    Redact { output: Value, note: String },
}

pub fn fingerprint(salt: &[u8], secret: &str) -> String {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(secret.as_bytes());
    h.finalize().iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// Text of a file worth scanning; `None` for missing, non-regular, over `MAX_FILE_BYTES` or binary files.
fn read_text(path: &Path) -> Option<String> {
    const MAX_FILE_BYTES: u64 = 2 << 20;
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
        return None;
    }
    let data = std::fs::read(path).ok()?;
    if data[..data.len().min(8192)].contains(&0) {
        return None;
    }
    Some(String::from_utf8_lossy(&data).into_owned())
}

type Lazy<F> = LazyCell<Policy, F>;

/// Shown to the model when the scanner failed: the call goes through, so the model must keep secrets out itself.
pub const UNSCANNED: &str = "secret-guard could not scan this call (internal error), so it was allowed unchecked. \
    Do not put secret values in tool calls or print them in output; reference them indirectly (env var, file, \
    secret manager).";

/// Tool output is redacted, everything else is blocked. The policy loads only once something is found, and a
/// scanner panic steers instead of blocking: only a found secret is worth stopping work for.
pub fn decide(event: &Event, policy: impl FnOnce() -> Policy) -> Decision {
    let policy = LazyCell::new(policy);
    catch_unwind(AssertUnwindSafe(|| match event {
        Event::PostTool { response } => redact_output(*response, &policy),
        _ => check_input(event, &policy),
    }))
    .unwrap_or_else(|_| Decision::Steer(UNSCANNED.into()))
}

fn redact_output(response: Option<&Value>, policy: &Lazy<impl FnOnce() -> Policy>) -> Decision {
    let mut output = response.cloned().unwrap_or(Value::Null);
    let n = redact_strings(&mut output, policy);
    if n == 0 {
        return Decision::Allow;
    }
    let note = format!(
        "secret-guard replaced {n} secret value(s) in this tool output with [secret-guard: <rule> redacted]. \
         Work with the redacted output; do not try to recover the values."
    );
    Decision::Redact { output, note }
}

fn check_input(event: &Event, policy: &Lazy<impl FnOnce() -> Policy>) -> Decision {
    if let Some(what) = bash_exposure(event) {
        return Decision::Block(format!(
            "secret-guard: blocked Bash call, `{what}` would print secret values into the conversation, \
             and anything printed there has to be rotated. Keep the values out of the output: pipe them into the \
             command that needs them, use them inside $(...), redirect to a file, or print names only \
             (`jq 'keys'`, `cut -d= -f1`, `grep -c`). If the user needs to see a value, ask them to look it up \
             outside this session."
        ));
    }
    let mut findings = event.scan();
    for path in event.files() {
        let Some(text) = read_text(&path) else { continue };
        for mut f in scan_text(&text) {
            f.field = format!("file {}", path.display());
            findings.push(f);
        }
    }
    findings.retain(|f| policy.reports(f));
    if findings.is_empty() {
        return Decision::Allow;
    }
    Decision::Block(block_message(event, &findings, policy))
}

/// `kubectl get secret -o yaml`, `op read`: a Bash command whose output would be secret values.
fn bash_exposure(event: &Event) -> Option<String> {
    let Event::PreTool { tool: "Bash", input: Some(input), .. } = event else { return None };
    raw_secret_output(input.get("command")?.as_str()?)
}

fn block_message(event: &Event, findings: &[Finding], policy: &Policy) -> String {
    let lines: Vec<String> = findings
        .iter()
        .map(|f| format!("  - {} in {}: {} [fingerprint {}]", f.rule, f.field, hidden(&f.secret), fingerprint(&policy.salt, &f.secret)))
        .collect();
    let lines = lines.join("\n");
    if let Event::Prompt { .. } = event {
        return format!(
            "secret-guard: prompt blocked, it contains what looks like a secret:\n{lines}\n\
             Remove it (point to an env var or file instead) and resend.\n\
             False positive? Add the fingerprint to {}.",
            policy.allowlist_path
        );
    }
    let tool = match event {
        Event::PreTool { tool, .. } if !tool.is_empty() => tool,
        _ => "tool",
    };
    let (what, advice) = if findings.iter().any(|f| f.field.starts_with("file ")) {
        (
            "the file it would load contains",
            "Do not load files that hold secret values. Read only what you need without the values \
             (e.g. `cut -d= -f1 .env` for the names), or ask the user.",
        )
    } else {
        (
            "its input contains",
            "Do not put secret values in tool calls. Reference them indirectly (env var, file, secret manager) \
             so the value never appears in the call.",
        )
    };
    format!(
        "secret-guard: blocked {tool} call, {what} what looks like a secret:\n{lines}\n{advice} \
         If you believe this is a false positive, stop and ask the user."
    )
}

/// Replace every reported secret in the strings of `v`, keeping its shape so the tool's output schema still matches.
fn redact_strings(v: &mut Value, policy: &Lazy<impl FnOnce() -> Policy>) -> usize {
    match v {
        Value::String(s) => {
            let found: Vec<Finding> = scan_text(s).into_iter().filter(|f| policy.reports(f)).collect();
            *s = mask(s, &found);
            found.len()
        }
        Value::Array(items) => items.iter_mut().map(|i| redact_strings(i, policy)).sum(),
        Value::Object(map) => map.values_mut().map(|i| redact_strings(i, policy)).sum(),
        _ => 0,
    }
}
