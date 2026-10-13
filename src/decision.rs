//! What the hook does with a Claude Code event: allow it, or block it with a message.

use crate::hook::{scan_event, Event};
use crate::{mask, raw_secret_output, scan_text, Finding};
use serde_json::Value;
use sha2::{Digest, Sha256};
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

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

/// No characters of the secret: block messages reach the model, and even a prefix narrows a password.
pub fn redact(s: &str) -> String {
    format!("{} chars", s.chars().count())
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

fn scan_all(event: &Value) -> Vec<Finding> {
    let mut findings = scan_event(event);
    for path in Event::parse(event).files() {
        let Some(text) = read_text(&path) else { continue };
        for mut f in scan_text(&text) {
            f.field = format!("file {}", path.display());
            findings.push(f);
        }
    }
    findings
}

/// Shown to the model when the scanner failed: the call goes through, so the model must keep secrets out itself.
pub const UNSCANNED: &str = "secret-guard could not scan this call (internal error), so it was allowed unchecked. \
    Do not put secret values in tool calls or print them in output; reference them indirectly (env var, file, \
    secret manager).";

/// `kubectl get secret -o yaml`, `op read`: a Bash command whose output would be secret values.
fn bash_exposure(event: &Value) -> Option<String> {
    let Event::PreTool { tool: "Bash", input: Some(input), .. } = Event::parse(event) else { return None };
    raw_secret_output(input.get("command")?.as_str()?)
}

/// A scanner panic steers instead of blocking: only a found secret is worth stopping work for.
pub fn decide(event: &Value, policy: impl FnOnce() -> Policy) -> Decision {
    let Ok((findings, exposure)) = std::panic::catch_unwind(|| (scan_all(event), bash_exposure(event))) else {
        return Decision::Steer(UNSCANNED.into());
    };
    if let Some(what) = exposure {
        return Decision::Block(format!(
            "secret-guard: blocked Bash call, `{what}` would print secret values into the conversation, \
             and anything printed there has to be rotated. Keep the values out of the output: pipe them into the \
             command that needs them, use them inside $(...), redirect to a file, or print names only \
             (`jq 'keys'`, `cut -d= -f1`, `grep -c`). If the user needs to see a value, ask them to look it up \
             outside this session."
        ));
    }
    if findings.is_empty() {
        return Decision::Allow;
    }
    let policy = policy();
    let event = Event::parse(event);
    if let Event::PostTool { response } = event {
        let mut output = response.cloned().unwrap_or(Value::Null);
        let n = redact_strings(&mut output, &policy);
        if n == 0 {
            return Decision::Allow;
        }
        let note = format!(
            "secret-guard replaced {n} secret value(s) in this tool output with [secret-guard: <rule> redacted]. \
             Work with the redacted output; do not try to recover the values."
        );
        return Decision::Redact { output, note };
    }
    let findings: Vec<Finding> = findings.into_iter().filter(|f| policy.reports(f)).collect();
    if findings.is_empty() {
        return Decision::Allow;
    }
    Decision::Block(block_message(&event, &findings, &policy))
}

fn block_message(event: &Event, findings: &[Finding], policy: &Policy) -> String {
    let lines: Vec<String> = findings
        .iter()
        .map(|f| format!("  - {} in {}: {} [fingerprint {}]", f.rule, f.field, redact(&f.secret), fingerprint(&policy.salt, &f.secret)))
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
fn redact_strings(v: &mut Value, policy: &Policy) -> usize {
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

/// `width` chars either side of a finding, the secret masked, and long digit-bearing tokens nearby hidden too.
pub fn redacted_context(text: &str, f: &Finding, width: usize) -> String {
    let before: String = {
        let mut v: Vec<char> = text[..f.start].chars().rev().take(width).collect();
        v.reverse();
        v.into_iter().collect()
    };
    let after: String = text[f.end..].chars().take(width).collect();
    format!("{}«{}»{}", hide_tokens(&before), redact(&f.secret), hide_tokens(&after)).replace('\n', "⏎")
}

/// Runs of 12+ token chars that contain a digit become `#<len>`: neighbouring values may be secrets too.
fn hide_tokens(s: &str) -> String {
    static TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/=_~.-]{12,}").unwrap());
    TOKEN
        .replace_all(s, |c: &regex::Captures| {
            let t = &c[0];
            if t.bytes().any(|b| b.is_ascii_digit()) { format!("#{}", t.len()) } else { t.to_string() }
        })
        .into_owned()
}
