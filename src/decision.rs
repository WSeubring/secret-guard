//! What the hook does with a Claude Code event: allow it, or block it with a message.

use crate::{is_post_tool_use, raw_secret_output, referenced_files, scan_event, scan_text, Finding};
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
    for path in referenced_files(event) {
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

/// A scanner panic steers instead of blocking: only a found secret is worth stopping work for.
/// `cat .env`, `kubectl get secret -o yaml`: a Bash command whose output would carry secret values.
fn bash_exposure(event: &Value) -> Option<String> {
    if is_post_tool_use(event) || event.get("tool_name").and_then(Value::as_str) != Some("Bash") {
        return None;
    }
    let command = event.get("tool_input")?.get("command")?.as_str()?;
    raw_secret_output(command)
}

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
    if is_post_tool_use(event) {
        let mut output = event.get("tool_response").cloned().unwrap_or(Value::Null);
        let n = redact_strings(&mut output, &|f| !policy.allowlist.contains(&fingerprint(&policy.salt, &f.secret)));
        if n == 0 {
            return Decision::Allow;
        }
        let note = format!(
            "secret-guard replaced {n} secret value(s) in this tool output with [secret-guard: <rule> redacted]. \
             Work with the redacted output; do not try to recover the values."
        );
        return Decision::Redact { output, note };
    }
    let findings: Vec<(Finding, String)> = findings
        .into_iter()
        .map(|f| {
            let fp = fingerprint(&policy.salt, &f.secret);
            (f, fp)
        })
        .filter(|(_, fp)| !policy.allowlist.contains(fp))
        .collect();
    if findings.is_empty() {
        return Decision::Allow;
    }
    let lines: Vec<String> = findings
        .iter()
        .map(|(f, fp)| format!("  - {} in {}: {} [fingerprint {fp}]", f.rule, f.field, redact(&f.secret)))
        .collect();
    let msg = if event.get("hook_event_name").and_then(Value::as_str) == Some("UserPromptSubmit") {
        format!(
            "secret-guard: prompt blocked, it contains what looks like a secret:\n{}\n\
             Remove it (point to an env var or file instead) and resend.\n\
             False positive? Add the fingerprint to {}.",
            lines.join("\n"),
            policy.allowlist_path
        )
    } else if findings.iter().any(|(f, _)| f.field.starts_with("file ")) {
        format!(
            "secret-guard: blocked {} call, the file it would load contains what looks like a secret:\n{}\n\
             Do not load files that hold secret values. Read only what you need without the values \
             (e.g. `cut -d= -f1 .env` for the names), or ask the user. If you believe this is a false positive, \
             stop and ask the user.",
            event.get("tool_name").and_then(Value::as_str).unwrap_or("tool"),
            lines.join("\n")
        )
    } else {
        format!(
            "secret-guard: blocked {} call, its input contains what looks like a secret:\n{}\n\
             Do not put secret values in tool calls. Reference them indirectly (env var, file, secret manager) \
             so the value never appears in the call. If you believe this is a false positive, stop and ask the user.",
            event.get("tool_name").and_then(Value::as_str).unwrap_or("tool"),
            lines.join("\n")
        )
    };
    Decision::Block(msg)
}

/// Replace every secret in the strings of `v` (keeping its shape, so the tool's output schema still matches).
fn redact_strings(v: &mut Value, keep: &dyn Fn(&Finding) -> bool) -> usize {
    match v {
        Value::String(s) => {
            let found: Vec<Finding> = scan_text(s).into_iter().filter(|f| keep(f)).collect();
            for f in found.iter().rev() {
                s.replace_range(f.start..f.end, &format!("[secret-guard: {} redacted]", f.rule));
            }
            found.len()
        }
        Value::Array(items) => items.iter_mut().map(|i| redact_strings(i, keep)).sum(),
        Value::Object(map) => map.values_mut().map(|i| redact_strings(i, keep)).sum(),
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
