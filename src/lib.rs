//! Secret detection tuned for precision.
//!
//! Provider rules need a distinctive prefix. Generic rules need an assignment, flag,
//! header or prose context plus a value that looks random and is not a placeholder,
//! reference, identifier, template or hash.

mod classify;
pub mod decision;
pub mod hook;
mod patterns;
mod rules;
mod shell;

pub use classify::{classify, Context, Reason, Verdict};
pub use hook::{explain_event, scan_event};
pub use shell::raw_secret_output;
use rules::RULES;

use regex::bytes::Regex as BytesRegex;
use regex::Regex;
use std::sync::LazyLock;

/// Unicode-free regexes compile in a fraction of the time, and every process compiles from scratch.
pub(crate) fn ascii_regex(p: &str) -> Regex {
    regex::RegexBuilder::new(p).unicode(false).build().unwrap()
}

pub(crate) fn bytes_regex(p: &str) -> BytesRegex {
    regex::bytes::RegexBuilder::new(p).unicode(false).build().unwrap()
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule: &'static str,
    pub secret: String,
    pub start: usize,
    pub end: usize,
    pub field: String,
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn overlaps(taken: &[(usize, usize)], a: usize, b: usize) -> bool {
    taken.iter().any(|&(s, e)| a < e && s < b)
}

/// A candidate match that was not reported, and why.
#[derive(Debug, Clone)]
pub struct Rejection {
    pub rule: &'static str,
    pub value: String,
    pub reason: Reason,
    pub field: String,
}

/// Runs of 24+ base64 chars (standard or URL-safe alphabet, optional padding).
fn base64_runs(bytes: &[u8]) -> Vec<(usize, usize)> {
    let b64 = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_');
    let mut runs = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !b64(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && b64(bytes[i]) {
            i += 1;
        }
        let body = i;
        while i < bytes.len() && i - body < 2 && bytes[i] == b'=' {
            i += 1;
        }
        if body - start >= 24 {
            runs.push((start, i));
        }
    }
    runs
}

/// Secrets hidden in base64 (`.dockerconfigjson`, k8s `data:`, `echo … | base64 -d`): decode printable runs and rescan.
const MAX_BASE64_DEPTH: u8 = 2;

fn scan_at(text: &str, mut trace: Option<&mut Vec<Rejection>>, depth: u8) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut taken: Vec<(usize, usize)> = Vec::new();
    let bytes = text.as_bytes();
    let lower = text.to_ascii_lowercase();
    let has = |needles: &[&str], ci: bool| needles.iter().any(|n| if ci { lower.contains(n) } else { text.contains(n) });

    for rule in RULES.iter() {
        if !has(rule.needles, rule.ci) || !rule.may_match(bytes) {
            continue;
        }
        for caps in rule.re().captures_iter(bytes) {
            let Some(span) = rule.check.span(&caps, text) else { continue };
            let (a, b) = (span.start, span.end);
            if overlaps(&taken, a, b) {
                continue;
            }
            let embedded = rule.check.bounded() && ((a > 0 && is_word_byte(bytes[a - 1])) || (b < bytes.len() && is_word_byte(bytes[b])));
            let verdict = if embedded { Err(Reason::Embedded) } else { rule.check.verify(&caps, &span, text) };
            match verdict {
                Ok(()) => {
                    taken.push((a, b));
                    out.push(Finding { rule: rule.id, secret: span.body, start: a, end: b, field: String::new() });
                }
                Err(reason) => {
                    if let Some(t) = trace.as_deref_mut() {
                        t.push(Rejection { rule: rule.id, value: span.body, reason, field: String::new() });
                    }
                }
            }
        }
    }
    if depth < MAX_BASE64_DEPTH {
        for (a, b) in base64_runs(bytes) {
            if overlaps(&taken, a, b) {
                continue;
            }
            let Some(decoded) = classify::b64decode_loose(&text[a..b]).as_deref().and_then(classify::printable) else { continue };
            if let Some(f) = scan_at(&decoded, None, depth + 1).into_iter().next() {
                taken.push((a, b));
                out.push(Finding { rule: f.rule, secret: f.secret, start: a, end: b, field: String::new() });
            }
        }
    }
    out.sort_by_key(|f| f.start);
    out
}

/// Scan one string. Findings are non-overlapping and in text order; `field` is left empty.
pub fn scan_text(text: &str) -> Vec<Finding> {
    scan_at(text, None, 0)
}

/// Candidates in one string that were not reported, with the reason. For triaging misses.
pub fn explain_text(text: &str) -> Vec<Rejection> {
    let mut trace = Vec::new();
    scan_at(text, Some(&mut trace), 0);
    trace
}

/// A JSON string under `key`. A short single-word value is scanned as `key=value`, so `{"password": "..."}`
/// gets the same context as `password=...`.
pub fn scan_field(key: &str, value: &str) -> Vec<Finding> {
    if key.is_empty() || value.len() > 200 || value.contains(char::is_whitespace) {
        return scan_text(value);
    }
    let prefix = key.len() + 1;
    let mut found = scan_text(&format!("{key}={value}"));
    found.retain(|f| f.start >= prefix);
    for f in &mut found {
        f.start -= prefix;
        f.end -= prefix;
    }
    found
}

/// `text` with each finding's span replaced by `[secret-guard: <rule> redacted]`.
pub fn mask(text: &str, findings: &[Finding]) -> String {
    let mut out = text.to_string();
    for f in findings.iter().rev() {
        out.replace_range(f.start..f.end, &format!("[secret-guard: {} redacted]", f.rule));
    }
    out
}

/// No characters of the secret: block messages reach the model, and even a prefix narrows a password.
pub fn hidden(secret: &str) -> String {
    format!("{} chars", secret.chars().count())
}

/// `width` chars either side of a finding, the secret hidden, and long digit-bearing tokens nearby hidden too.
pub fn redacted_context(text: &str, f: &Finding, width: usize) -> String {
    let before: String = {
        let mut v: Vec<char> = text[..f.start].chars().rev().take(width).collect();
        v.reverse();
        v.into_iter().collect()
    };
    let after: String = text[f.end..].chars().take(width).collect();
    format!("{}«{}»{}", hide_tokens(&before), hidden(&f.secret), hide_tokens(&after)).replace('\n', "⏎")
}

/// Runs of 12+ token chars that contain a digit become `#<len>`: neighbouring values may be secrets too.
fn hide_tokens(s: &str) -> String {
    static TOKEN: LazyLock<Regex> = LazyLock::new(|| ascii_regex(r"[A-Za-z0-9+/=_~.-]{12,}"));
    TOKEN
        .replace_all(s, |c: &regex::Captures| {
            let t = &c[0];
            if t.bytes().any(|b| b.is_ascii_digit()) { format!("#{}", t.len()) } else { t.to_string() }
        })
        .into_owned()
}
