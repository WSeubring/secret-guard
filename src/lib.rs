//! Secret detection tuned for precision.
//!
//! Provider rules need a distinctive prefix. Generic rules need an assignment, flag,
//! header or prose context plus a value that looks random and is not a placeholder,
//! reference, identifier, template or hash.

mod classify;
mod patterns;
pub mod decision;
mod rules;

pub use classify::{classify, Context, Reason, Verdict};
use rules::RULES;

use regex::bytes::Regex as BytesRegex;
use regex::Regex;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// Unicode-free regexes compile in a fraction of the time, and every process compiles from scratch.
fn ascii_regex(p: &str) -> Regex {
    regex::RegexBuilder::new(p).unicode(false).build().unwrap()
}

fn bytes_regex(p: &str) -> BytesRegex {
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

const SKIP_FIELDS: &[&str] = &["old_string"];

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

fn scan(text: &str, trace: Option<&mut Vec<Rejection>>) -> Vec<Finding> {
    scan_at(text, trace, 0)
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
    out
}

/// Scan one string. Findings are non-overlapping; `field` is left empty.
pub fn scan_text(text: &str) -> Vec<Finding> {
    scan(text, None)
}

/// Candidates in one string that were not reported, with the reason. For triaging misses.
pub fn explain_text(text: &str) -> Vec<Rejection> {
    let mut trace = Vec::new();
    scan(text, Some(&mut trace));
    trace
}

fn walk<'a>(v: &'a Value, path: String, out: &mut Vec<(String, &'a str)>) {
    match v {
        Value::String(s) => out.push((path, s)),
        Value::Object(map) => {
            for (k, v) in map {
                if SKIP_FIELDS.contains(&k.as_str()) {
                    continue;
                }
                let p = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                walk(v, p, out);
            }
        }
        Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                walk(v, format!("{path}[{i}]"), out);
            }
        }
        _ => {}
    }
}

/// Tools whose `file_path` content reaches the model or leaves the machine.
const FILE_TOOLS: &[&str] = &["Read", "Artifact"];

/// Files whose content the event sends to the model: `Read`/`Artifact` targets, and `@`-mentions in a prompt,
/// which Claude Code attaches without a tool call. Paths may not exist; the caller skips those.
pub fn referenced_files(event: &Value) -> Vec<PathBuf> {
    let cwd = Path::new(event.get("cwd").and_then(Value::as_str).unwrap_or(""));
    if event.get("hook_event_name").and_then(Value::as_str) == Some("UserPromptSubmit") {
        let prompt = event.get("prompt").and_then(Value::as_str).unwrap_or("");
        return mentions(prompt).into_iter().map(|m| resolve(&m, cwd)).collect();
    }
    let tool = event.get("tool_name").and_then(Value::as_str).unwrap_or("");
    if !FILE_TOOLS.contains(&tool) {
        return Vec::new();
    }
    let input = event.get("tool_input");
    let single = input.and_then(|i| i.get("file_path")).and_then(Value::as_str);
    let many = input.and_then(|i| i.get("file_paths")).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str);
    single.into_iter().chain(many).map(|p| resolve(p, cwd)).collect()
}

/// `@path`, `@"path with spaces"`, `@path#L10-20`; trailing punctuation is tried both kept and dropped.
fn mentions(prompt: &str) -> Vec<String> {
    static MENTION: LazyLock<BytesRegex> = LazyLock::new(|| bytes_regex(r#"(?:^|\s)@(?:"([^"]+)"|(\S+))"#));
    static LINES: LazyLock<Regex> = LazyLock::new(|| ascii_regex(r"#L\d+(?:-\d+)?$"));
    let mut out = Vec::new();
    if !prompt.contains('@') {
        return out;
    }
    for c in MENTION.captures_iter(prompt.as_bytes()) {
        let raw = c.get(1).or(c.get(2)).map_or("".into(), |m| String::from_utf8_lossy(m.as_bytes()));
        let trimmed = raw.trim_end_matches([',', '.', ';', ':', '!', '?', ')']);
        for candidate in [trimmed, &*raw] {
            out.push(LINES.replace(candidate, "").into_owned());
        }
        out.dedup();
    }
    out
}

fn resolve(path: &str, cwd: &Path) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return Path::new(&home).join(rest);
        }
    }
    cwd.join(path)
}

/// The strings of a hook event that get scanned: the prompt for UserPromptSubmit, every string in tool_input otherwise.
pub fn event_fields(event: &Value) -> Vec<(String, &str)> {
    let mut items: Vec<(String, &str)> = Vec::new();
    if event.get("hook_event_name").and_then(Value::as_str) == Some("UserPromptSubmit") {
        if let Some(p) = event.get("prompt").and_then(Value::as_str) {
            items.push(("prompt".into(), p));
        }
    } else if let Some(input) = event.get("tool_input") {
        walk(input, String::new(), &mut items);
    }
    items
}

/// Candidates in a hook event that were not reported, with the reason.
pub fn explain_event(event: &Value) -> Vec<Rejection> {
    let mut out = Vec::new();
    for (field, text) in event_fields(event) {
        for mut r in explain_text(text) {
            r.field = field.clone();
            out.push(r);
        }
    }
    out
}

/// Scan a Claude Code hook event: the prompt for UserPromptSubmit, every string in tool_input otherwise.
pub fn scan_event(event: &Value) -> Vec<Finding> {
    let mut out = Vec::new();
    for (field, text) in event_fields(event) {
        for mut f in scan_text(text) {
            f.field = field.clone();
            out.push(f);
        }
    }
    out
}
