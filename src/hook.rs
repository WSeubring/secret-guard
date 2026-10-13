//! The Claude Code hook protocol: what an event carries, and the reply that goes back.

use crate::decision::{decide, Decision, Policy};
use crate::{ascii_regex, bytes_regex, explain_text, scan_field, Finding, Rejection};
use regex::bytes::Regex as BytesRegex;
use regex::Regex;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

pub enum Event<'a> {
    /// `UserPromptSubmit`: exit 2 keeps the prompt from being sent.
    Prompt { text: &'a str, cwd: &'a Path },
    /// `PreToolUse` (and any other event): exit 2 stops the call.
    PreTool { tool: &'a str, input: Option<&'a Value>, cwd: &'a Path },
    /// `PostToolUse` carries the tool's result, which the reply can replace before the model sees it.
    PostTool { response: Option<&'a Value> },
}

const SKIP_FIELDS: &[&str] = &["old_string"];

/// Tools that send a file's content off the machine. `Read` is not here: its result is redacted (PostToolUse).
const FILE_TOOLS: &[&str] = &["Artifact"];

impl<'a> Event<'a> {
    pub fn parse(v: &'a Value) -> Self {
        let str_at = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("");
        let cwd = Path::new(str_at("cwd"));
        match str_at("hook_event_name") {
            "UserPromptSubmit" => Event::Prompt { text: str_at("prompt"), cwd },
            "PostToolUse" => Event::PostTool { response: v.get("tool_response") },
            _ => Event::PreTool { tool: str_at("tool_name"), input: v.get("tool_input"), cwd },
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Event::Prompt { .. } => "UserPromptSubmit",
            Event::PreTool { .. } => "PreToolUse",
            Event::PostTool { .. } => "PostToolUse",
        }
    }

    /// The strings that get scanned: the prompt, every string in tool_input, or every string in tool_response.
    pub fn fields(&self) -> Vec<(String, &'a str)> {
        let mut items = Vec::new();
        match self {
            Event::Prompt { text, .. } => items.push(("prompt".into(), *text)),
            Event::PreTool { input: Some(v), .. } | Event::PostTool { response: Some(v) } => walk(v, String::new(), &mut items),
            _ => {}
        }
        items
    }

    /// Findings in `fields`, each naming its field; tool input values get their JSON key as context.
    pub fn scan(&self) -> Vec<Finding> {
        let mut out = Vec::new();
        for (field, text) in self.fields() {
            let key = match self {
                Event::Prompt { .. } => "",
                _ => field.rsplit('.').next().filter(|k| !k.ends_with(']')).unwrap_or(""),
            };
            for mut f in scan_field(key, text) {
                f.field = field.clone();
                out.push(f);
            }
        }
        out
    }

    /// Files whose content the event sends on unredacted: `Artifact` targets, and `@`-mentions in a prompt, which
    /// Claude Code attaches without a tool call. Paths may not exist; the caller skips those.
    pub fn files(&self) -> Vec<PathBuf> {
        match self {
            Event::Prompt { text, cwd } => mentions(text).into_iter().map(|m| resolve(&m, cwd)).collect(),
            Event::PreTool { tool, input: Some(input), cwd } if FILE_TOOLS.contains(tool) => {
                let single = input.get("file_path").and_then(Value::as_str);
                let many = input.get("file_paths").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str);
                let root = cwd.join(input.get("root").and_then(Value::as_str).unwrap_or(""));
                let source = |v: &'a Value| v.as_str().or_else(|| v.get("from").and_then(Value::as_str)).or_else(|| v.get("path").and_then(Value::as_str));
                let supporting: Vec<&str> = match input.get("files") {
                    Some(Value::Object(map)) => map.values().filter(|v| v.get("artifact").is_none()).filter_map(source).collect(),
                    Some(Value::Array(items)) => items.iter().filter_map(source).collect(),
                    _ => Vec::new(),
                };
                let own = single.into_iter().chain(many).map(|p| resolve(p, cwd));
                own.chain(supporting.into_iter().map(|p| resolve(p, &root))).collect()
            }
            _ => Vec::new(),
        }
    }
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

/// Scan a hook event's fields; each finding names its field.
pub fn scan_event(event: &Value) -> Vec<Finding> {
    Event::parse(event).scan()
}

/// Candidates in a hook event that were not reported, with the reason.
pub fn explain_event(event: &Value) -> Vec<Rejection> {
    let mut out = Vec::new();
    for (field, text) in Event::parse(event).fields() {
        for mut r in explain_text(text) {
            r.field = field.clone();
            out.push(r);
        }
    }
    out
}

/// What the hook process answers: exit code, stderr (exit 2 only) and stdout JSON.
#[derive(Debug, PartialEq)]
pub struct Reply {
    pub code: u8,
    pub stderr: Option<String>,
    pub stdout: Option<Value>,
}

pub fn respond(event: &Value, policy: impl FnOnce() -> Policy) -> Reply {
    let event = Event::parse(event);
    let name = event.name();
    let (code, stderr, stdout) = match decide(&event, policy) {
        Decision::Allow => (0, None, None),
        Decision::Block(msg) => (2, Some(msg), None),
        Decision::Steer(note) => (0, None, Some(json!({"hookEventName": name, "additionalContext": note}))),
        Decision::Redact { output, note } => {
            (0, None, Some(json!({"hookEventName": name, "updatedToolOutput": output, "additionalContext": note})))
        }
    };
    Reply { code, stderr, stdout: stdout.map(|out| json!({"hookSpecificOutput": out})) }
}
