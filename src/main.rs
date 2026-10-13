//! secret-guard: Claude Code hook that blocks secrets in user prompts and tool calls.
//!
//! Modes:
//!   secret-guard            hook mode: hook event JSON on stdin, exit 2 to block
//!   secret-guard scan       scan raw text on stdin, print redacted findings, exit 1 if any
//!   secret-guard corpus     JSONL on stdin ({"id", "event"}), JSONL out ({"id", "hits": [{"rule", "field", "context"}]});
//!                           secrets are redacted here, so real data never leaves this process in clear
//!   secret-guard eval       JSONL on stdin ({"id", "event"}), JSONL out ({"id", "rules", "secrets", "spans", "rejected"}); no allowlist
//!
//! Hook mode blocks only found secrets: unreadable input is allowed (and logged), a scanner error is
//! allowed with a note telling the model to keep secrets out.
//! SECRET_GUARD_DISABLE=1, or a file named `disabled` in the config dir, disables it. False positives go in
//! ~/.config/secret-guard/allowlist.txt as one fingerprint per line.

use secret_guard::decision::{decide, redact, redacted_context, Decision, Policy};
use secret_guard::{event_fields, explain_event, scan_event, scan_text};
use serde_json::{json, Value};
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

fn config_dir() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"));
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"))
        .join("secret-guard")
}

fn salt() -> Vec<u8> {
    let path = config_dir().join("salt");
    if let Ok(s) = fs::read(&path) {
        if !s.is_empty() {
            return s;
        }
    }
    let mut buf = [0u8; 32];
    if fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf)).is_err() {
        return Vec::new();
    }
    let _ = fs::create_dir_all(config_dir());
    let _ = fs::write(&path, buf);
    buf.to_vec()
}

fn policy() -> Policy {
    let path = config_dir().join("allowlist.txt");
    let allowlist = fs::read_to_string(&path)
        .unwrap_or_default()
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    Policy { salt: salt(), allowlist, allowlist_path: path.display().to_string() }
}

fn log_error(msg: &str) {
    let path = config_dir().join("errors.log");
    let _ = fs::create_dir_all(config_dir());
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{msg}");
    }
}

fn block(msg: &str) -> ExitCode {
    eprintln!("{msg}");
    ExitCode::from(2)
}

fn hook() -> ExitCode {
    if std::env::var("SECRET_GUARD_DISABLE").as_deref() == Ok("1") || config_dir().join("disabled").exists() {
        return ExitCode::SUCCESS;
    }
    let mut input = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input) {
        log_error(&format!("cannot read hook input: {e}"));
        return ExitCode::SUCCESS;
    }
    let event: Value = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(e) => {
            log_error(&format!("bad hook input: {e}"));
            return ExitCode::SUCCESS;
        }
    };
    std::panic::set_hook(Box::new(|info| log_error(&format!("panic: {info}"))));
    match decide(&event, policy) {
        Decision::Allow => ExitCode::SUCCESS,
        Decision::Block(msg) => block(&msg),
        Decision::Steer(note) => {
            let name = event.get("hook_event_name").and_then(Value::as_str).unwrap_or("PreToolUse");
            println!("{}", json!({"hookSpecificOutput": {"hookEventName": name, "additionalContext": note}}));
            ExitCode::SUCCESS
        }
    }
}

fn scan() -> ExitCode {
    let mut input = String::new();
    let _ = io::stdin().read_to_string(&mut input);
    let findings = scan_text(&input);
    for f in &findings {
        println!("{}\t{}..{}\t{}", f.rule, f.start, f.end, redact(&f.secret));
    }
    if findings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn eval() -> ExitCode {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(case) = serde_json::from_str::<Value>(&line) else { continue };
        let findings = scan_event(&case["event"]);
        let rules: Vec<&str> = findings.iter().map(|f| f.rule).collect();
        let secrets: Vec<&str> = findings.iter().map(|f| f.secret.as_str()).collect();
        let rejected: Vec<String> = if findings.is_empty() {
            explain_event(&case["event"]).iter().map(|r| format!("{}:{:?}", r.rule, r.reason)).collect()
        } else {
            Vec::new()
        };
        let spans: Vec<(usize, usize)> = findings.iter().map(|f| (f.start, f.end)).collect();
        let _ = writeln!(out, "{}", json!({"id": case["id"], "rules": rules, "secrets": secrets, "spans": spans, "rejected": rejected}));
    }
    ExitCode::SUCCESS
}

fn corpus() -> ExitCode {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let Ok(case) = serde_json::from_str::<Value>(&line) else { continue };
        let mut hits = Vec::new();
        for (field, text) in event_fields(&case["event"]) {
            for f in scan_text(text) {
                hits.push(json!({"rule": f.rule, "field": field, "context": redacted_context(text, &f, 50)}));
            }
        }
        let _ = writeln!(out, "{}", json!({"id": case["id"], "hits": hits}));
    }
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("scan") => scan(),
        Some("eval") => eval(),
        Some("corpus") => corpus(),
        _ => hook(),
    }
}
