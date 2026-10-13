use secret_guard::decision::{decide, fingerprint, Decision, Policy};
use serde_json::json;
use std::collections::HashSet;

fn token() -> String {
    format!("ghp_{}", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ3kL6")
}

fn policy(allow: &[String]) -> impl FnOnce() -> Policy {
    let allowlist: HashSet<String> = allow.iter().cloned().collect();
    move || Policy { salt: b"salt".to_vec(), allowlist, allowlist_path: "/cfg/allowlist.txt".into() }
}

fn block(d: Decision) -> String {
    match d {
        Decision::Block(m) => m,
        other => panic!("expected block, got {other:?}"),
    }
}

#[test]
fn clean_event_allows_without_loading_policy() {
    let ev = json!({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}});
    assert_eq!(decide(&ev, || panic!("policy loaded for a clean event")), Decision::Allow);
}

#[test]
fn prompt_block_names_allowlist_and_fingerprint() {
    let ev = json!({"hook_event_name": "UserPromptSubmit", "prompt": format!("use {}", token())});
    let msg = block(decide(&ev, policy(&[])));
    assert!(msg.contains("prompt blocked"));
    assert!(msg.contains("/cfg/allowlist.txt"));
    assert!(msg.contains(&fingerprint(b"salt", &token())));
    assert!(!msg.contains(&token()));
}

#[test]
fn tool_block_names_tool_and_field() {
    let ev = json!({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": format!("echo {}", token())}});
    let msg = block(decide(&ev, policy(&[])));
    assert!(msg.contains("blocked Bash call"));
    assert!(msg.contains("github-token in command"));
    assert!(!msg.contains(&token()));
}

#[test]
fn allowlisted_fingerprint_allows() {
    let ev = json!({"hook_event_name": "UserPromptSubmit", "prompt": token()});
    assert_eq!(decide(&ev, policy(&[fingerprint(b"salt", &token())])), Decision::Allow);
}

#[test]
fn fingerprint_depends_on_salt() {
    assert_ne!(fingerprint(b"a", "x"), fingerprint(b"b", "x"));
    assert_eq!(fingerprint(b"a", "x").len(), 16);
}

#[test]
fn redacted_context_hides_secret_and_neighbouring_tokens() {
    let text = format!("TOKEN={} region: eu-west-1 id: build20261013xk29fq done", token());
    let f = &secret_guard::scan_text(&text)[0];
    let ctx = secret_guard::decision::redacted_context(&text, f, 50);
    assert!(!ctx.contains(&token()));
    assert!(ctx.contains("«40 chars»"));
    assert!(ctx.contains("region: eu-west-1"));
    assert!(ctx.contains("id: #19 done"));
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("secret-guard-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(".env"), format!("GITHUB_TOKEN={}\n", token())).unwrap();
    std::fs::write(dir.join("clean.txt"), "nothing here\n").unwrap();
    let mut binary = format!("GITHUB_TOKEN={}", token()).into_bytes();
    binary.insert(0, 0);
    std::fs::write(dir.join("blob.bin"), binary).unwrap();
    dir
}

#[test]
fn read_of_file_with_secret_blocks() {
    let dir = temp_dir("read");
    let read = |p: &str| json!({"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": p}, "cwd": dir});
    let msg = block(decide(&read(dir.join(".env").to_str().unwrap()), policy(&[])));
    assert!(msg.contains("blocked Read call, the file it would load") && msg.contains("in file ") && msg.contains(".env"));
    assert!(!msg.contains(&token()));
    block(decide(&read(".env"), policy(&[])));
    for clean in ["clean.txt", "missing.txt", "blob.bin"] {
        assert_eq!(decide(&read(clean), policy(&[])), Decision::Allow, "{clean}");
    }
}

#[test]
fn prompt_mentioning_file_with_secret_blocks() {
    let dir = temp_dir("mention");
    let prompt = |p: &str| json!({"hook_event_name": "UserPromptSubmit", "prompt": p, "cwd": dir});
    block(decide(&prompt("check @.env please"), policy(&[])));
    block(decide(&prompt("look at @.env#L1-2, then fix"), policy(&[])));
    assert_eq!(decide(&prompt("check @clean.txt and ping @alice"), policy(&[])), Decision::Allow);
    assert_eq!(decide(&prompt("mail me@.env.example.com"), policy(&[])), Decision::Allow);
}

#[test]
fn other_tools_do_not_read_files() {
    let dir = temp_dir("write");
    let ev = json!({"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"file_path": dir.join(".env"), "content": "x"}});
    assert_eq!(decide(&ev, policy(&[])), Decision::Allow);
}
