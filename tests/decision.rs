use secret_guard::decision::{fingerprint, Decision, Policy};
use secret_guard::hook::Event;
use serde_json::Value;
use serde_json::json;
use std::collections::HashSet;

fn decide(ev: &Value, policy: impl FnOnce() -> Policy) -> Decision {
    secret_guard::decision::decide(&Event::parse(ev), policy)
}

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
    let ctx = secret_guard::redacted_context(&text, f, 50);
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
fn read_is_allowed_but_artifact_publish_of_secret_file_blocks() {
    let dir = temp_dir("read");
    let env = dir.join(".env");
    let call = |tool: &str, p: &str| json!({"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": {"file_path": p}, "cwd": dir});
    assert_eq!(decide(&call("Read", env.to_str().unwrap()), policy(&[])), Decision::Allow);
    let msg = block(decide(&call("Artifact", env.to_str().unwrap()), policy(&[])));
    assert!(msg.contains("blocked Artifact call, the file it would load") && msg.contains(".env"));
    assert!(!msg.contains(&token()));
    block(decide(&call("Artifact", ".env"), policy(&[])));
    for clean in ["clean.txt", "missing.txt", "blob.bin"] {
        assert_eq!(decide(&call("Artifact", clean), policy(&[])), Decision::Allow, "{clean}");
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

#[test]
fn post_tool_use_redacts_output_and_keeps_its_shape() {
    let ev = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "./deploy.sh"},
        "tool_response": {"stdout": format!("using {}\nok", token()), "stderr": "", "interrupted": false, "isImage": false}
    });
    match decide(&ev, policy(&[])) {
        Decision::Redact { output, note } => {
            assert_eq!(output["stdout"], "using [secret-guard: github-token redacted]\nok");
            assert_eq!(output["interrupted"], false);
            assert!(note.contains("1 secret"));
        }
        other => panic!("expected redact, got {other:?}"),
    }
    let clean = json!({"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_response": {"stdout": "ok"}});
    assert_eq!(decide(&clean, || panic!("policy loaded for clean output")), Decision::Allow);
    let allowed = json!({"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_response": {"stdout": token()}});
    assert_eq!(decide(&allowed, policy(&[fingerprint(b"salt", &token())])), Decision::Allow);
}

fn password() -> String {
    let alphabet = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
    let mut x: u64 = 0x9E3779B97F4A7C15;
    (0..20)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            alphabet[(x % alphabet.len() as u64) as usize] as char
        })
        .collect()
}

#[test]
fn bash_secret_dump_blocks() {
    let ev = json!({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "gh auth token"}});
    assert!(block(decide(&ev, policy(&[]))).contains("`gh auth token` would print secret values"));
    let other = json!({"hook_event_name": "PreToolUse", "tool_name": "mcp__x__run", "tool_input": {"command": "gh auth token"}});
    assert_eq!(decide(&other, policy(&[])), Decision::Allow);
}

#[test]
fn block_message_without_tool_name_says_tool() {
    let ev = json!({"hook_event_name": "PreToolUse", "tool_input": {"x": token()}});
    assert!(block(decide(&ev, policy(&[]))).contains("blocked tool call"));
}

#[test]
fn secrets_in_arrays_are_found() {
    let ev = json!({"hook_event_name": "PreToolUse", "tool_name": "mcp__x__y", "tool_input": {"args": ["a", token()]}});
    assert!(block(decide(&ev, policy(&[]))).contains("github-token in args[1]"));
    let post = json!({"hook_event_name": "PostToolUse", "tool_name": "mcp__x__y", "tool_response": [{"type": "text", "text": token()}]});
    match decide(&post, policy(&[])) {
        Decision::Redact { output, .. } => assert_eq!(output[0]["text"], "[secret-guard: github-token redacted]"),
        other => panic!("expected redact, got {other:?}"),
    }
}

#[test]
fn json_keys_give_short_values_context() {
    let pw = password();
    let ev = json!({"hook_event_name": "PreToolUse", "tool_name": "mcp__db__create_user", "tool_input": {"user": "app", "password": pw}});
    assert!(block(decide(&ev, policy(&[]))).contains("in password"));
    let post = json!({"hook_event_name": "PostToolUse", "tool_name": "mcp__db__get", "tool_response": {"user": "app", "password": pw}});
    match decide(&post, policy(&[])) {
        Decision::Redact { output, .. } => {
            assert_eq!(output["password"], "[secret-guard: generic-assignment redacted]");
            assert_eq!(output["user"], "app");
        }
        other => panic!("expected redact, got {other:?}"),
    }
    for key in ["pageToken", "next_page_token", "syncToken", "user", "description"] {
        let ev = json!({"hook_event_name": "PreToolUse", "tool_name": "mcp__x__list", "tool_input": {key: pw}});
        assert_eq!(decide(&ev, policy(&[])), Decision::Allow, "{key}");
    }
}

#[test]
fn artifact_supporting_files_are_scanned() {
    let dir = temp_dir("artifact-files");
    let call = |files: serde_json::Value| {
        json!({"hook_event_name": "PreToolUse", "tool_name": "Artifact", "tool_input": {"file_path": "clean.txt", "files": files}, "cwd": dir})
    };
    block(decide(&call(json!({"config.txt": ".env"})), policy(&[])));
    block(decide(&call(json!({"config.txt": {"from": ".env"}})), policy(&[])));
    block(decide(&call(json!([{"path": ".env"}])), policy(&[])));
    assert_eq!(decide(&call(json!({"a.txt": "clean.txt", "b.css": {"artifact": "x", "path": ".env"}})), policy(&[])), Decision::Allow);
}

#[test]
fn explain_event_names_rejected_candidates() {
    let ev = json!({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "export API_KEY=${API_KEY}"}});
    let rejected = secret_guard::explain_event(&ev);
    assert!(rejected.iter().any(|r| r.field == "command"), "{rejected:?}");
}

#[test]
fn files_up_to_two_mib_are_scanned() {
    let dir = temp_dir("size");
    let head = format!("GITHUB_TOKEN={}\n", token());
    for (name, len, blocked) in [("max.txt", 2 << 20, true), ("over.txt", (2 << 20) + 1, false)] {
        let mut body = head.clone().into_bytes();
        body.resize(len, b'\n');
        std::fs::write(dir.join(name), body).unwrap();
        let ev = json!({"hook_event_name": "PreToolUse", "tool_name": "Artifact", "tool_input": {"file_path": name}, "cwd": dir});
        assert_eq!(matches!(decide(&ev, policy(&[])), Decision::Block(_)), blocked, "{name}");
    }
}
