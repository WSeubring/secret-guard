use secret_guard::decision::Policy;
use secret_guard::hook::{respond, Reply};
use serde_json::json;

fn token() -> String {
    format!("ghp_{}", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ3kL6")
}

fn policy() -> Policy {
    Policy { salt: b"salt".to_vec(), allowlist: Default::default(), allowlist_path: "/cfg/allowlist.txt".into() }
}

#[test]
fn clean_event_exits_zero_silently() {
    let ev = json!({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}});
    assert_eq!(respond(&ev, policy), Reply { code: 0, stderr: None, stdout: None });
}

#[test]
fn block_exits_two_with_message_on_stderr() {
    for ev in [
        json!({"hook_event_name": "UserPromptSubmit", "prompt": token()}),
        json!({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": format!("echo {}", token())}}),
    ] {
        let reply = respond(&ev, policy);
        assert_eq!(reply.code, 2);
        assert_eq!(reply.stdout, None);
        assert!(reply.stderr.unwrap().starts_with("secret-guard: "));
    }
}

#[test]
fn redact_replies_with_updated_tool_output() {
    let ev = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_response": {"type": "text", "file": {"filePath": "/x/.env", "content": format!("T={}\n", token())}}
    });
    let reply = respond(&ev, policy);
    assert_eq!(reply.code, 0);
    assert_eq!(reply.stderr, None);
    let out = &reply.stdout.unwrap()["hookSpecificOutput"];
    assert_eq!(out["hookEventName"], "PostToolUse");
    assert_eq!(out["updatedToolOutput"]["type"], "text");
    assert_eq!(out["updatedToolOutput"]["file"]["filePath"], "/x/.env");
    assert_eq!(out["updatedToolOutput"]["file"]["content"], "T=[secret-guard: github-token redacted]\n");
    assert!(out["additionalContext"].as_str().unwrap().contains("1 secret"));
}
