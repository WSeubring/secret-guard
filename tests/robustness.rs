use secret_guard::{scan_event, scan_text};

const PIECES: &[&str] = &[
    "\u{a0}", "é", "€", "😀", "\u{2028}", " ", "\n", "\"", "'", "`", "=", ":", "://", "@", "?", "&", "/",
    "-----BEGIN PRIVATE KEY-----", "\\n", "http", "127.0.0.1", "localhost", "token", "password", "secret",
    "Authorization: Bearer ", "Basic ", "glpat-", "ghp_", "eyJ", "LS0tLS1CRUdJTi", "AKIA", "sig=", "sv=2022-11-02",
    "-p", "-u", "--password=", "abc", "Xk29fLm2pQ7vR4", "0123456789abcdef", "%", "%4", "==", "{{", "$",
];

/// Splice random pieces, including multibyte chars next to every pattern, and make sure nothing panics.
#[test]
fn never_panics_on_random_unicode() {
    let mut x: u64 = 0x9E3779B97F4A7C15;
    for _ in 0..20000 {
        let mut s = String::new();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let n = (x % 24) as usize + 1;
        for _ in 0..n {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            s.push_str(PIECES[(x % PIECES.len() as u64) as usize]);
        }
        scan_text(&s);
    }
}

#[test]
fn hook_event_shapes() {
    let prompt = serde_json::json!({"hook_event_name": "UserPromptSubmit", "prompt": "hi"});
    assert!(scan_event(&prompt).is_empty());
    let weird = serde_json::json!({"hook_event_name": "PreToolUse", "tool_input": {"a": [1, null, {"b": true}]}});
    assert!(scan_event(&weird).is_empty());
    let missing = serde_json::json!({});
    assert!(scan_event(&missing).is_empty());
}

#[test]
fn edit_old_string_is_not_scanned() {
    let tok = format!("ghp_{}", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ3kL6");
    let ev = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {"old_string": format!("T = \"{tok}\""), "new_string": "T = os.environ[\"T\"]"}
    });
    assert!(scan_event(&ev).is_empty());
    let ev = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {"old_string": "x", "new_string": format!("T = \"{tok}\"")}
    });
    assert_eq!(scan_event(&ev)[0].rule, "github-token");
}
