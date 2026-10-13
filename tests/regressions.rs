use secret_guard::{explain_text, scan_event, scan_text};
use serde_json::json;

struct Rng(u64);

impl Rng {
    fn pick(&mut self, n: usize, alphabet: &str) -> String {
        let a = alphabet.as_bytes();
        (0..n)
            .map(|_| {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                a[(self.0 % a.len() as u64) as usize] as char
            })
            .collect()
    }
}

const HEX: &str = "0123456789abcdef";
const A62: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const URLSAFE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn fill(template: &str, rng: &mut Rng) -> String {
    let mut out = template.to_string();
    for (name, n, alphabet) in [("{hex40}", 40, HEX), ("{hex64}", 64, HEX), ("{urlsafe20}", 20, URLSAFE), ("{lower26}", 26, "abcdefghijklmnopqrstuvwxyz0123456789")] {
        while out.contains(name) {
            out = out.replacen(name, &rng.pick(n, alphabet), 1);
        }
    }
    out.replace("{port}", "7906")
}

fn events(text: &str) -> [serde_json::Value; 3] {
    [
        json!({"hook_event_name": "UserPromptSubmit", "prompt": text}),
        json!({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": text}}),
        json!({"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"file_path": "/tmp/x", "content": text}}),
    ]
}

/// Every false positive seen in real data stays clean. Shared with eval/gen_cases.py.
#[test]
fn clean_regressions_stay_clean() {
    let fixtures = include_str!("fixtures/clean-regressions.jsonl");
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let mut n = 0;
    for line in fixtures.lines().filter(|l| !l.trim().is_empty()) {
        let template: String = serde_json::from_str(line).unwrap();
        for _ in 0..20 {
            let text = fill(&template, &mut rng);
            let found = scan_text(&text);
            assert!(found.is_empty(), "false positive {:?} in {text:?}", found.iter().map(|f| f.rule).collect::<Vec<_>>());
            for ev in events(&text) {
                assert!(scan_event(&ev).is_empty(), "false positive in event {ev}");
            }
        }
        n += 1;
    }
    assert!(n >= 20, "fixture file looks truncated: {n} cases");
}

#[test]
fn smoke_positives_are_found() {
    let mut rng = Rng(0xD1B54A32D192ED03);
    for _ in 0..50 {
        let pw = format!("{}{}", rng.pick(8, A62), rng.pick(8, "0123456789"));
        let cases = [
            ("github-token", format!("echo {}{}", "ghp_", rng.pick(36, A62))),
            ("gitlab-token", format!("GITLAB={}{}", "glpat-", rng.pick(20, URLSAFE))),
            ("aws-access-key-id", format!("id {}{}", "AKIA", rng.pick(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"))),
            ("url-credentials", format!("postgres://app:{pw}@db.prod.internal:5432/app")),
            ("short-password-flag", format!("mysql -u root -p{pw} app")),
            ("prose-secret", format!("the password is {pw}")),
            ("generic-assignment", format!("DB_PASSWORD=\"{pw}\"")),
            ("cli-password-flag", format!("app login --password {pw}")),
        ];
        for (rule, text) in cases {
            let found = scan_text(&text);
            assert!(
                found.iter().any(|f| f.rule == rule),
                "{rule} missed in {text:?}, rejected: {:?}",
                explain_text(&text).iter().map(|r| (r.rule, r.reason)).collect::<Vec<_>>()
            );
        }
    }
}

/// The keyword regex, prefilter needles and key-name check must agree on every credential word.
#[test]
fn every_credential_keyword_is_detected() {
    let keys = [
        "password", "passwd", "passphrase", "wachtwoord", "pwd", "secret", "token", "api_key", "apikey", "access-key",
        "secret_key", "private_key", "client_secret", "auth_key", "credential", "credentials", "secret_key_base", "pat",
        "webhook_secret", "signing_key", "encryption_key", "master_key", "DB_PASSWORD", "githubToken",
    ];
    let mut rng = Rng(0xA0761D6478BD642F);
    for key in keys {
        let value = format!("{}{}", rng.pick(10, A62), rng.pick(6, "0123456789"));
        for text in [format!("{key}=\"{value}\""), format!("{key}: {value}")] {
            assert!(
                scan_text(&text).iter().any(|f| f.secret == value),
                "{text:?} missed, rejected: {:?}",
                explain_text(&text).iter().map(|r| (r.rule, r.reason)).collect::<Vec<_>>()
            );
        }
    }
}

#[test]
fn structured_key_formats() {
    const B32: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const LOWER36: &str = "abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = Rng(0x2545F4914F6CDD1D);
    for _ in 0..20 {
        let cases = [
            ("jwk-private-key", format!("{{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{}\",\"d\":\"{}\"}}", rng.pick(43, URLSAFE), rng.pick(43, URLSAFE))),
            ("jwk-private-key", format!("const key = {{\n  kty: 'oct',\n  k: '{}',\n}};", rng.pick(22, URLSAFE))),
            ("paserk-key", format!("\"paserk\": \"k4.secret.{}\"", rng.pick(86, URLSAFE))),
            ("paseto-token", format!("token: v4.public.{}", rng.pick(120, URLSAFE))),
            ("nkey-seed", format!("seed = \"SU{}\"", rng.pick(56, B32))),
            ("mailgun-key", format!("Mailgun::create('key-{}')", rng.pick(32, HEX))),
            ("akamai-client-token", format!("client_token = akab-{}-{}", rng.pick(16, LOWER36), rng.pick(16, LOWER36))),
            ("alibaba-access-key-id", format!("'access_id' => 'LTAI{}'", rng.pick(16, A62))),
            ("wundergraph-key", format!("COSMO={}{}", "cosmo_", rng.pick(32, HEX))),
            ("posthog-personal-key", format!("POSTHOG={}{}", "phx_", rng.pick(43, A62))),
        ];
        for (rule, text) in cases {
            assert!(
                scan_text(&text).iter().any(|f| f.rule == rule),
                "{rule} missed in {text:?}, rejected: {:?}",
                explain_text(&text).iter().map(|r| (r.rule, r.reason)).collect::<Vec<_>>()
            );
        }
        let clean = [
            format!("{{\"kty\":\"RSA\",\"kid\":\"{}\",\"e\":\"AQAB\",\"n\":\"{}\"}}", rng.pick(43, URLSAFE), rng.pick(342, URLSAFE)),
            format!("paserk: k4.public.{}", rng.pick(43, URLSAFE)),
            format!("nats: U{}", rng.pick(55, B32)),
            format!("node-modules-cache-key-{}", rng.pick(32, HEX)),
        ];
        for text in clean {
            assert!(scan_text(&text).is_empty(), "false positive in {text:?}");
        }
    }
}
