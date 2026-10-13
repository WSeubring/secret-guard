use secret_guard::{mask, scan_text};

fn random(n: usize, seed: u64, alphabet: &[u8]) -> String {
    let mut x = seed;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            alphabet[(x % alphabet.len() as u64) as usize] as char
        })
        .collect()
}

const ALNUM: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn redacted(text: &str) -> String {
    mask(text, &scan_text(text))
}

#[test]
fn every_secret_on_a_line_is_masked_whatever_rule_finds_it_first() {
    let token = format!("ghp_{}", random(36, 7, ALNUM));
    for len in [20, 120] {
        let password = random(len, 11, ALNUM);
        let out = redacted(&format!("db_password={password} and {token} end"));
        assert!(!out.contains(&password) && !out.contains(&token), "{out}");
        assert!(out.ends_with(" end"), "{out}");
    }
}

#[test]
fn whole_private_key_body_is_masked() {
    let lines: Vec<String> = (0..10).map(|i| random(64, 100 + i, B64)).collect();
    for sep in ["\n", "\\n"] {
        let key = format!(
            "-----BEGIN RSA PRIVATE KEY-----{sep}{}{sep}-----END RSA PRIVATE KEY-----{sep}after",
            lines.join(sep)
        );
        let out = redacted(&key);
        assert!(lines.iter().all(|l| !out.contains(l.as_str())), "{out}");
        assert!(out.contains("-----END RSA PRIVATE KEY-----") && out.ends_with("after"), "{out}");
    }
}

#[test]
fn long_random_key_bodies_are_never_taken_for_placeholders() {
    for seed in 0..300 {
        let body = random(3200, 1000 + seed, B64);
        let lines: Vec<&str> = (0..body.len()).step_by(64).map(|i| &body[i..i + 64]).collect();
        let key = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", lines.join("\n"));
        assert!(!scan_text(&key).is_empty(), "missed key {seed}");
    }
}

#[test]
fn redact_mode_masks_pgp_private_key_blocks() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let lines: Vec<String> = (0..8).map(|i| random(64, 300 + i, B64)).collect();
    let block = format!("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n{}\n-----END PGP PRIVATE KEY BLOCK-----\n", lines.join("\n"));
    let mut child = Command::new(env!("CARGO_BIN_EXE_secret-guard"))
        .arg("redact")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(block.as_bytes()).unwrap();
    let out = String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap();
    assert!(lines.iter().all(|l| !out.contains(l.as_str())), "{out}");
}
