use secret_guard::{mask, scan_field, scan_text};

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

fn b64(s: &str) -> String {
    s.as_bytes()
        .chunks(3)
        .flat_map(|c| {
            let n = c.iter().enumerate().fold(0u32, |a, (i, &b)| a | (b as u32) << (16 - 8 * i));
            (0..4).map(move |i| if i <= c.len() { B64[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' })
        })
        .collect()
}

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

#[test]
fn tokens_embedded_in_words_are_not_findings() {
    let token = format!("ghp_{}", random(36, 7, ALNUM));
    assert!(scan_text(&format!("x{token}")).is_empty());
    assert!(scan_text(&format!("prefix_{token}y")).is_empty());
    assert_eq!(scan_text(&format!("({token})")).len(), 1);
}

#[test]
fn secrets_inside_base64_are_found_and_masked_whole() {
    let token = format!("ghp_{}", random(36, 9, ALNUM));
    let text = format!("data:\n  token: {}\n  other: plain\n", b64(&format!("GITHUB_TOKEN={token}")));
    let found = scan_text(&text);
    assert_eq!(found.len(), 1, "{found:?}");
    let out = mask(&text, &found);
    assert!(out.contains("token: [secret-guard: github-token redacted]\n  other: plain"), "{out}");
}

#[test]
fn one_secret_matched_by_several_rules_is_one_finding() {
    let token = format!("ghp_{}", random(36, 7, ALNUM));
    assert_eq!(scan_text(&format!("GITHUB_TOKEN={token}")).len(), 1);
    let password = random(20, 11, ALNUM);
    let found = scan_text(&format!("{token} then db_password={password}"));
    assert_eq!(found.len(), 2, "{found:?}");
}

#[test]
fn token_followed_by_word_char_is_embedded() {
    let token = format!("ghp_{}", random(36, 7, ALNUM));
    assert!(scan_text(&format!("{token}_x")).is_empty());
}

#[test]
fn base64_padding_is_part_of_the_masked_run() {
    let token = format!("ghp_{}", random(36, 9, ALNUM));
    let encoded = b64(&format!("GITHUB_TOKEN={token}"));
    assert!(encoded.ends_with('=') && !encoded.ends_with("=="));
    let text = format!("blob {encoded}=== end");
    assert_eq!(redacted(&text), "blob [secret-guard: github-token redacted]== end");
}

#[test]
fn base64_is_unwrapped_two_levels_deep() {
    let token = format!("ghp_{}", random(36, 9, ALNUM));
    let secret = format!("GITHUB_TOKEN={token}");
    assert_eq!(scan_text(&b64(&b64(&secret))).len(), 1);
    assert!(scan_text(&b64(&b64(&b64(&secret)))).is_empty());
}

#[test]
fn json_key_context_applies_to_short_single_words_only() {
    let password = random(20, 11, ALNUM);
    assert_eq!(scan_field("password", &password).len(), 1);
    assert!(scan_field("", &password).is_empty());
    assert!(scan_field("password", &format!("{password} {password}")).is_empty());
    let long = random(200, 13, ALNUM);
    assert_eq!(scan_field("password", &long).len(), 1);
    assert!(scan_field("password", &format!("{long}x")).is_empty());
}
