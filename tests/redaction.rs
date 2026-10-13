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
