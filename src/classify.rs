//! Does a free-standing value look like a real credential, and if not, why not.

use crate::ascii_regex;
use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

const KNOWN_EXAMPLES: &[&str] = &[
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",
];

const PLACEHOLDER_WORDS: &[&str] = &[
    "example", "sample", "dummy", "fake", "placeholder", "your", "xxxx", "changeme",
    "change_me", "change-me", "replace", "redacted", "insert", "todo", "fixme", "lorem",
    "<", ">", "...", "***", "•",
];

const GENERIC_PLACEHOLDER_WORDS: &[&str] = &[
    "test", "secret", "password", "passwd", "token", "demo", "default", "admin", "foo",
    "bar", "baz", "qwerty", "hunter2", "letmein", "welcome", "mock", "dev", "local",
    "none", "null", "undefined", "string", "required", "optional", "abc123", "123abc",
    "cafe", "dead", "beef", "c0ffee", "feedface", "pass", "secure", "another", "seed",
    "welkom", "correcthorse", "value", "jbswy3dpehpk3pxp",
];

const REFERENCE_PREFIXES: &[&str] = &[
    "$", "@", "&", "*", "!", "env.", "env:", "process.env", "os.environ", "os.getenv",
    "secrets.", "vars.", "inputs.", "env[", "enc[", "vault:", "op://", "ref+", "sm://",
    "arn:", "projects/", "file:", "keyring:", "valuefrom", "secretkeyref", "secretref",
    "sha256:", "sha512:", "sha1:", "sha384:", "md5:", "sha512-", "sha256-", "sha384-",
    "sha1-", "http://", "https://", "/", "./", "../", "~/", "\\",
];

const HASH_PREFIXES: &[&str] = &[
    "$2a$", "$2b$", "$2y$", "$argon2", "$5$", "$6$", "$pbkdf2", "pbkdf2_", "{ssha}", "{sha}",
];

const TEMPLATE_MARKERS: &[&str] = &["{", "}", "$(", "<%", "%>", "%("];

const CODE_MARKERS: &[&str] = &["|", "&&", "??", "?.", "==", "=>", "::", "->"];

const REGEX_MARKERS: &[&str] = &[
    "\\s", "\\S", "\\d", "\\w", "\\b", ".*", ".+", "[^", "[a-z", "[A-Z", "[0-9", "(?",
];


pub(crate) fn entropy(s: &str) -> f64 {
    let mut counts: HashMap<char, usize> = HashMap::new();
    let mut n = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_default() += 1;
        n += 1;
    }
    if n == 0 {
        return 0.0;
    }
    let n = n as f64;
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn has_run(s: &str, n: usize) -> bool {
    let mut prev = None;
    let mut run = 0;
    for c in s.chars().map(|c| c.to_ascii_lowercase()) {
        if Some(c) == prev {
            run += 1;
            if run >= n {
                return true;
            }
        } else {
            prev = Some(c);
            run = 1;
        }
    }
    false
}

fn has_sequence(s: &str, n: usize) -> bool {
    let chars: Vec<char> = s.chars().map(|c| c.to_ascii_lowercase()).collect();
    let mut run = 1;
    for w in chars.windows(2) {
        if w[0].is_ascii_alphanumeric() && w[1].is_ascii_alphanumeric() && w[1] as u32 == w[0] as u32 + 1 {
            run += 1;
            if run >= n {
                return true;
            }
        } else {
            run = 1;
        }
    }
    false
}

fn low_diversity(s: &str) -> bool {
    let mut seen: Vec<char> = s.chars().collect();
    let len = seen.len() as f64;
    seen.sort_unstable();
    seen.dedup();
    (seen.len() as f64) < f64::min(10.0, len * 0.5)
}

fn unleet(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '@' | '4' => 'a',
            '0' => 'o',
            '1' | '!' => 'i',
            '3' => 'e',
            '$' | '5' => 's',
            '7' => 't',
            c => c,
        })
        .collect()
}

pub(crate) fn looks_placeholder(body: &str, generic: bool) -> bool {
    let low = body.to_lowercase();
    if PLACEHOLDER_WORDS.iter().any(|w| low.contains(w)) {
        return true;
    }
    if generic {
        let plain = if low.len() <= 24 && !HEX.is_match(&low) { unleet(&low) } else { String::new() };
        if GENERIC_PLACEHOLDER_WORDS.iter().any(|w| low.contains(w) || plain.contains(w)) {
            return true;
        }
    }
    let letters: String = low.chars().filter(|c| c.is_ascii_lowercase()).collect();
    let digits: String = low.chars().filter(|c| c.is_ascii_digit()).collect();
    let run = if body.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') { 6 } else { 5 };
    has_run(body, run)
        || has_sequence(body, 5)
        || (low.len() <= 24 && has_sequence(&letters, 4) && has_sequence(&digits, 4))
        || low_diversity(body)
}

pub(crate) fn b64decode_loose(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut n = 0;
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        n += 1;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if n % 4 == 1 {
        return None;
    }
    Some(out)
}

pub(crate) fn printable(b: &[u8]) -> Option<String> {
    let t = std::str::from_utf8(b).ok()?;
    if !t.is_empty() && t.chars().all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t')) {
        Some(t.to_string())
    } else {
        None
    }
}

pub(crate) fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() && b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit() {
            let hex = |c: u8| (c as char).to_digit(16).unwrap() as u8;
            out.push(hex(b[i + 1]) * 16 + hex(b[i + 2]));
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

static IDENT_DOTTED: LazyLock<Regex> =
    LazyLock::new(|| ascii_regex(r"^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)+$"));
static CONST_CASE: LazyLock<Regex> = LazyLock::new(|| ascii_regex(r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$"));
static WORDY: LazyLock<Regex> =
    LazyLock::new(|| ascii_regex(r"^[a-z]+(?:[-_.][a-z0-9]+)*$|^[a-z0-9]+(?:[-_.][a-z]+)+$"));
static VERSIONISH: LazyLock<Regex> = LazyLock::new(|| ascii_regex(r"^v?\d+(\.\d+)+([-+][\w.]+)?$"));
static DATEISH: LazyLock<Regex> = LazyLock::new(|| ascii_regex(r"^\d{4}-\d{2}-\d{2}"));
static UUID: LazyLock<Regex> = LazyLock::new(|| {
    ascii_regex(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
});
static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| ascii_regex(r"^[\w.+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$"));
static HEX: LazyLock<Regex> = LazyLock::new(|| ascii_regex(r"^[0-9a-fA-F]+$"));
static B64: LazyLock<Regex> = LazyLock::new(|| ascii_regex(r"^[A-Za-z0-9+/]+={0,2}$"));

/// `PostApiV1CredentialsBody`, `Release-V2-Creds`: several real words, not random humps.
fn looks_identifier(v: &str) -> bool {
    static IDENT: LazyLock<Regex> = LazyLock::new(|| {
        let hump = r"(?:[A-Z]?[a-z]+[0-9]*|[A-Z][0-9]+)";
        ascii_regex(&format!(r"^{hump}(?:[-_.]?{hump})+$"))
    });
    static WORD: LazyLock<Regex> = LazyLock::new(|| ascii_regex(r"[A-Z]?[a-z]{3,}"));
    let camel = v.chars().skip(1).filter(|c| c.is_ascii_uppercase()).count();
    let seps = v.chars().filter(|c| matches!(c, '-' | '_' | '.')).count();
    IDENT.is_match(v) && WORD.find_iter(v).count() >= 3 && camel + seps >= 2
}

/// Text rather than randomness: `Argo/Helm-rendered`, `Tulip#Kanaal`.
fn looks_wordy(v: &str) -> bool {
    let words: Vec<&str> = v.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).collect();
    words.len() >= 2 && words.iter().all(|w| w.len() >= 3 && w.chars().all(char::is_alphabetic))
}

/// References, not values: `acme/deploy!335`, `acme/backend`, `app-staging/API_KEY`.
fn looks_path_ref(v: &str) -> bool {
    static MR_REF: LazyLock<Regex> = LazyLock::new(|| ascii_regex(r"^[\w./-]*[!#]\d+$"));
    if MR_REF.is_match(v) {
        return true;
    }
    v.contains('/')
        && v.split('/').all(|seg| {
            !seg.is_empty()
                && (WORDY.is_match(seg)
                    || CONST_CASE.is_match(seg)
                    || looks_identifier(seg)
                    || (seg.len() <= 24 && seg.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'))))
        })
}

/// Why a candidate was not reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Length,
    KnownExample,
    Reference,
    PasswordHash,
    Template,
    Regex,
    Code,
    Identifier,
    Wordy,
    PathRef,
    Whitespace,
    Email,
    SealedSecret,
    EnvVarSyntax,
    Placeholder,
    DottedName,
    ConstCase,
    Version,
    Date,
    Numeric,
    NotRandom,
    LowEntropy,
    KeyNotSecret,
    LocalUrl,
    Embedded,
    PublicJwt,
    NotJwt,
    NoKeyMaterial,
    NoSasVersion,
    NotBasicCredential,
    NotNtlmResponse,
}

/// Where a value was found, which sets how much evidence it needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Context {
    /// Bare value, e.g. `password=abc`: dotted names are code, not values.
    Unquoted,
    /// Quoted or otherwise delimited value, e.g. `password="abc"`, a URL password.
    Quoted,
    /// Decoded from a carrier (the password half of HTTP Basic auth); shorter values count.
    Decoded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Secret,
    NotSecret(Reason),
}

/// Does a free-standing value look like a real credential (vs code, reference, placeholder)?
pub fn classify(value: &str, ctx: Context) -> Verdict {
    let (quoted, min_len) = match ctx {
        Context::Unquoted => (false, 8),
        Context::Quoted => (true, 8),
        Context::Decoded => (true, 6),
    };
    match classify_at(value, quoted, min_len, 0) {
        Ok(()) => Verdict::Secret,
        Err(r) => Verdict::NotSecret(r),
    }
}

pub(crate) fn secret_value(value: &str, ctx: Context) -> Result<(), Reason> {
    match classify(value, ctx) {
        Verdict::Secret => Ok(()),
        Verdict::NotSecret(r) => Err(r),
    }
}

fn classify_at(v: &str, quoted: bool, min_len: usize, depth: u8) -> Result<(), Reason> {
    let reject = |hit: bool, r: Reason| if hit { Err(r) } else { Ok(()) };
    let v = v.trim();
    let n = v.chars().count();
    reject(n < min_len || n > 200, Reason::Length)?;
    let low = v.to_lowercase();
    reject(KNOWN_EXAMPLES.contains(&v), Reason::KnownExample)?;
    reject(REFERENCE_PREFIXES.iter().any(|p| low.starts_with(p)), Reason::Reference)?;
    reject(HASH_PREFIXES.iter().any(|p| low.starts_with(p)), Reason::PasswordHash)?;
    reject(TEMPLATE_MARKERS.iter().any(|m| v.contains(m)), Reason::Template)?;
    reject(REGEX_MARKERS.iter().any(|m| v.contains(m)), Reason::Regex)?;
    reject(CODE_MARKERS.iter().any(|m| v.trim_end_matches('=').contains(m)), Reason::Code)?;
    reject(looks_identifier(v.trim_end_matches([':', ',', '.'])), Reason::Identifier)?;
    reject(looks_wordy(v), Reason::Wordy)?;
    reject(looks_path_ref(v), Reason::PathRef)?;
    reject(v.chars().any(|c| c.is_whitespace() || matches!(c, '(' | ')' | '[' | ']' | '\\')), Reason::Whitespace)?;
    reject(EMAIL.is_match(v), Reason::Email)?;
    reject(v.starts_with("Ag") && n > 100, Reason::SealedSecret)?;
    reject(v.starts_with('%') && v.ends_with('%'), Reason::EnvVarSyntax)?;
    reject(looks_placeholder(v, true), Reason::Placeholder)?;
    reject(!quoted && IDENT_DOTTED.is_match(v), Reason::DottedName)?;
    reject(CONST_CASE.is_match(v), Reason::ConstCase)?;
    reject(VERSIONISH.is_match(v), Reason::Version)?;
    reject(DATEISH.is_match(v), Reason::Date)?;
    reject(v.chars().all(|c| c.is_ascii_digit()), Reason::Numeric)?;

    if depth == 0 && n >= 8 && n % 4 == 0 && B64.is_match(v) {
        if let Some(text) = b64decode_loose(v).as_deref().and_then(printable) {
            if text.chars().count() >= 4 {
                return classify_at(&text, true, 6, 1);
            }
        }
    }
    reject(!random_shape(v, &low, n), Reason::NotRandom)
}

/// Character-class mix and entropy of a value that passed every structural check.
fn random_shape(v: &str, low: &str, n: usize) -> bool {
    let lower = v.chars().any(|c| c.is_lowercase());
    let upper = v.chars().any(|c| c.is_uppercase());
    let digit = v.chars().any(|c| c.is_ascii_digit());
    let symbol = v.chars().any(|c| !c.is_alphanumeric() && !matches!(c, '-' | '_' | '.'));
    let ent = entropy(v);

    if UUID.is_match(v) || (HEX.is_match(v) && n >= 32) {
        return true;
    }
    if lower && upper && digit {
        return ent >= 2.5;
    }
    if symbol && digit && (lower || upper) {
        return ent >= 2.5;
    }
    if symbol && lower && upper {
        return n >= 10 && ent >= 3.0;
    }
    if digit && (lower != upper) {
        let digits = v.chars().filter(|c| c.is_ascii_digit()).count();
        let ratio = digits as f64 / n as f64;
        let separated = v.contains(['-', '_', '.']);
        if !separated && n >= 16 && digits >= 2 && ent >= 3.5 {
            return true;
        }
        if WORDY.is_match(low) && ratio < 0.25 {
            return false;
        }
        return n >= 12 && ratio >= 0.2 && ent >= 3.0;
    }
    if lower && upper && !digit {
        let uppers = v.chars().filter(|c| c.is_uppercase()).count() as f64 / n as f64;
        return (n >= 16 && !v.contains(['-', '_', '.']) && (0.3..=0.7).contains(&uppers) && ent >= 3.8)
            || (n >= 32 && ent >= 4.2);
    }
    false
}

pub(crate) fn fake_token(token: &str, part: &str) -> Result<(), Reason> {
    if KNOWN_EXAMPLES.contains(&token) {
        return Err(Reason::KnownExample);
    }
    if looks_placeholder(part, false) {
        return Err(Reason::Placeholder);
    }
    Ok(())
}
