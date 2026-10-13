//! The rule table: each rule is a prefiltered regex plus a check that confirms the match.

use crate::classify::{b64decode_loose, consonant_run, entropy, fake_token, percent_decode, printable, secret_value, Context, Reason};
use crate::{ascii_regex, bytes_regex};
use regex_automata::dfa::{dense::DFA, Automaton};
use regex_automata::Input;
use regex::bytes::{Captures, Regex as BytesRegex};
use regex::Regex;
use serde_json::Value;
use std::sync::{LazyLock, OnceLock};

const KEY_EXCLUDE_WORDS: &[&str] = &[
    "hash", "digest", "checksum", "sha", "sha1", "sha256", "sha512", "fingerprint", "page",
    "cursor", "next", "continuation", "csrf", "xsrf", "nonce", "length", "len", "expiry",
    "expires", "expiration", "ttl", "type", "count", "limit", "max", "min", "public",
    "publishable", "file", "path", "name", "ref", "env", "var", "url", "header", "prefix",
    "regex", "pattern", "field", "label", "placeholder", "example", "sample", "dummy",
    "fake", "mock", "test", "embed",
];

/// Longest `-`/`_`/`.`-separated segment, so placeholder checks skip prefixes like `glpat-` and numeric ids.
fn random_part(body: &str) -> &str {
    let longest = body.split(['-', '_', '.']).max_by_key(|s| s.len()).unwrap_or(body);
    if longest.len() >= 8 {
        longest
    } else {
        body
    }
}

/// Lowercase words of a key name: `dbPassword` and `DB_PASSWORD` both give `[db, password]`.
fn key_words(key: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in key.chars() {
        if !c.is_ascii_alphanumeric() {
            if !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
            prev_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && prev_lower && !cur.is_empty() {
            words.push(std::mem::take(&mut cur));
        }
        prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        cur.push(c.to_ascii_lowercase());
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

/// The key's last word(s) must name a credential; compounds like `dbpassword` count, `oscompat` does not.
fn key_names_secret(words: &[String]) -> bool {
    const LONG: &[&str] = &[
        "password", "passwd", "passphrase", "wachtwoord", "secret", "token", "apikey", "accesskey",
        "secretkey", "privatekey", "authkey", "credential", "credentials", "clientsecret",
    ];
    const KEY_QUALIFIERS: &[&str] = &["api", "access", "secret", "private", "auth", "signing", "encryption", "master"];
    let n = words.len();
    let Some(last) = words.last().map(String::as_str) else { return false };
    if LONG.iter().any(|w| last.ends_with(w)) || matches!(last, "pwd" | "pat") {
        return true;
    }
    if last == "key" && n >= 2 && KEY_QUALIFIERS.contains(&words[n - 2].as_str()) {
        return true;
    }
    last == "base" && n >= 3 && words[n - 2] == "key" && words[n - 3] == "secret"
}

/// Does a variable or key name, like `GITHUB_TOKEN`, name a credential? `1Password` names the password manager.
pub(crate) fn names_secret(name: &str) -> bool {
    let words = key_words(name);
    let product = words.len() >= 2 && words[words.len() - 2] == "1" && words[words.len() - 1] == "password";
    !product && key_names_secret(&words) && !words.iter().any(|w| KEY_EXCLUDE_WORDS.contains(&w.as_str()))
}

#[derive(Clone, Copy)]
pub(crate) enum Check {
    Prefix,
    HighEntropy(f64),
    Jwt,
    Pem,
    PemBase64,
    Sas,
    Strong,
    Prose,
    BasicAuth,
    Ntlm,
    Conn,
    Literal,
    AwsSecret,
    Assignment,
}

mod gates {
    /// Dense DFAs load zero-copy only from u32-aligned bytes.
    #[repr(C, align(4))]
    pub struct Aligned<T: ?Sized>(pub T);

    include!(concat!(env!("OUT_DIR"), "/gates.rs"));
}

pub(crate) struct Span {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) body: String,
}

impl Span {
    fn of(m: regex::bytes::Match, text: &str) -> Option<Span> {
        let (start, end) = (m.start(), m.end());
        (text.is_char_boundary(start) && text.is_char_boundary(end)).then(|| Span { start, end, body: text[start..end].to_string() })
    }
}

pub(crate) struct Rule {
    pub(crate) id: &'static str,
    pat: String,
    pub(crate) check: Check,
    /// The regex only runs (and only compiles) when one of these literals occurs in the text.
    pub(crate) needles: &'static [&'static str],
    /// Needles are matched against the lowercased text.
    pub(crate) ci: bool,
    re: OnceLock<BytesRegex>,
    gate: OnceLock<Option<DFA<&'static [u32]>>>,
}

impl Rule {
    pub(crate) fn re(&self) -> &BytesRegex {
        self.re.get_or_init(|| bytes_regex(&self.pat))
    }

    /// False only when the precompiled DFA proves the regex cannot match, so it need not be compiled.
    pub(crate) fn may_match(&self, text: &[u8]) -> bool {
        let gate = self.gate.get_or_init(|| {
            let (_, bytes) = gates::GATES.iter().find(|(id, _)| *id == self.id)?;
            // SAFETY: build.rs serialized these bytes from a DFA built by regex-automata 0.4; the header is still checked.
            unsafe { DFA::from_bytes_unchecked(&bytes.0) }.ok().map(|(dfa, _)| dfa)
        });
        gate.as_ref().is_none_or(|dfa| !matches!(dfa.try_search_fwd(&Input::new(text).earliest(true)), Ok(None)))
    }
}

const PREFIX_RULES: &[(&str, &[&str], &str)] = &[
    ("aws-access-key-id", &["AKIA", "ASIA", "ABIA", "ACCA"], r"(?P<body>(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})"),
    ("github-token", &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"], r"(?P<body>gh[pousr]_[A-Za-z0-9]{36,})"),
    ("github-fine-grained-pat", &["github_pat_"], r"(?P<body>github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})"),
    ("gitlab-token", &["glpat-", "gldt-", "glrt-", "glcbt-", "glptt-", "glft-", "glimt-", "glagent-", "gloas-", "glsoat-", "glffct-", "glswt-"], r"(?P<body>(?:glpat|gldt|glrt|glcbt|glptt|glft|glimt|glagent|gloas|glsoat|glffct|glswt)-[A-Za-z0-9_-]{20,}(?:\.[0-9a-z]{2}\.[0-9a-z]{6,})?)"),
    ("gitlab-runner-registration", &["GR1348941"], r"(?P<body>GR1348941[A-Za-z0-9_-]{20,})"),
    ("slack-token", &["xox"], r"(?P<body>xox[abposre]-[0-9A-Za-z-]{20,})"),
    ("slack-app-token", &["xapp-"], r"(?P<body>xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]{32,})"),
    ("stripe-live-key", &["_live_"], r"(?P<body>(?:sk|rk)_live_[A-Za-z0-9]{20,})"),
    ("stripe-webhook-secret", &["whsec_"], r"(?P<body>whsec_[A-Za-z0-9+/]{32,})"),
    ("openai-key", &["sk-proj-", "sk-svcacct-", "sk-admin-"], r"(?P<body>sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,})"),
    ("openai-legacy-key", &["T3BlbkFJ"], r"(?P<body>sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})"),
    ("anthropic-key", &["sk-ant-"], r"(?P<body>sk-ant-(?:api|admin|oat|ort|sid)\d{2}-[A-Za-z0-9_-]{80,})"),
    ("google-api-key", &["AIza"], r"(?P<body>AIza[0-9A-Za-z_-]{35})"),
    ("google-oauth-client-secret", &["GOCSPX-"], r"(?P<body>GOCSPX-[A-Za-z0-9_-]{28})"),
    ("google-oauth-refresh-token", &["1//0"], r"(?P<body>1//0[A-Za-z0-9_-]{40,})"),
    ("google-oauth-access-token", &["ya29."], r"(?P<body>ya29\.[A-Za-z0-9_-]{50,})"),
    ("digitalocean-token", &["_v1_"], r"(?P<body>do[opr]_v1_[a-f0-9]{64})"),
    ("docker-hub-token", &["dckr_"], r"(?P<body>dckr_(?:pat|oat)_[A-Za-z0-9_-]{27,})"),
    ("npm-token", &["npm_"], r"(?P<body>npm_[A-Za-z0-9]{36})"),
    ("pypi-token", &["pypi-"], r"(?P<body>pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})"),
    ("huggingface-token", &["hf_"], r"(?P<body>hf_[A-Za-z]{34})"),
    ("sendgrid-key", &["SG."], r"(?P<body>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})"),
    ("shopify-token", &["shpat_", "shpss_", "shpca_", "shppa_"], r"(?P<body>shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32})"),
    ("atlassian-token", &["ATATT3"], r"(?P<body>ATATT3[A-Za-z0-9_=-]{180,})"),
    ("azure-ad-client-secret", &["Q~"], r"(?P<body>[A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.-]{31,34})"),
    ("tailscale-key", &["tskey-"], r"(?P<body>tskey-(?:auth|api|client|scim|webhook)-[A-Za-z0-9]{8,}-[A-Za-z0-9]{20,})"),
    ("grafana-service-account-token", &["glsa_"], r"(?P<body>glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})"),
    ("grafana-cloud-token", &["glc_"], r"(?P<body>glc_[A-Za-z0-9+/]{32,}={0,2})"),
    ("1password-service-account", &["ops_eyJ"], r"(?P<body>ops_eyJ[A-Za-z0-9+/=_-]{100,})"),
    ("telegram-bot-token", &[":AA"], r"(?P<body>\d{8,10}:AA[A-Za-z0-9_-]{33})"),
    ("vault-token", &["hvs.", "hvb."], r"(?P<body>hv[sb]\.[A-Za-z0-9_-]{90,})"),
    ("terraform-cloud-token", &[".atlasv1."], r"(?P<body>[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,})"),
    ("age-secret-key", &["AGE-SECRET-KEY-1"], r"(?P<body>AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58})"),
    ("linear-key", &["lin_api_"], r"(?P<body>lin_api_[A-Za-z0-9]{40})"),
    ("notion-token", &["secret_", "ntn_"], r"(?P<body>secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{46})"),
    ("sentry-token", &["sntrys_", "sntryu_"], r"(?P<body>sntrys_eyJ[A-Za-z0-9+/=_-]{60,}|sntryu_[a-f0-9]{64})"),
    ("databricks-token", &["dapi"], r"(?P<body>dapi[a-f0-9]{32}(?:-\d)?)"),
    ("heroku-token", &["HRKU-"], r"(?P<body>HRKU-[A-Za-z0-9_-]{60,})"),
    ("postman-key", &["PMAK-"], r"(?P<body>PMAK-[a-f0-9]{24}-[a-f0-9]{34})"),
    ("groq-key", &["gsk_"], r"(?P<body>gsk_[A-Za-z0-9]{52})"),
    ("xai-key", &["xai-"], r"(?P<body>xai-[A-Za-z0-9]{80})"),
    ("perplexity-key", &["pplx-"], r"(?P<body>pplx-[A-Za-z0-9]{48})"),
    ("replicate-token", &["r8_"], r"(?P<body>r8_[A-Za-z0-9]{37})"),
    ("plane-api-key", &["plane_api_"], r"(?P<body>plane_api_[a-f0-9]{32})"),
    ("doppler-token", &["dp."], r"(?P<body>dp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,})"),
    ("mailchimp-key", &["-us"], r"(?P<body>[0-9a-f]{32}-us\d{1,2})"),
    ("mailgun-key", &["key-"], r"(?:^|[^\w.-])(?P<body>key-[0-9a-z]{32})"),
    ("akamai-client-token", &["akab-"], r"(?P<body>akab-[0-9a-z]{16}-[0-9a-z]{16})"),
    ("alibaba-access-key-id", &["LTAI"], r"(?P<body>LTAI[A-Za-z0-9]{12,20})"),
    ("posthog-personal-key", &["phx_"], r"(?P<body>phx_[A-Za-z0-9_]{43})"),
    ("wundergraph-key", &["cosmo_"], r"(?P<body>cosmo_[a-f0-9]{32})"),
    ("grafana-api-key", &["eyJrIjoi"], r"(?P<body>eyJrIjoi[A-Za-z0-9+/_-]{30,}={0,2})"),
    ("nkey-seed", &["SA", "SC", "SN", "SO", "SU", "SX"], r"(?P<body>S[ACNOUX][A-Z2-7]{56})"),
    ("paseto-token", &[".local.", ".public."], r"(?P<body>v[1-4]\.(?:local|public)\.[A-Za-z0-9_-]{40,}(?:\.[A-Za-z0-9_-]+)?)"),
    ("paserk-key", &[".local.", ".secret."], r"(?P<body>k[1-4]\.(?:local|secret)\.[A-Za-z0-9_-]{40,})"),
    ("jwk-private-key", &["kty"], r#"(?:^|[{,\s])\\?["']?(?:d|p|q|dp|dq|qi|k)\\?["']?\s*:\s*\\?["'](?P<body>[A-Za-z0-9_-]{22,})"#),
];

/// Pattern of a rule that has a precompiled match gate (see `patterns.rs` and `build.rs`).
fn gated(id: &str) -> &'static str {
    crate::patterns::GATED.iter().find(|(i, _)| *i == id).map(|(_, p)| *p).unwrap()
}

pub(crate) static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    let mut rules: Vec<Rule> = PREFIX_RULES
        .iter()
        .map(|&(id, needles, pat)| Rule { id, pat: pat.to_string(), check: Check::Prefix, needles, ci: false, re: OnceLock::new(), gate: OnceLock::new() })
        .collect();
    let mut add = |id: &'static str, needles: &'static [&'static str], ci: bool, pat: &str, check: Check| {
        rules.push(Rule { id, pat: pat.to_string(), check, needles, ci, re: OnceLock::new(), gate: OnceLock::new() });
    };
    add("azure-storage-key", &["AccountKey="], false, r"AccountKey=(?P<body>[A-Za-z0-9+/]{86}==)", Check::HighEntropy(4.5));
    add(
        "aws-secret-key", &["aws"], true,
        r#"(?i)aws[\w. -]{0,20}?(?:secret|sk)[\w. -]{0,20}?["']?(?:[ \t]*(?:[:=]|=>)[ \t]*|[ \t]+)["']?(?P<body>[A-Za-z0-9/+]{40})"#,
        Check::AwsSecret,
    );
    add(
        "jwt", &["eyJ"], false,
        r"(?P<body>eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,})",
        Check::Jwt,
    );
    add(
        "private-key", &["PRIVATE KEY"], false,
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP |SSH2 ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
        Check::Pem,
    );
    add("private-key-base64", &["LS0tLS1CRUdJTi"], false, r"(?P<body>LS0tLS1CRUdJTi[A-Za-z0-9+/]{60,}={0,2})", Check::PemBase64);
    add(
        "slack-webhook", &["hooks.slack.com"], false,
        r"(?P<body>https://hooks\.slack\.com/(?:services|workflows|triggers)/T[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]{20,})",
        Check::HighEntropy(3.5),
    );
    add(
        "discord-webhook", &["discord"], false,
        r"(?P<body>https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{60,})",
        Check::HighEntropy(3.5),
    );
    add("ntlm-authenticate", &["TlRMTVNTUAAD"], false, r"(?P<body>TlRMTVNTUAAD[A-Za-z0-9+/]{40,}={0,2})", Check::Ntlm);
    add("azure-sas-signature", &["sig="], false, r"[?&]sig=(?P<body>[A-Za-z0-9%+/=]{40,})", Check::Sas);
    add(
        "url-credentials", &["://"], false,
        gated("url-credentials"),
        Check::Conn,
    );
    add(
        "authorization-bearer", &["bearer ", "bearer\t", "token ", "token\t"], true,
        gated("authorization-bearer"),
        Check::Strong,
    );
    add(
        "authorization-basic", &["basic ", "basic\t", "apikey ", "apikey\t"], true,
        gated("authorization-basic"),
        Check::BasicAuth,
    );
    add(
        "docker-config-auth", &["\"auth\"", "\"auth\\\""], false,
        r#""auth\\?"[ \t]*:[ \t]*\\?"(?P<body>[A-Za-z0-9+/]{8,}={0,2})\\?""#,
        Check::BasicAuth,
    );
    add(
        "curl-user", &[" -u", "\t-u", "\n-u", "\r-u", "\x0b-u", "\x0c-u", "--user=", "--user "], false,
        gated("curl-user"),
        Check::Strong,
    );
    add(
        "cli-password-flag", followed_by(&["password", "passwd", "pass", "token", "secret", "key"], &["=", " ", "\t"]), true,
        gated("cli-password-flag"),
        Check::Strong,
    );
    add("securestring-literal", &["convertto-securestring"], true, gated("securestring-literal"), Check::Literal);
    add("curl-setopt", &["CURLOPT_"], false, gated("curl-setopt"), Check::Literal);
    add(
        "short-password-flag", &["mysql", "mariadb", "mongo", "docker"], false,
        gated("short-password-flag"),
        Check::Strong,
    );
    add(
        "sshpass", &["sshpass"], false,
        gated("sshpass"),
        Check::Strong,
    );
    add(
        "prose-secret", followed_by(&["password", "passwd", "passphrase", "token", "api key", "apikey", "secret", "wachtwoord"], &[" ", "\t"]), true,
        gated("prose-secret"),
        Check::Prose,
    );
    add(
        "generic-assignment", key_needles(), true,
        gated("generic-assignment"),
        Check::Assignment,
    );
    rules
});

/// Every way the generic-assignment keyword can end, then the char the assignment regex requires next.
fn key_needles() -> &'static [&'static str] {
    followed_by(
        &["password", "passwd", "passphrase", "wachtwoord", "pwd", "secret", "token", "key", "credential", "credentials", "base", "pat"],
        &["\"", "'", " ", "\t", ":", "="],
    )
}

/// Each word followed by each of `next`: tighter needles, so the regex compiles only when it can match.
fn followed_by(words: &[&str], next: &[&str]) -> &'static [&'static str] {
    let v: Vec<&'static str> = words.iter().flat_map(|w| next.iter().map(move |n| &*format!("{w}{n}").leak())).collect();
    v.leak()
}

fn jwt_verdict(tok: &str) -> Result<(), Reason> {
    let parts: Vec<&str> = tok.split('.').collect();
    let parse = |p: &str| b64decode_loose(p).and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    let Some(Value::Object(h)) = parse(parts[0]) else { return Err(Reason::NotJwt) };
    if !["alg", "typ", "kid", "enc"].iter().any(|k| h.contains_key(*k)) {
        return Err(Reason::NotJwt);
    }
    if let Some(Value::Object(p)) = parse(parts[1]) {
        if p.get("role").and_then(Value::as_str) == Some("anon") {
            return Err(Reason::PublicJwt);
        }
        if p.get("name").and_then(Value::as_str) == Some("John Doe") {
            return Err(Reason::KnownExample);
        }
    }
    fake_token(tok, parts[2])
}

/// Base64 body of a PEM private key whose BEGIN line ends at `from`; the span runs to the end of the body.
/// Lines may be split by newlines or by literal `\n` escapes (a key inside a JSON string).
fn pem_span(text: &str, from: usize) -> Span {
    let rest = &text[from..];
    let limit = rest.char_indices().nth(12000).map(|(i, _)| i).unwrap_or(rest.len());
    let rest = &rest[..limit];
    let mut body = String::new();
    let (mut headers, mut pos, mut end) = (0, 0, 0);
    while pos < rest.len() {
        let line_len = match (rest[pos..].find('\n'), rest[pos..].find("\\n")) {
            (Some(a), Some(b)) => a.min(b),
            (a, b) => a.or(b).unwrap_or(rest.len() - pos),
        };
        let (start, line) = (pos, &rest[pos..pos + line_len]);
        pos += line_len + if rest[pos + line_len..].starts_with("\\n") { 2 } else { 1 };
        let t = line.trim().trim_end_matches("\\r");
        if t.is_empty() {
            continue;
        }
        if t.starts_with("-----END") {
            break;
        }
        if body.is_empty() && headers < 5 && t.contains(": ") {
            headers += 1;
            continue;
        }
        if t.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')) {
            body.push_str(t);
            end = start + line_len;
        } else {
            break;
        }
    }
    Span { start: from, end: from + end, body }
}

fn key_material(body: &str) -> Result<(), Reason> {
    if body.len() < 64 {
        return Err(Reason::NoKeyMaterial);
    }
    fake_token(body, body)
}

impl Check {
    /// The match may not touch a word character on either side.
    pub(crate) fn bounded(self) -> bool {
        matches!(self, Check::Prefix | Check::Jwt | Check::PemBase64)
    }

    /// The part of a regex match that is reported as the secret.
    pub(crate) fn span(self, caps: &Captures, text: &str) -> Option<Span> {
        match self {
            Check::Pem => Some(pem_span(text, caps.get(0)?.end())),
            Check::Assignment => {
                if !text.is_char_boundary(caps.get(0)?.start()) {
                    return None;
                }
                Span::of(["dq", "sq", "bq", "uq"].iter().find_map(|g| caps.name(g))?, text)
            }
            Check::Prose => {
                let mut span = Span::of(caps.name("body")?, text)?;
                let trimmed = span.body.trim_end_matches(['.', ',', ';', ':', ')', ']', '?', '*', '`']).to_string();
                span.end -= span.body.len() - trimmed.len();
                span.body = trimmed;
                Some(span)
            }
            _ => Span::of(caps.name("body")?, text),
        }
    }

    /// Whether the span holds a real credential.
    pub(crate) fn verify(self, caps: &Captures, span: &Span, text: &str) -> Result<(), Reason> {
        let body = span.body.as_str();
        let quoted = caps.name("q").is_some_and(|m| !m.as_bytes().is_empty());
        let ctx = if quoted { Context::Quoted } else { Context::Unquoted };
        let local = |at: usize| if in_local_url(text, at) { Err(Reason::LocalUrl) } else { Ok(()) };
        let min_entropy = |min: f64| if entropy(body) >= min { Ok(()) } else { Err(Reason::LowEntropy) };
        match self {
            Check::Prefix => fake_token(body, random_part(body)),
            Check::HighEntropy(min) => fake_token(body, random_part(body)).and_then(|_| min_entropy(min)),
            Check::AwsSecret => {
                let next = text.as_bytes().get(span.end).copied();
                if matches!(next, Some(b) if b.is_ascii_alphanumeric() || matches!(b, b'/' | b'+' | b'=')) {
                    return Err(Reason::Embedded);
                }
                fake_token(body, body).and_then(|_| min_entropy(4.0))
            }
            Check::Jwt => jwt_verdict(body),
            Check::Pem => key_material(body),
            Check::PemBase64 => {
                static HDR: LazyLock<Regex> = LazyLock::new(|| ascii_regex(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"));
                let pem = b64decode_loose(body).as_deref().and_then(printable).ok_or(Reason::NoKeyMaterial)?;
                let m = HDR.find(&pem).ok_or(Reason::NoKeyMaterial)?;
                key_material(&pem_span(&pem, m.end()).body)
            }
            Check::Sas => {
                let mut from = caps.get(0).unwrap().start().saturating_sub(400);
                while !text.is_char_boundary(from) {
                    from -= 1;
                }
                static SV: LazyLock<Regex> = LazyLock::new(|| ascii_regex(r"(?:[?&]|SharedAccessSignature=)sv=\d{4}-\d\d-\d\d"));
                if !SV.is_match(&text[from..span.end]) {
                    return Err(Reason::NoSasVersion);
                }
                fake_token(body, body)
            }
            Check::Strong | Check::Prose => local(span.start).and_then(|_| secret_value(body, ctx)),
            Check::BasicAuth => {
                local(span.start)?;
                let password = b64decode_loose(body)
                    .as_deref()
                    .and_then(printable)
                    .and_then(|t| t.split_once(':').map(|(_, p)| p.to_string()))
                    .ok_or(Reason::NotBasicCredential)?;
                secret_value(&password, Context::Decoded)
            }
            Check::Ntlm => {
                let msg = b64decode_loose(body).ok_or(Reason::NotNtlmResponse)?;
                let nt_len = msg.get(20..22).map_or(0, |b| u16::from_le_bytes([b[0], b[1]]));
                if nt_len > 0 { Ok(()) } else { Err(Reason::NotNtlmResponse) }
            }
            Check::Conn => local(span.start).and_then(|_| match secret_value(&percent_decode(body), Context::Decoded) {
                Err(Reason::NotRandom) if unpronounceable(body) => Ok(()),
                r => r,
            }),
            Check::Literal => match secret_value(body, Context::Decoded) {
                Err(Reason::NotRandom | Reason::Identifier | Reason::Wordy) => Ok(()),
                r => r,
            },
            Check::Assignment => {
                let key = std::str::from_utf8(caps.name("key").unwrap().as_bytes()).unwrap_or("");
                if !names_secret(key) {
                    return Err(Reason::KeyNotSecret);
                }
                local(caps.get(0).unwrap().start())?;
                let ctx = if caps.name("uq").is_some() { Context::Unquoted } else { Context::Quoted };
                secret_value(body, ctx)
            }
        }
    }
}

/// Lowercase letters with a run of five consonants (`pxidztpv`): random, not a word like `postgres`.
fn unpronounceable(v: &str) -> bool {
    v.len() >= 8
        && v.bytes().all(|b| b.is_ascii_lowercase())
        && consonant_run(v) >= 5
}

/// Credentials for a service on this machine (`http://127.0.0.1:7906/auth?token=…`) are not worth blocking.
fn in_local_url(text: &str, start: usize) -> bool {
    static LOCAL: LazyLock<Regex> = LazyLock::new(|| {
        ascii_regex(r"^[a-z][a-z0-9+.-]*://(?:[\x21-\x2E\x30-\x7E]*@)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?:[:/?#]|$)")
    });
    let delim = |c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '(' | '<' | '>' | '=');
    let Some(scheme) = text[..start].rfind("://") else { return false };
    let from = text[..scheme].char_indices().rev().find(|&(_, c)| delim(c)).map_or(0, |(i, c)| i + c.len_utf8());
    if text[from..start].contains(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`')) {
        return false;
    }
    let end = text[start..].find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`')).map_or(text.len(), |i| start + i);
    LOCAL.is_match(&text[from..end])
}

