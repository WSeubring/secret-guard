/// Patterns of the context rules, shared with `build.rs`, which precompiles each into a DFA.
/// The DFA answers "can this rule match at all?" before the capture regex is compiled.
pub const GATED: &[(&str, &str)] = &[
    (
        "url-credentials",
        r#"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver|clickhouse|s?ftp|smtps?|ldaps?|https?|nats|kafka)://[^\s:/@'"]+:(?P<body>[^\s@/'"]+)@[^\s/'"]+"#,
    ),
    (
        "authorization-bearer",
        r#"(?i)\b(?:authorization|auth)["']?[ \t]*[:=][ \t]*["']?(?:bearer|token)[ \t]+(?P<body>[A-Za-z0-9._~+/=-]{16,})"#,
    ),
    (
        "authorization-basic",
        r#"(?i)\b(?:authorization|auth)["']?[ \t]*[:=][ \t]*["']?basic[ \t]+(?P<body>[A-Za-z0-9+/]{8,}={0,2})"#,
    ),
    (
        "curl-user",
        r#"(?:\s-u[ \t]*|--user[= ][ \t]*)(?P<q>["']?)[^\s:'"]+:(?P<body>[^\s'"]{6,})"#,
    ),
    (
        "cli-password-flag",
        r#"(?i)(?:^|[\s;|&(])--?(?:[a-z0-9]+-)*(?:password|passwd|pass|token|secret|api-key|apikey|client-secret|access-key|secret-key|auth-token)(?:=|[ \t]+)(?P<q>["']?)(?P<body>[^\s"']{6,})"#,
    ),
    (
        "short-password-flag",
        r#"\b(?:mysql|mysqldump|mariadb|sshpass|docker[ \t]+login|mongosh|mongo)\b[^\n|;&]*?[ \t]-p(?P<q>["']?)(?P<body>[^\s"'-][^\s"']{5,})"#,
    ),
    (
        "sshpass",
        r#"\bsshpass[ \t]+-p[ \t]*(?P<q>["']?)(?P<body>[^\s"']{6,})"#,
    ),
    (
        "prose-secret",
        r#"(?i)\b(?:password|passwd|passphrase|token|api key|apikey|secret|wachtwoord)[ \t]+(?:is|was|=|:|is:)[ \t]+(?P<q>["'`]?)(?P<body>[^\s"'`]{8,})"#,
    ),
    (
        "generic-assignment",
        r#"(?i)(?P<key>[A-Za-z0-9_./-]*?(?:password|passwd|passphrase|wachtwoord|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key|credentials?|secret_key_base|pat|webhook[_-]?secret|signing[_-]?key|encryption[_-]?key|master[_-]?key))["']?[ \t]*(?::=|=>|:|=)[ \t]*(?:"(?P<dq>[^"\n]+)"|'(?P<sq>[^'\n]+)'|`(?P<bq>[^`\n]+)`|(?P<uq>[^\s"'`,;)}\]=:][^\s"'`,;)}\]]*))"#,
    ),
];
