use secret_guard::{classify, explain_text, Context, Reason, Verdict};

#[test]
fn rejects_with_reason() {
    let cases: &[(&str, Context, Reason)] = &[
        ("abc", Context::Quoted, Reason::Length),
        ("${DB_PASSWORD}", Context::Quoted, Reason::Reference),
        ("{{ .Values.db.password }}", Context::Quoted, Reason::Template),
        ("changeme123", Context::Quoted, Reason::Placeholder),
        ("Tulip#Kanaal", Context::Quoted, Reason::Wordy),
        ("acme/deploy!335", Context::Quoted, Reason::PathRef),
        ("deploy#1234", Context::Quoted, Reason::PathRef),
        ("!ImportValue", Context::Quoted, Reason::Reference),
        ("PostApiV1CredentialsBody", Context::Quoted, Reason::Identifier),
        ("DB_HOST_V2", Context::Quoted, Reason::ConstCase),
        ("v1.22.3-beta", Context::Quoted, Reason::Version),
        ("j.doe42@acme.io", Context::Quoted, Reason::Email),
        ("i.credentials||S.withCredentials", Context::Unquoted, Reason::Code),
        ("20261013", Context::Quoted, Reason::Numeric),
        ("abcdefghijkl", Context::Quoted, Reason::Placeholder),
    ];
    for &(value, ctx, reason) in cases {
        assert_eq!(classify(value, ctx), Verdict::NotSecret(reason), "{value}");
    }
}

#[test]
fn accepts_random_values() {
    for value in ["Xk29fLm2pQ7vR4", "q8!Zr2#Lm4?Tx9", "Xk29fLm2pQ7vR4!9", "Xk29fLm2pQ7vR4#9", "!Xk29fLm2pQ7vR4", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"] {
        assert_eq!(classify(value, Context::Quoted), Verdict::Secret, "{value}");
    }
}

#[test]
fn decoded_context_accepts_shorter_values() {
    assert_eq!(classify("k2Xp9q", Context::Quoted), Verdict::NotSecret(Reason::Length));
    assert_eq!(classify("k2Xp9q", Context::Decoded), Verdict::Secret);
}

#[test]
fn explain_names_rule_and_reason() {
    let r = explain_text("DATABASE_URL=postgres://app:Xk29fLm2pQ7vR4@localhost:5432/app");
    assert!(r.iter().any(|r| r.rule == "url-credentials" && r.reason == Reason::LocalUrl), "{r:?}");
    let r = explain_text("api_key = ${API_KEY}");
    assert!(r.iter().any(|r| r.rule == "generic-assignment" && r.reason == Reason::Reference), "{r:?}");
}
