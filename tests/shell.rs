use secret_guard::raw_secret_output;
use secret_guard::shell::SecretFile;
use std::path::{Path, PathBuf};

fn workdir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("secret-guard-shell-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(".env"), format!("GITHUB_TOKEN=ghp_{}\nAPP_ENV=prod\n", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ3kL6")).unwrap();
    std::fs::write(dir.join("clean.txt"), "nothing to see\n").unwrap();
    dir
}

fn check(dir: &Path, command: &str) -> Option<String> {
    let secrets = |p: &Path| {
        let text = std::fs::read_to_string(p).ok()?;
        let found = secret_guard::scan_text(&text);
        (!found.is_empty()).then(|| SecretFile {
            lines: found.iter().map(|f| text[..f.start].matches('\n').count() + 1).collect(),
            secrets: found.into_iter().map(|f| f.secret).collect(),
            text,
        })
    };
    raw_secret_output(command, dir, &secrets)
}

#[test]
fn raw_secret_output_is_blocked() {
    let dir = workdir();
    for command in [
        "cat .env",
        "cd /srv && grep TOKEN .env",
        "kubectl get secret app -o yaml",
        "kubectl -n prod get secret app -o jsonpath='{.data.password}' | base64 -d",
        "kubectl get secret app -ojson | jq '.data'",
        "kubectl get secret app -o yaml >&2",
        "op read op://vault/item/password",
        "op item get db --vault Dev --format json --reveal | jq -r '.fields[]'",
        "gh auth token",
        "printenv",
        "env | grep TOKEN",
        "echo $GITHUB_TOKEN",
        "echo \"token: ${DB_PASSWORD}\"",
        "echo \"$(cat .env)\"",
        "sops -d secrets.enc.yaml",
        "grep -i token .env",
        "grep -C1 APP_ENV .env",
        "head -n 1 .env",
        "sed -n 1,2p .env",
        "grep -oE 'GITHUB_TOKEN=.*' .env",
        "true 2>/dev/null; sudo cat .env",
    ] {
        assert!(check(&dir, command).is_some(), "not blocked: {command}");
    }
}

#[test]
fn piped_or_hidden_output_is_allowed() {
    let dir = workdir();
    for command in [
        "cat clean.txt",
        "cat .env | cut -d= -f1",
        "cut -d= -f1 .env",
        "grep -c TOKEN .env",
        "wc -l .env",
        "kubectl get secrets",
        "kubectl describe secret app",
        "kubectl get secret app -o json | jq '.data | keys'",
        "kubectl get secret app -o jsonpath='{.metadata.name}'",
        "kubectl get secret app -o jsonpath='{.data.password}' | base64 -d | kubeseal --raw --name app",
        "kubectl get secret app -o yaml > /tmp/app.yaml",
        "kubectl get secret app -o yaml | sha256sum",
        "export TOKEN=$(op read op://vault/item/password)",
        "op read op://vault/item/password | docker login -u ci --password-stdin",
        "gh auth token | wc -c",
        "printenv HOME",
        "echo $HOME",
        "env FOO=1 make test",
        "sops -d -i secrets.yaml",
        "cat > .env <<EOF\nGITHUB_TOKEN=placeholder\nEOF",
        "echo 'cat .env' >> notes.md",
        "sed 's/=.*/= .../' .env",
        "env | grep -i '^OP_' | sed 's/=.*/=<set>/'",
        "awk -F= '{print $1}' .env",
        "grep -oE '^[A-Z_]+' .env",
        "cat .env | grep -viE 'key|token|secret'",
        "head -c 0 .env",
        "tail -n 1 .env",
        "grep -n APP_ENV .env",
        "grep -A0 -iE 'app_env|debug' .env",
        "sed -n 2p .env",
        "sed -i 's/prod/dev/' .env",
        "echo $PWD",
        "echo 'GITLAB_TOKEN=$CI_JOB_TOKEN'",
        "echo \"hash: $(kubectl get secret app -o jsonpath='{.data.key}' | base64 -d | sha256sum)\"",
    ] {
        assert_eq!(check(&dir, command), None, "blocked: {command}");
    }
}
