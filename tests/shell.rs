use secret_guard::raw_secret_output;

fn check(command: &str) -> Option<String> {
    raw_secret_output(command)
}

#[test]
fn dumped_secrets_are_blocked() {
    for command in [
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
        "sops -d secrets.enc.yaml",
        "echo \"$(op read op://vault/item/password)\"",
        "true 2>/dev/null; sudo kubectl get secret app -o yaml",
        "( gh auth token )",
        "(gh auth token)",
        "{ gh auth token; }",
        "for i in 1; do gh auth token; done",
        "if true; then gh auth token; fi",
        "bash -c 'gh auth token'",
        "sh -c 'echo $GITHUB_TOKEN'",
        "eval gh auth token",
        "xargs -a f gh auth token",
        "sudo -E gh auth token",
        "sudo -u root kubectl get secret app -o yaml",
        "env FOO=1 gh auth token",
        "kubectl get -n prod secret app -o yaml",
        "kubectl get -o yaml secret app",
        "kubectl get secret/app -o yaml",
        "env | cut -d= -f1-",
        "env | cut -d= -f1,2",
        "env | awk -F= '{print $1, $2}'",
        "kubectl get secret app -o json | jq -r '.data.\"tls.key\"'",
        "gh auth token | rg -L x",
        "gh auth token | grep '>'",
        "cat <<EOF\n$GITHUB_TOKEN\nEOF",
        "cat <<-EOF | grep token\ntoken: ${DB_PASSWORD}\nEOF",
        "echo \"x<<END\"\ngh auth token",
    ] {
        assert!(check(command).is_some(), "not blocked: {command}");
    }
}

#[test]
fn file_reads_and_safe_handling_are_allowed() {
    for command in [
        "cat clean.txt",
        "cat .env",
        "grep -i token .env",
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
        "kubectl get secretstores -o yaml",
        "kubectl get externalsecrets,secretstores -o yaml",
        "gh auth token |& kubeseal --raw --name app",
        "cat <<EOF > .env\nGITHUB_TOKEN=$GITHUB_TOKEN\nEOF",
        "cat <<'EOF'\nGITHUB_TOKEN=$GITHUB_TOKEN\nEOF",
        "cat <<EOF | kubectl apply -f -\ntoken: $GITHUB_TOKEN\nEOF",
        "cat <<EOF\nhome: $HOME \\$GITHUB_TOKEN\nEOF",
        "bash -c 'make test'",
        "(cd src && make)",
        "env | awk -F= '{print $1}'",
        "env | cut -d = -f 1",
        "for f in *.yaml; do kubeseal < $f; done",
    ] {
        assert_eq!(check(command), None, "blocked: {command}");
    }
}
