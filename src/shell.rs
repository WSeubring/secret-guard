//! Would a Bash command dump secret values? Output is redacted on the way back (PostToolUse), but only the
//! secrets the scanner recognises; commands that print nothing but secret values are blocked up front.
//!
//! A command that dumps secrets is only a problem when its output
//! reaches the end of the pipeline through printers like `grep` or `jq`. A consumer (`kubeseal`, `wc`, any
//! unknown command), a names-only filter (`jq keys`, `cut -d= -f1`), a redirect to a file, or a `$(...)`
//! keeps the values out.

/// Commands that pass their input or file arguments through to their output.
const PRINTERS: &[&str] = &[
    "cat", "head", "tail", "less", "more", "bat", "grep", "egrep", "fgrep", "rg", "sed", "awk", "cut", "jq", "yq",
    "base64", "sort", "uniq", "tr", "column", "tee", "xxd", "od", "strings", "nl", "tac", "fold", "rev", "paste",
];

/// Words before the command itself, with their flags that take a value.
const PREFIXES: &[(&str, &[&str])] = &[
    ("sudo", &["-u", "-g", "-h", "-C", "-D", "-p", "-U"]),
    ("xargs", &["-a", "-I", "-n", "-P", "-d", "-E", "-L", "-s"]),
    ("env", &["-u", "-C", "-S"]),
    ("timeout", &["-s", "-k", "--signal", "--kill-after"]),
    ("nice", &["-n"]),
    ("watch", &["-n", "--interval"]),
    ("stdbuf", &[]), ("time", &[]), ("nohup", &[]), ("command", &[]), ("exec", &[]), ("builtin", &[]),
    ("if", &[]), ("then", &[]), ("elif", &[]), ("else", &[]), ("do", &[]), ("while", &[]), ("until", &[]), ("{", &[]), ("!", &[]),
];

/// What the command would print, e.g. `kubectl get secret -o yaml` or `cat .env`, or `None` when nothing raw.
pub fn raw_secret_output(command: &str) -> Option<String> {
    for statement in split_top(&strip_heredocs(command), &[";", "&&", "||", "\n", "&"]) {
        let stages: Vec<Vec<String>> = split_top(&statement, &["|"]).iter().map(|s| words(s)).collect();
        if let Some(found) = pipeline(&stages) {
            return Some(found);
        }
    }
    None
}

fn pipeline(stages: &[Vec<String>]) -> Option<String> {
    for (i, stage) in stages.iter().enumerate() {
        let cmd = command_words(stage);
        let Some(source) = dump(cmd).or_else(|| echoed_substitution(cmd)).or_else(|| nested(cmd)) else {
            continue;
        };
        let printed = !redirected(stage) && stages[i + 1..].iter().all(|s| passes_through(command_words(s)) && !redirected(s));
        if printed {
            return Some(source);
        }
    }
    None
}

/// The stage's command and arguments, without `VAR=x`, `sudo -E`, `do` and the like. Bare `env` is a command.
fn command_words(stage: &[String]) -> &[String] {
    let mut i = 0;
    while let Some(w) = stage.get(i) {
        if is_assignment(w) {
            i += 1;
            continue;
        }
        let Some((_, takes_value)) = PREFIXES.iter().find(|(p, _)| p == w) else { break };
        if w == "env" && i + 1 == stage.len() {
            break;
        }
        i += 1;
        i = after_flags(stage, i, takes_value);
        if w == "timeout" {
            i += 1;
        }
    }
    &stage[i.min(stage.len())..]
}

fn is_assignment(w: &str) -> bool {
    w.split_once('=').is_some_and(|(k, _)| !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
}

fn passes_through(cmd: &[String]) -> bool {
    cmd.first().is_some_and(|c| PRINTERS.contains(&base(c))) && !hides(cmd)
}

/// A printer that shows names or counts only.
fn hides(cmd: &[String]) -> bool {
    let Some(c) = cmd.first().map(|c| base(c)) else { return false };
    let flags = || cmd[1..].iter().filter(|w| w.starts_with('-') && !w.starts_with("--"));
    match c {
        "grep" | "egrep" | "fgrep" | "rg" => {
            let names_only: &[char] = if c == "rg" { &['c', 'l', 'q'] } else { &['c', 'l', 'L', 'q'] };
            flags().any(|f| f.contains(names_only))
                || cmd.iter().any(|w| matches!(w.as_str(), "--count" | "--quiet" | "--files-with-matches"))
        }
        "sed" => {
            cmd.iter().any(|w| w == "-i" || w.starts_with("--in-place") || w.starts_with("-i."))
                || cmd[1..].iter().any(|w| ["***", "redacted", "<x>", "<set>", "...", "=.*"].iter().any(|m| w.to_lowercase().contains(m)))
        }
        "awk" => {
            let program = |w: &String| unword(w).split_whitespace().collect::<String>() == "{print$1}";
            has_flag(cmd, "-F", "=") && cmd.iter().any(program)
        }
        "head" | "tail" => cmd.windows(2).any(|p| p[0] == "-c" && p[1].parse::<u32>().is_ok_and(|n| n <= 8))
            || cmd.iter().any(|w| w.strip_prefix("-c").and_then(|n| n.parse::<u32>().ok()).is_some_and(|n| n <= 8)),
        "cut" => has_flag(cmd, "-f", "1") && has_flag(cmd, "-d", "="),
        "jq" | "yq" => cmd[1..].iter().filter(|w| !w.starts_with('-')).any(|w| {
            let path = w.split('"').step_by(2).collect::<String>().to_lowercase();
            let counted = |rest: &str| rest.trim_start().strip_prefix('|').is_some_and(|r| ["keys", "length"].iter().any(|k| r.trim_start().starts_with(k)));
            let values = [".data", ".stringdata", ".value", "secretstring", "secretbinary"]
                .iter()
                .any(|k| path.match_indices(k).any(|(i, _)| !counted(&path[i + k.len()..])));
            !values && ["keys", "length", "paths", ".metadata", ".kind", "type", ".key", "label", ".name", ".arn"].iter().any(|k| path.contains(k))
        }),
        _ => false,
    }
}

/// Index of the first word from `i` that is not a flag or the value of one in `takes_value`.
fn after_flags<S: AsRef<str>>(words: &[S], mut i: usize, takes_value: &[&str]) -> usize {
    while let Some(flag) = words.get(i).map(AsRef::as_ref).filter(|f| f.starts_with('-')) {
        i += if takes_value.contains(&flag) { 2 } else { 1 };
    }
    i
}

/// The value of `--flag value` or `--flag=value`.
fn flag_value<'a>(w: &[&'a str], flag: &str) -> Option<&'a str> {
    w.iter().enumerate().find_map(|(i, x)| if *x == flag { w.get(i + 1).copied() } else { x.strip_prefix(flag)?.strip_prefix('=') })
}

/// `flag` with `value`, attached (`-f1`) or separate (`-f 1`).
fn has_flag(cmd: &[String], flag: &str, value: &str) -> bool {
    cmd.iter().any(|w| w.strip_prefix(flag) == Some(value)) || cmd.windows(2).any(|p| p[0] == flag && p[1] == value)
}

/// `> file` on stdout; `> /dev/stderr` and `>&2` still reach the conversation.
fn redirected(stage: &[String]) -> bool {
    stage.iter().enumerate().any(|(i, w)| {
        let target = match w.strip_prefix("&>").or(w.strip_prefix("1>")).or(w.strip_prefix('>')) {
            Some(rest) => rest.trim_start_matches('>'),
            None => return false,
        };
        let target = if target.is_empty() { stage.get(i + 1).map_or("", |t| t.as_str()) } else { target };
        !target.is_empty() && !target.starts_with('&') && !matches!(target, "/dev/stdout" | "/dev/stderr" | "/dev/tty")
    })
}

fn base(cmd: &str) -> &str {
    cmd.rsplit('/').next().unwrap_or(cmd)
}

/// Commands whose output is secret values.
fn dump(cmd: &[String]) -> Option<String> {
    const GLOBAL_VALUE_FLAGS: &[&str] = &[
        "--profile", "--region", "--endpoint-url", "--project", "--account", "--configuration", "--context",
        "--kubeconfig", "--config", "-n", "--namespace", "-namespace", "-address", "-o", "--output",
    ];
    let c = base(cmd.first()?);
    if cmd.iter().any(|x| matches!(x.as_str(), "--help" | "-h" | "help")) {
        return None;
    }
    let w: Vec<&str> = cmd[..1].iter().chain(&cmd[after_flags(cmd, 1, GLOBAL_VALUE_FLAGS).min(cmd.len())..]).map(String::as_str).collect();
    let all: Vec<&str> = cmd.iter().map(String::as_str).collect();
    let has = |x: &str| all.contains(&x);
    let label = |s: &str| Some(s.to_string());
    match c {
        "kubectl" | "oc" => {
            const TAKES_VALUE: &[&str] = &["-n", "--namespace", "-o", "--output", "-l", "--selector", "--context", "--kubeconfig"];
            let mut i = w.iter().position(|x| *x == "get")? + 1;
            let kind = loop {
                let x = w.get(i)?;
                if !x.starts_with('-') {
                    break x;
                }
                i += if TAKES_VALUE.contains(x) { 2 } else { 1 };
            };
            if !kind.split(',').any(|k| matches!(k.split('/').next(), Some("secret" | "secrets"))) {
                return None;
            }
            let output = w.iter().enumerate().find_map(|(i, x)| {
                if *x == "-o" || *x == "--output" {
                    w.get(i + 1).copied()
                } else {
                    x.strip_prefix("--output=").or(x.strip_prefix("-o=")).or(x.strip_prefix("-o")).filter(|v| !v.is_empty())
                }
            })?;
            let values = output.starts_with("yaml") || output.starts_with("json") && !output.starts_with("jsonpath")
                || (output.starts_with("jsonpath") || output.contains("template")) && output.contains(".data");
            values.then(|| format!("{c} get secret -o {}", output.split(['=', '{']).next().unwrap_or(output)))
        }
        "op" => match w.get(1..3) {
            Some(["read", _]) if !has("-o") && !has("--out-file") => label("op read"),
            Some(["item", "get"]) if has("--reveal") => label("op item get --reveal"),
            Some(["inject", _]) if !w.iter().any(|x| x.starts_with("-o") || x.starts_with("--out-file")) => label("op inject"),
            _ => None,
        },
        "gh" if w.get(1..3) == Some(&["auth", "token"]) => label("gh auth token"),
        "glab" if w.get(1..3) == Some(&["auth", "status"]) && (has("-t") || has("--show-token")) => label("glab auth status -t"),
        "glab" if matches!(w.get(1..3), Some(["variable", "get" | "export"])) => label("glab variable get"),
        "printenv" if w.len() == 1 || w[1..].iter().any(|v| crate::rules::names_secret(v)) => label("printenv"),
        "env" if w.len() == 1 => label("env"),
        "echo" | "printf" => w[1..].iter().flat_map(|a| variables(a)).find(|v| crate::rules::names_secret(v)).map(|v| format!("{c} ${v}")),
        "vault" if (matches!(w.get(1..3), Some(["kv", "get"])) || w.get(1) == Some(&"read")) && !w.iter().any(|x| x.starts_with("sys/")) => {
            label("vault read")
        }
        "aws" => {
            let read = w.get(1..3) == Some(&["secretsmanager", "get-secret-value"]) || w.get(1) == Some(&"ssm") && has("--with-decryption");
            let names_only = flag_value(&all, "--query").is_some_and(|q| !q.to_lowercase().contains("secret") && !q.to_lowercase().contains("value"));
            let config = w.get(1..3) == Some(&["configure", "get"]) && w.get(3).is_some_and(|k| crate::rules::names_secret(k));
            (read && !names_only || config).then(|| "aws secret read".to_string())
        }
        "gcloud" if w.get(1..4) == Some(&["secrets", "versions", "access"]) => label("gcloud secrets versions access"),
        "az" if w.get(1..4) == Some(&["keyvault", "secret", "show"]) => label("az keyvault secret show"),
        "sops" if (has("-d") || has("--decrypt") || w.get(1) == Some(&"decrypt"))
            && !has("-i") && !has("--in-place") && flag_value(&all, "--output").is_none() =>
        {
            label("sops -d")
        }
        "terraform" | "tofu" if w.get(1) == Some(&"output") && (has("-raw") || has("-json")) => label("terraform output -raw"),
        "doppler" if w.get(1) == Some(&"secrets") && match w.get(2) {
            None => true,
            Some(&"get") => has("--plain"),
            Some(&"download") => has("--no-file"),
            _ => false,
        } => label("doppler secrets"),
        "pass" if w.get(1) == Some(&"show") => label("pass show"),
        "bw" if matches!(w.get(1..3), Some(["get", "password" | "item"])) => label("bw get"),
        "git" if w.get(1..3) == Some(&["credential", "fill"]) => label("git credential fill"),
        "security" if w.get(1).is_some_and(|s| s.starts_with("find-") && s.ends_with("-password")) && (has("-w") || has("-g")) => {
            label("security find-password")
        }
        _ => None,
    }
}

/// Names in `$NAME` and `${NAME}` that the shell expands, outside `$(...)`; `$PWD` is a directory and
/// `${NAME:+set}` only says whether it is set.
fn variables(arg: &str) -> Vec<&str> {
    let outside = arg.split_once("$(").map_or(arg, |(before, _)| before);
    outside
        .split('$')
        .skip(1)
        .filter_map(|rest| {
            let braced = rest.strip_prefix('{');
            let rest = braced.unwrap_or(rest);
            let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(rest.len());
            let presence = braced.is_some() && rest[end..].starts_with([':', '+']) && rest[end..].trim_start_matches(':').starts_with('+');
            (!presence).then_some(&rest[..end])
        })
        .filter(|v| !v.is_empty() && !matches!(*v, "PWD" | "OLDPWD"))
        .collect()
}

/// `echo "$(op read …)"`: a substitution whose output is printed.
fn echoed_substitution(cmd: &[String]) -> Option<String> {
    if !matches!(base(cmd.first()?), "echo" | "printf") {
        return None;
    }
    cmd[1..].iter().find_map(|a| {
        let inner = a.split_once("$(")?.1;
        raw_secret_output(&unword(inner.rsplit_once(')').map_or(inner, |(body, _)| body)))
    })
}

/// `(cmd)`, `bash -c 'cmd'`, `eval cmd`, `ssh host cmd`, `kubectl exec pod -- cmd`, `docker exec ctr cmd`: a
/// command run inside this one, whose output comes back here.
fn nested(cmd: &[String]) -> Option<String> {
    let first = cmd.first()?;
    if let Some(inner) = first.strip_prefix('(') {
        return raw_secret_output(&unword(inner.strip_suffix(')').unwrap_or(inner)));
    }
    match base(first) {
        "sh" | "bash" | "zsh" | "dash" | "su" | "script" => {
            let c = cmd.iter().position(|w| w.starts_with('-') && !w.starts_with("--") && w.ends_with('c'))?;
            raw_secret_output(&unword(cmd.get(c + 1)?))
        }
        "eval" => raw_secret_output(&unword(&cmd[1..].join(" "))),
        "ssh" => {
            const TAKES_VALUE: &[&str] = &["-p", "-i", "-l", "-o", "-F", "-J", "-L", "-R", "-D", "-W", "-E", "-S", "-b", "-c", "-m"];
            let host = after_flags(cmd, 1, TAKES_VALUE);
            raw_secret_output(&unword(&cmd.get(host + 1..)?.join(" ")))
        }
        "kubectl" | "oc" if cmd.iter().any(|w| w == "exec") => {
            let dashes = cmd.iter().position(|w| w == "--")?;
            raw_secret_output(&unword(&cmd[dashes + 1..].join(" ")))
        }
        "docker" | "podman" => {
            const TAKES_VALUE: &[&str] = &["-e", "--env", "-u", "--user", "-w", "--workdir", "--env-file"];
            let exec = cmd.iter().position(|w| w == "exec")?;
            let target = after_flags(cmd, exec + 1, TAKES_VALUE);
            raw_secret_output(&unword(&cmd.get(target + 1..)?.join(" ")))
        }
        _ => None,
    }
}

/// A word back as shell text, for commands that run it again: quoted `$` and `>` are live there.
fn unword(w: &str) -> String {
    w.replace('\u{1}', "$").replace('\u{2}', ">")
}

/// Heredoc bodies are data, not commands. An unquoted terminator expands `$VARS` in the body, so
/// `cat <<EOF` there becomes an `echo` of the secret-named ones, keeping the rest of its line (`> file`, `| cmd`).
fn strip_heredocs(command: &str) -> String {
    let mut out = String::new();
    let mut open: Option<(String, bool, &str)> = None;
    let mut secrets: Vec<String> = Vec::new();
    for line in command.lines() {
        if let Some((terminator, expands, opener)) = &open {
            if line.trim() == terminator {
                out.push_str(&expanded(opener, &secrets));
                out.push('\n');
                open = None;
                secrets.clear();
            } else if *expands {
                let live = line.replace("\\$", "");
                secrets.extend(variables(&live).into_iter().filter(|v| crate::rules::names_secret(v)).map(String::from));
            }
            continue;
        }
        if let Some((terminator, expands, _, _)) = heredoc(line) {
            open = Some((terminator, expands, line));
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if let Some((_, _, opener)) = open {
        out.push_str(opener);
    }
    out
}

/// The heredoc a line opens: terminator, whether the body expands, and the line before and after it.
fn heredoc(line: &str) -> Option<(String, bool, &str, &str)> {
    let at = line.match_indices("<<").map(|(i, _)| i).find(|&i| {
        let before = &line[..i];
        before.matches('\'').count() % 2 == 0 && before.matches('"').count() % 2 == 0
    })?;
    let rest = &line[at + 2..];
    if rest.starts_with('<') {
        return None;
    }
    let rest = rest.trim_start_matches(['-', '~']).trim_start();
    let quoted = rest.starts_with(['\'', '"']);
    let rest = rest.trim_start_matches(['\'', '"']);
    let len = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(rest.len());
    let after = rest[len..].trim_start_matches(['\'', '"']);
    (len > 0).then(|| (rest[..len].to_string(), !quoted, &line[..at], after))
}

fn expanded(opener: &str, secrets: &[String]) -> String {
    let Some((_, _, before, after)) = heredoc(opener) else { return opener.to_string() };
    let Some(args) = before.trim_start().strip_prefix("cat").filter(|a| a.is_empty() || a.starts_with(' ')) else {
        return opener.to_string();
    };
    if secrets.is_empty() {
        return opener.to_string();
    }
    let vars: Vec<String> = secrets.iter().map(|v| format!("${{{v}}}")).collect();
    format!("echo {}{args} {after}", vars.join(" "))
}

/// Split on separators outside quotes, `$(...)`, `(...)` and backticks.
fn split_top(s: &str, seps: &[&str]) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let (mut single, mut double, mut tick, mut depth) = (false, false, false, 0u32);
    let mut i = 0;
    let b = s.as_bytes();
    while i < b.len() {
        let c = b[i] as char;
        let quoted = single || double || tick || depth > 0;
        match c {
            '\\' if !single && i + 1 < b.len() => {
                let end = s[i + 1..].chars().next().map_or(i + 1, |ch| i + 1 + ch.len_utf8());
                cur.push_str(&s[i..end]);
                i = end;
                continue;
            }
            '\'' if !double && !tick => single = !single,
            '"' if !single && !tick => double = !double,
            '`' if !single => tick = !tick,
            '(' if !single => depth += 1,
            ')' if !single && depth > 0 => depth -= 1,
            _ => {}
        }
        if !quoted && !single && !double {
            if let Some(sep) = seps.iter().find(|sep| s[i..].starts_with(**sep)) {
                let pipe_or = *sep == "|" && s[i..].starts_with("||");
                let amp_and = *sep == "&"
                    && (s[i..].starts_with("&&") || s[i..].starts_with("&>") || (i > 0 && matches!(b[i - 1], b'>' | b'|')));
                if !pipe_or && !amp_and {
                    parts.push(std::mem::take(&mut cur));
                    i += sep.len() + usize::from(*sep == "|" && s[i + 1..].starts_with('&'));
                    continue;
                }
            }
        }
        let end = s[i..].chars().next().map_or(i + 1, |ch| i + ch.len_utf8());
        cur.push_str(&s[i..end]);
        i = end;
    }
    parts.push(cur);
    parts.into_iter().map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect()
}

/// Shell words with quotes removed; `$(...)` stays inside its word. Quoted `$` becomes `\u{1}` and quoted `>`
/// becomes `\u{2}`: neither is live.
fn words(stage: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut single, mut double, mut depth) = (false, false, 0u32);
    let mut started = false;
    let mut escaped = false;
    for c in stage.chars() {
        if escaped {
            cur.push(if c == '$' { '\u{1}' } else { c });
            escaped = false;
            continue;
        }
        match c {
            '\\' if !single => escaped = true,
            '$' if single => cur.push('\u{1}'),
            '>' if single || double => cur.push('\u{2}'),
            '\'' if !double && depth == 0 => {
                single = !single;
                started = true;
            }
            '"' if !single && depth == 0 => {
                double = !double;
                started = true;
            }
            '(' if !single => {
                depth += 1;
                cur.push(c);
            }
            ')' if !single && depth > 0 => {
                depth -= 1;
                cur.push(c);
            }
            c if c.is_whitespace() && !single && !double && depth == 0 => {
                if started || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                started = false;
            }
            _ => cur.push(c),
        }
    }
    if started || !cur.is_empty() {
        out.push(cur);
    }
    out
}
