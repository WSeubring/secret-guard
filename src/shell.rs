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

/// Words before the command itself.
const PREFIXES: &[&str] = &["sudo", "time", "nohup", "command", "exec", "builtin"];

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
        let Some(source) = dump(cmd).or_else(|| echoed_substitution(cmd)) else {
            continue;
        };
        let printed = !redirected(stage) && stages[i + 1..].iter().all(|s| passes_through(command_words(s)) && !redirected(s));
        if printed {
            return Some(source);
        }
    }
    None
}

/// The stage's command and arguments, without `VAR=x`, `sudo` and the like.
fn command_words(stage: &[String]) -> &[String] {
    let skip = stage.iter().take_while(|w| PREFIXES.contains(&w.as_str()) || is_assignment(w)).count();
    &stage[skip..]
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
            let invert = flags().any(|f| f.contains('v'));
            flags().any(|f| f.contains(['c', 'l', 'L', 'q']))
                || cmd.iter().any(|w| matches!(w.as_str(), "--count" | "--quiet" | "--files-with-matches"))
                || invert && cmd[1..].iter().any(|w| !w.starts_with('-') && ["key", "token", "secret", "pass"].iter().any(|k| w.to_lowercase().contains(k)))
        }
        "sed" => {
            cmd.iter().any(|w| w == "-i" || w.starts_with("--in-place") || w.starts_with("-i."))
                || cmd[1..].iter().any(|w| ["***", "redacted", "<x>", "<set>", "...", "=.*"].iter().any(|m| w.to_lowercase().contains(m)))
        }
        "awk" => {
            let joined = cmd.join(" ");
            (joined.contains("-F=") || joined.contains("-F =")) && (joined.contains("print $1") || joined.contains("print \u{1}1"))
        }
        "head" | "tail" => cmd.windows(2).any(|p| p[0] == "-c" && p[1].parse::<u32>().is_ok_and(|n| n <= 8))
            || cmd.iter().any(|w| w.strip_prefix("-c").and_then(|n| n.parse::<u32>().ok()).is_some_and(|n| n <= 8)),
        "cut" => {
            let joined = cmd.join(" ");
            (joined.contains("-f1") || joined.contains("-f 1")) && (joined.contains("-d=") || joined.contains("-d ="))
        }
        "jq" | "yq" => cmd[1..].iter().any(|w| {
            !w.starts_with('-') && !w.contains(".value") && ["keys", "length", "paths", ".metadata", ".kind", "type", ".key", "label"].iter().any(|k| w.contains(k))
        }),
        _ => false,
    }
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
    let w: Vec<&str> = cmd.iter().map(String::as_str).collect();
    let c = base(w.first()?);
    let has = |x: &str| w.contains(&x);
    let label = |s: &str| Some(s.to_string());
    match c {
        "kubectl" | "oc" => {
            let get = w.iter().position(|x| *x == "get")?;
            let kind = w[get + 1..].iter().find(|x| !x.starts_with('-'))?;
            if !(kind.starts_with("secret") || kind.starts_with("secrets")) {
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
            Some(["read", _]) => label("op read"),
            Some(["item", "get"]) if has("--reveal") => label("op item get --reveal"),
            Some(["inject", _]) if !w.iter().any(|x| x.starts_with("-o") || x.starts_with("--out-file")) => label("op inject"),
            _ => None,
        },
        "gh" if w.get(1..3) == Some(&["auth", "token"]) => label("gh auth token"),
        "glab" if w.get(1..3) == Some(&["auth", "status"]) && (has("-t") || has("--show-token")) => label("glab auth status -t"),
        "printenv" if w.len() == 1 || w[1..].iter().any(|v| crate::rules::names_secret(v)) => label("printenv"),
        "env" if w.len() == 1 => label("env"),
        "echo" | "printf" => w[1..].iter().flat_map(|a| variables(a)).find(|v| crate::rules::names_secret(v)).map(|v| format!("{c} ${v}")),
        "vault" if matches!(w.get(1..3), Some(["kv", "get"])) || w.get(1) == Some(&"read") => label("vault read"),
        "aws" if w.get(1..3) == Some(&["secretsmanager", "get-secret-value"])
            || w.get(1) == Some(&"ssm") && has("--with-decryption") =>
        {
            label("aws secret read")
        }
        "gcloud" if w.get(1..4) == Some(&["secrets", "versions", "access"]) => label("gcloud secrets versions access"),
        "az" if w.get(1..4) == Some(&["keyvault", "secret", "show"]) => label("az keyvault secret show"),
        "sops" if (has("-d") || has("--decrypt")) && !has("-i") && !has("--in-place") => label("sops -d"),
        "git" if w.get(1..3) == Some(&["credential", "fill"]) => label("git credential fill"),
        "security" if w.get(1).is_some_and(|s| s.starts_with("find-") && s.ends_with("-password")) && (has("-w") || has("-g")) => {
            label("security find-password")
        }
        _ => None,
    }
}

/// Names in `$NAME` and `${NAME}` that the shell expands, outside `$(...)`; `$PWD` is a directory.
fn variables(arg: &str) -> Vec<&str> {
    let outside = arg.split_once("$(").map_or(arg, |(before, _)| before);
    outside
        .split('$')
        .skip(1)
        .map(|rest| {
            let rest = rest.strip_prefix('{').unwrap_or(rest);
            let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(rest.len());
            &rest[..end]
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
        raw_secret_output(inner.rsplit_once(')').map_or(inner, |(body, _)| body))
    })
}

/// Heredoc bodies are data, not commands.
fn strip_heredocs(command: &str) -> String {
    let mut out = String::new();
    let mut terminator: Option<String> = None;
    for line in command.lines() {
        if let Some(t) = &terminator {
            if line.trim() == t {
                terminator = None;
            }
            continue;
        }
        if let Some((_, rest)) = line.split_once("<<") {
            let word: String = rest.trim_start_matches(['-', '~']).trim_start().trim_start_matches(['\'', '"'])
                .chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            if !word.is_empty() && !rest.starts_with('<') {
                terminator = Some(word);
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    out
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
                let amp_and = *sep == "&" && (s[i..].starts_with("&&") || s[i..].starts_with("&>") || (i > 0 && b[i - 1] == b'>'));
                if !pipe_or && !amp_and {
                    parts.push(std::mem::take(&mut cur));
                    i += sep.len();
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

/// Shell words with quotes removed; `$(...)` stays inside its word.
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
