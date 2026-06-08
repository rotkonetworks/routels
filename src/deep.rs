// Deep-validation: shell out to the platform's own parser/validator.
// Returns Vec<Diagnostic> with source=tool name in the `code` slot.

use crate::diag::{Diagnostic, Severity};
use std::path::Path;
use std::process::Command;

#[derive(Copy, Clone)]
pub enum Platform {
    Eos,
    Frr,
    Vyos,
    Mikrotik,
    Bird,
    Nft,
    Debian,
    Wireguard,
    Haproxy,
    Sysctl,
}

pub fn check(platform: Platform, path: &Path) -> Vec<Diagnostic> {
    let file = path.display().to_string();
    if file == "-" {
        return vec![Diagnostic::new(
            file,
            0,
            1,
            Severity::Hint,
            "DEEP000",
            "--deep requires a file path (stdin not supported)",
        )];
    }
    match platform {
        Platform::Frr => check_frr(&file, path),
        Platform::Nft => check_nft(&file, path),
        Platform::Bird => check_bird(&file, path),
        Platform::Haproxy => check_haproxy(&file, path),
        Platform::Wireguard => check_wireguard(&file, path),
        Platform::Eos => container_required(&file, "cEOS"),
        Platform::Vyos => container_required(&file, "VyOS"),
        Platform::Mikrotik => container_required(&file, "RouterOS"),
        Platform::Debian => not_implemented(&file, "Debian /etc/network/interfaces"),
        Platform::Sysctl => not_implemented(&file, "sysctl"),
    }
}

fn not_implemented(file: &str, name: &str) -> Vec<Diagnostic> {
    vec![Diagnostic::new(
        file.to_string(),
        0,
        1,
        Severity::Hint,
        "DEEP901",
        format!(
            "no offline validator known for {} — structural lint only",
            name
        ),
    )]
}

fn check_haproxy(file: &str, path: &Path) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    match run("haproxy", &["-c", "-f", &path.display().to_string()]) {
        Ok((stdout, stderr, code)) => {
            if code != 0 {
                for line in stderr.lines().chain(stdout.lines()) {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    // Examples: "[ALERT] (123) : config : parsing [/file:7] : 'bind' ..."
                    let lno = line
                        .split(':')
                        .filter_map(|t| t.trim_end_matches(']').parse::<usize>().ok())
                        .find(|n| *n > 0 && *n < 1_000_000)
                        .unwrap_or(0);
                    diags.push(Diagnostic::new(
                        file.to_string(),
                        lno,
                        1,
                        Severity::Error,
                        "DEEP-HAP",
                        line.to_string(),
                    ));
                }
            }
        }
        Err(e) => diags.push(Diagnostic::new(
            file.to_string(),
            0,
            1,
            Severity::Hint,
            "DEEP404",
            format!("skipping deep check: {}", e),
        )),
    }
    diags
}

fn check_wireguard(file: &str, path: &Path) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    // `wg-quick strip <file>` parses without applying; non-zero on parse error.
    match run("wg-quick", &["strip", &path.display().to_string()]) {
        Ok((_stdout, stderr, code)) => {
            if code != 0 {
                for line in stderr.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    diags.push(Diagnostic::new(
                        file.to_string(),
                        0,
                        1,
                        Severity::Error,
                        "DEEP-WG",
                        line.to_string(),
                    ));
                }
            }
        }
        Err(e) => diags.push(Diagnostic::new(
            file.to_string(),
            0,
            1,
            Severity::Hint,
            "DEEP404",
            format!("skipping deep check: {}", e),
        )),
    }
    diags
}

fn container_required(file: &str, name: &str) -> Vec<Diagnostic> {
    vec![Diagnostic::new(
        file,
        0,
        1,
        Severity::Hint,
        "DEEP900",
        format!(
            "--deep for {} requires a running container (not implemented yet)",
            name
        ),
    )]
}

fn run(cmd: &str, args: &[&str]) -> Result<(String, String, i32), String> {
    let output = Command::new(cmd).args(args).output().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!("`{}` not found on PATH", cmd)
        } else {
            format!("failed to spawn `{}`: {}", cmd, e)
        }
    })?;
    Ok((
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code().unwrap_or(-1),
    ))
}

fn check_frr(file: &str, path: &Path) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    // vtysh -C -f <file> ; output to stderr; exit 0 == OK.
    match run("vtysh", &["-C", "-f", &path.display().to_string()]) {
        Ok((stdout, stderr, code)) => {
            if code != 0 || !stderr.is_empty() {
                for line in stderr.lines().chain(stdout.lines()) {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    // Examples:
                    //   "line 24: % Unknown command..."
                    //   "Error occured during reading below line:"
                    let (lno, msg) =
                        parse_line_prefix(line, "line ").unwrap_or((0, line.to_string()));
                    diags.push(Diagnostic::new(
                        file.to_string(),
                        lno,
                        1,
                        Severity::Error,
                        "DEEP-FRR",
                        msg,
                    ));
                }
            }
        }
        Err(e) => diags.push(Diagnostic::new(
            file.to_string(),
            0,
            1,
            Severity::Hint,
            "DEEP404",
            format!("skipping deep check: {}", e),
        )),
    }
    diags
}

fn check_nft(file: &str, path: &Path) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    // Auto-route to iptables-restore if the file looks like iptables-save.
    let looks_iptables = std::fs::read_to_string(path)
        .map(|s| {
            s.lines().take(50).any(|l| {
                let t = l.trim_start();
                t.starts_with("*filter")
                    || t.starts_with("*nat")
                    || t.starts_with("*mangle")
                    || t.starts_with("*raw")
            })
        })
        .unwrap_or(false);

    if looks_iptables {
        return check_iptables(file, path);
    }

    match run("nft", &["-c", "-f", &path.display().to_string()]) {
        Ok((stdout, stderr, code)) => {
            let combined = format!("{stderr}\n{stdout}");
            if combined.contains("Operation not permitted")
                || combined.contains("must be run as root")
            {
                diags.push(Diagnostic::new(
                    file.to_string(),
                    0,
                    1,
                    Severity::Hint,
                    "DEEP403",
                    "nft -c needs CAP_NET_ADMIN; run with sudo or grant the capability to routels",
                ));
            } else if code != 0 || !stderr.is_empty() {
                for line in stderr.lines().chain(stdout.lines()) {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    diags.push(parse_nft_line(file, line));
                }
            }
        }
        Err(e) => diags.push(Diagnostic::new(
            file.to_string(),
            0,
            1,
            Severity::Hint,
            "DEEP404",
            format!("skipping deep check: {}", e),
        )),
    }
    diags
}

fn check_iptables(file: &str, path: &Path) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    match run(
        "iptables-restore",
        &["--test", "-w", "1", &path.display().to_string()],
    ) {
        Ok((stdout, stderr, code)) => {
            if code != 0 {
                let body = if stderr.is_empty() { stdout } else { stderr };
                for line in body.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    // Example: "iptables-restore: line 7 failed"
                    let lno = line
                        .split("line ")
                        .nth(1)
                        .and_then(|s| s.split_whitespace().next())
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(0);
                    diags.push(Diagnostic::new(
                        file.to_string(),
                        lno,
                        1,
                        Severity::Error,
                        "DEEP-IPT",
                        line.to_string(),
                    ));
                }
            }
        }
        Err(e) => diags.push(Diagnostic::new(
            file.to_string(),
            0,
            1,
            Severity::Hint,
            "DEEP404",
            format!("skipping deep check: {}", e),
        )),
    }
    diags
}

fn check_bird(file: &str, path: &Path) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    // bird -p -c <file> : parse-only, exit 0 on success
    match run("bird", &["-p", "-c", &path.display().to_string()]) {
        Ok((stdout, stderr, code)) => {
            if code != 0 || !stderr.is_empty() {
                for line in stderr.lines().chain(stdout.lines()) {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    // Examples:
                    //   "bird: /tmp/x.conf:5:1 syntax error"
                    //   "Error in configuration file /tmp/x.conf at line 5: …"
                    let lno = line
                        .split([':', ' '])
                        .filter_map(|t| t.parse::<usize>().ok())
                        .find(|n| *n > 0 && *n < 1_000_000)
                        .unwrap_or(0);
                    diags.push(Diagnostic::new(
                        file.to_string(),
                        lno,
                        1,
                        Severity::Error,
                        "DEEP-BIRD",
                        line.to_string(),
                    ));
                }
            }
        }
        Err(e) => diags.push(Diagnostic::new(
            file.to_string(),
            0,
            1,
            Severity::Hint,
            "DEEP404",
            format!("skipping deep check: {}", e),
        )),
    }
    diags
}

fn parse_line_prefix(s: &str, prefix: &str) -> Option<(usize, String)> {
    let idx = s.find(prefix)?;
    let after = &s[idx + prefix.len()..];
    let mut chars = after.char_indices();
    let mut end = 0;
    for (i, c) in chars.by_ref() {
        if c.is_ascii_digit() {
            end = i + 1;
        } else {
            break;
        }
    }
    if end == 0 {
        return None;
    }
    let lno: usize = after[..end].parse().ok()?;
    let msg = after[end..]
        .trim_start_matches(|c: char| c == ':' || c.is_whitespace())
        .to_string();
    Some((lno, msg))
}

fn parse_nft_line(file: &str, line: &str) -> Diagnostic {
    // <path>:<line>:<col>[-<col2>]: <Level>: <message>
    let parts: Vec<&str> = line.splitn(4, ':').collect();
    if parts.len() >= 4 {
        let lno: usize = parts[1].parse().unwrap_or(0);
        let col: usize = parts[2]
            .split('-')
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        let rest = parts[3].trim_start();
        let sev = if rest.starts_with("Error") {
            Severity::Error
        } else if rest.starts_with("Warning") {
            Severity::Warning
        } else {
            Severity::Info
        };
        return Diagnostic::new(
            file.to_string(),
            lno,
            col,
            sev,
            "DEEP-NFT",
            rest.to_string(),
        );
    }
    Diagnostic::new(
        file.to_string(),
        0,
        1,
        Severity::Error,
        "DEEP-NFT",
        line.to_string(),
    )
}
