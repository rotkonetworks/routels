use crate::diag::{Diagnostic, Severity};

const ROOT_PATHS: &[&str] = &[
    "interface",
    "ip",
    "ipv6",
    "routing",
    "system",
    "user",
    "tool",
    "queue",
    "ppp",
    "ports",
    "snmp",
    "certificate",
    "file",
    "log",
    "radius",
    "container",
    "mpls",
    "lcd",
    "iot",
    "disk",
    "partitions",
    "console",
    "special-login",
];

pub fn lint(file: &str, src: &str) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let mut current_path: Option<String> = None;
    // Continuation handling: trailing `\` joins next line.
    let mut joined: String = String::new();
    let mut join_start: usize = 0;

    for (i, raw) in src.lines().enumerate() {
        let lno = i + 1;
        let line = raw.trim_end();
        let stripped = line.trim_start();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }

        if let Some(body) = stripped.strip_suffix('\\') {
            if joined.is_empty() {
                join_start = lno;
            }
            joined.push_str(body.trim_end());
            joined.push(' ');
            continue;
        }

        let (effective_line, effective_lno) = if !joined.is_empty() {
            joined.push_str(stripped);
            let s = std::mem::take(&mut joined);
            (s, join_start)
        } else {
            (stripped.to_string(), lno)
        };

        analyze(
            file,
            effective_lno,
            &effective_line,
            &mut current_path,
            &mut diags,
        );
    }
    diags
}

fn analyze(
    file: &str,
    lno: usize,
    line: &str,
    current_path: &mut Option<String>,
    diags: &mut Vec<Diagnostic>,
) {
    if !brackets_balanced(line) {
        diags.push(Diagnostic::new(
            file,
            lno,
            1,
            Severity::Error,
            "ROS010",
            "unbalanced `[`/`]`, `{`/`}`, or quotes",
        ));
    }

    if let Some(after_slash) = line.strip_prefix('/') {
        // Path-set line. Might be just `/ip route` or `/ip route add ...`.
        let (path_part, cmd_part) = split_path_and_command(after_slash);
        let root = path_part.split_whitespace().next().unwrap_or("");
        if !ROOT_PATHS.contains(&root) {
            diags.push(Diagnostic::new(
                file,
                lno,
                2,
                Severity::Warning,
                "ROS011",
                format!("unknown root path `/{}`", root),
            ));
        }
        *current_path = Some(path_part.to_string());
        if let Some(cmd) = cmd_part {
            check_command(file, lno, cmd, current_path.as_deref().unwrap_or(""), diags);
        }
        return;
    }

    // Implicit command in current path
    check_command(
        file,
        lno,
        line,
        current_path.as_deref().unwrap_or(""),
        diags,
    );
}

fn split_path_and_command(s: &str) -> (&str, Option<&str>) {
    // Path tokens are alphabetic / hyphenated; command starts with a known verb.
    let verbs = [
        "add", "set", "remove", "print", "export", "import", "find", "comment", "enable",
        "disable", "move",
    ];
    for (idx, tok) in s.match_indices(' ') {
        let next = s[idx + 1..].split_whitespace().next().unwrap_or("");
        if verbs.contains(&next) {
            return (s[..idx].trim_end(), Some(s[idx + 1..].trim_start()));
        }
        let _ = tok;
    }
    (s.trim_end(), None)
}

fn check_command(file: &str, lno: usize, cmd: &str, path: &str, diags: &mut Vec<Diagnostic>) {
    let verb = cmd.split_whitespace().next().unwrap_or("");
    let known = [
        "add", "set", "remove", "print", "export", "import", "find", "comment", "enable",
        "disable", "move",
    ];
    if !verb.is_empty() && !known.contains(&verb) {
        diags.push(Diagnostic::new(
            file,
            lno,
            1,
            Severity::Warning,
            "ROS020",
            format!("unknown verb `{}`", verb),
        ));
    }
    // Check obvious IP-bearing keys.
    for kv in iter_kv(cmd) {
        if kv.key == "mac-address" {
            let v = kv.value.trim_matches('"');
            if !is_valid_mac(v) {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    1,
                    Severity::Error,
                    "ROS040",
                    format!(
                        "invalid MAC address `{}` in `{}` (path /{})",
                        v, kv.key, path
                    ),
                ));
            }
            continue;
        }
        if matches!(kv.key, "dst-port" | "src-port" | "port") {
            let v = kv.value.trim_matches('"');
            for piece in v.split(',') {
                let p = piece.trim();
                if p.is_empty() {
                    continue;
                }
                if !is_valid_port_spec(p) {
                    diags.push(Diagnostic::new(
                        file,
                        lno,
                        1,
                        Severity::Error,
                        "ROS041",
                        format!("invalid port spec `{}` in `{}` (path /{})", p, kv.key, path),
                    ));
                }
            }
            continue;
        }
        if matches!(
            kv.key,
            "address" | "network" | "gateway" | "dst-address" | "src-address" | "to-addresses"
        ) {
            // Comma-separated lists are valid here (e.g. `/ip service set ... address=A,B,C`).
            for raw in kv.value.trim_matches('"').split(',') {
                let raw = raw.trim();
                if raw.is_empty() {
                    continue;
                }
                // Take the first half of a range like `10.0.0.1-10.0.0.5`.
                let v = raw.split('-').next().unwrap_or(raw);
                // Strip RouterOS scope/zone suffix: `fe80::1%ether1`, `172.16.10.2%BKK50`.
                let v = v.split('%').next().unwrap_or(v);
                let (addr, prefix) = match v.split_once('/') {
                    Some((a, p)) => (a, Some(p)),
                    None => (v, None),
                };
                let looks_v4 = addr.chars().all(|c| c.is_ascii_digit() || c == '.')
                    && addr.matches('.').count() == 3;
                let looks_v6 = addr.contains(':');
                if !looks_v4 && !looks_v6 {
                    // Hostname or other non-IP value (e.g. NTP `pool.ntp.org`) — skip.
                    continue;
                }
                let ok = if looks_v4 {
                    crate::diag::is_valid_ipv4(addr)
                } else {
                    crate::diag::is_valid_ipv6(addr)
                };
                let prefix_ok = prefix
                    .map(|p| {
                        let max = if looks_v6 { 128 } else { 32 };
                        p.parse::<u8>().map(|n| n <= max).unwrap_or(false)
                    })
                    .unwrap_or(true);
                if !ok || !prefix_ok {
                    let code = if prefix.is_some() { "ROS030" } else { "ROS031" };
                    let label = if prefix.is_some() {
                        "prefix"
                    } else {
                        "address"
                    };
                    diags.push(Diagnostic::new(
                        file,
                        lno,
                        1,
                        Severity::Error,
                        code,
                        format!(
                            "invalid {} `{}` in `{}` (path /{})",
                            label, raw, kv.key, path
                        ),
                    ));
                }
            }
        }
    }
}

struct Kv<'a> {
    key: &'a str,
    value: &'a str,
}

fn iter_kv(s: &str) -> Vec<Kv<'_>> {
    // Walk tokens respecting quotes / brackets; pull `key=value` pairs.
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let start = i;
        let mut depth_bracket = 0;
        let mut quote: Option<u8> = None;
        while i < bytes.len() {
            let c = bytes[i];
            match quote {
                Some(q) if c == q => quote = None,
                Some(_) => {}
                None => match c {
                    b'"' => quote = Some(b'"'),
                    b'[' => depth_bracket += 1,
                    b']' if depth_bracket > 0 => depth_bracket -= 1,
                    c if c.is_ascii_whitespace() && depth_bracket == 0 => break,
                    _ => {}
                },
            }
            i += 1;
        }
        let tok = &s[start..i];
        if let Some(eq) = tok.find('=') {
            let key = &tok[..eq];
            let value = &tok[eq + 1..];
            if !key.is_empty() {
                out.push(Kv { key, value });
            }
        }
    }
    out
}

fn is_valid_mac(s: &str) -> bool {
    // EUI-48: six hex pairs separated by `:` or `-`.
    let sep = if s.contains(':') { ':' } else { '-' };
    let parts: Vec<&str> = s.split(sep).collect();
    if parts.len() != 6 {
        return false;
    }
    parts
        .iter()
        .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn is_valid_port_spec(s: &str) -> bool {
    // Single `N` or range `A-B`. Each must parse as u16 (0 is allowed —
    // firewall rules often match port 0 as a security filter).
    let parse = |x: &str| x.parse::<u16>().ok();
    match s.split_once('-') {
        Some((a, b)) => parse(a).is_some() && parse(b).is_some(),
        None => parse(s).is_some(),
    }
}

fn brackets_balanced(s: &str) -> bool {
    let mut sq = 0i32;
    let mut cu = 0i32;
    let mut paren = 0i32;
    let mut dq = false;
    let mut prev = '\0';
    for c in s.chars() {
        if c == '"' && prev != '\\' {
            dq = !dq;
            prev = c;
            continue;
        }
        if dq {
            prev = c;
            continue;
        }
        match c {
            '[' => sq += 1,
            ']' => sq -= 1,
            '{' => cu += 1,
            '}' => cu -= 1,
            '(' => paren += 1,
            ')' => paren -= 1,
            _ => {}
        }
        if sq < 0 || cu < 0 || paren < 0 {
            return false;
        }
        prev = c;
    }
    !dq && sq == 0 && cu == 0 && paren == 0
}

#[cfg(test)]
mod tests {
    use super::lint;
    use crate::diag::tests::{assert_clean, assert_emits, assert_silent};

    #[test]
    fn ros011_unknown_root_path() {
        assert_emits(&lint("f", "/bogus-root\nadd name=x\n"), "ROS011");
        assert_silent(
            &lint("f", "/ip address\nadd address=10.0.0.1/24 interface=lan\n"),
            "ROS011",
        );
    }

    #[test]
    fn ros030_invalid_prefix() {
        let bad = "/ip address\nadd address=10.0.0.999/24 interface=lan\n";
        assert_emits(&lint("f", bad), "ROS030");
        let ok = "/ip address\nadd address=10.0.0.1/24 interface=lan\n";
        assert_silent(&lint("f", ok), "ROS030");
    }

    #[test]
    fn comma_separated_address_list_not_flagged() {
        // Real RouterOS: `/ip service set winbox address=10.0.0.0/8,192.168.0.0/16`
        let ok = "/ip service\nset winbox address=10.0.0.0/8,192.168.0.0/16\n";
        assert_silent(&lint("f", ok), "ROS030");
        assert_silent(&lint("f", ok), "ROS031");
    }

    #[test]
    fn ipv6_zone_id_not_flagged() {
        // Real RouterOS: `gateway=fe80::1%ether1` for link-local next-hops
        let ok = "/ipv6 route\nadd dst-address=::/0 gateway=fe80::1%ether1\n";
        assert_silent(&lint("f", ok), "ROS031");
    }

    #[test]
    fn ntp_hostname_not_flagged() {
        // NTP servers can be hostnames, not IPs
        let ok = "/system ntp client servers\nadd address=0.th.pool.ntp.org\n";
        assert_silent(&lint("f", ok), "ROS031");
    }

    #[test]
    fn ros040_invalid_mac() {
        let bad = "/interface ethernet\nset ether1 mac-address=NOT-A-MAC\n";
        assert_emits(&lint("f", bad), "ROS040");
        let ok = "/interface ethernet\nset ether1 mac-address=00:11:22:33:44:55\n";
        assert_silent(&lint("f", ok), "ROS040");
    }

    #[test]
    fn ros041_invalid_port_spec() {
        let bad = "/ip firewall filter\nadd chain=input dst-port=999999 action=accept\n";
        assert_emits(&lint("f", bad), "ROS041");
        let ok_single = "/ip firewall filter\nadd chain=input dst-port=80 action=accept\n";
        assert_silent(&lint("f", ok_single), "ROS041");
        let ok_range = "/ip firewall filter\nadd chain=input dst-port=80-443 action=accept\n";
        assert_silent(&lint("f", ok_range), "ROS041");
        let ok_list = "/ip firewall filter\nadd chain=input dst-port=80,443,8080 action=accept\n";
        assert_silent(&lint("f", ok_list), "ROS041");
    }

    #[test]
    fn port_zero_allowed_in_firewall() {
        // `port=0` is a valid filter match (security: drop bad traffic).
        let ok = "/ip firewall raw\nadd chain=prerouting port=0 protocol=udp action=drop\n";
        assert_silent(&lint("f", ok), "ROS041");
    }

    #[test]
    fn clean_minimal_export() {
        let src = "# /export\n/interface bridge\nadd name=br-lan\n/ip address\nadd address=10.0.0.1/24 interface=br-lan\n";
        assert_clean(&lint("f", src));
    }
}
