// Linter for HAproxy haproxy.cfg.
//
// Sectioned config: section keywords at column 0, option lines indented.
// We do structural checks only; for full validation use `haproxy -c -f`.

use crate::diag::{is_valid_ipv4, is_valid_ipv6, Diagnostic, Severity};

const SECTIONS: &[&str] = &[
    "global",
    "defaults",
    "frontend",
    "backend",
    "listen",
    "peers",
    "resolvers",
    "cache",
    "program",
    "userlist",
    "ring",
    "http-errors",
    "mailers",
    "fcgi-app",
];
const MODES: &[&str] = &["http", "tcp", "health"];

#[derive(Copy, Clone, PartialEq, Eq)]
enum Section {
    Global,
    Defaults,
    Frontend,
    Backend,
    Listen,
    Other,
    None,
}

pub fn lint(file: &str, src: &str) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let mut section = Section::None;
    let mut defined_backends: std::collections::HashMap<String, usize> = Default::default();
    let mut backend_refs: Vec<(usize, String)> = Vec::new();
    // Track frontends to flag those with no use_backend/default_backend
    let mut frontends: Vec<(usize, String, bool)> = Vec::new(); // (line, name, has_route)
    let mut current_frontend: Option<usize> = None; // index into `frontends`
                                                    // ACL definitions and references. Scope is per-section in HAproxy.
    let mut defined_acls: std::collections::HashSet<String> = Default::default();
    let mut acl_refs: Vec<(usize, String)> = Vec::new();

    for (i, raw) in src.lines().enumerate() {
        let lno = i + 1;
        let line = raw.trim_end();
        if line.is_empty() {
            continue;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }

        let starts_at_col0 = !line.starts_with(|c: char| c.is_whitespace());
        let head = trimmed.split_whitespace().next().unwrap_or("");

        if starts_at_col0 && SECTIONS.contains(&head) {
            section = match head {
                "global" => Section::Global,
                "defaults" => Section::Defaults,
                "frontend" => Section::Frontend,
                "backend" => Section::Backend,
                "listen" => Section::Listen,
                _ => Section::Other,
            };
            // Record backend/listen name so we can satisfy default_backend / use_backend.
            if matches!(section, Section::Backend | Section::Listen) {
                if let Some(name) = trimmed.split_whitespace().nth(1) {
                    defined_backends.insert(name.to_string(), lno);
                }
            }
            // Track frontends to flag dead-ends.
            current_frontend = if matches!(section, Section::Frontend) {
                let name = trimmed.split_whitespace().nth(1).unwrap_or("").to_string();
                frontends.push((lno, name, false));
                Some(frontends.len() - 1)
            } else {
                None
            };
            continue;
        }

        // Unknown column-0 keyword
        if starts_at_col0 && !SECTIONS.contains(&head) {
            diags.push(Diagnostic::new(
                file,
                lno,
                1,
                Severity::Warning,
                "HAP010",
                format!("unknown section keyword `{}`", head),
            ));
            section = Section::None;
            continue;
        }

        // Option line inside a section
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        let Some(key) = parts.first() else { continue };
        // ACL refs can appear after `if|unless` on many directives — collect uniformly.
        collect_acl_refs(&parts, lno, &mut acl_refs);
        match *key {
            "mode" => {
                let v = parts.get(1).copied().unwrap_or("");
                if !MODES.contains(&v) {
                    diags.push(Diagnostic::new(
                        file,
                        lno,
                        1,
                        Severity::Error,
                        "HAP020",
                        format!("invalid `mode {}` (expected http|tcp|health)", v),
                    ));
                }
            }
            "bind" => {
                let v = parts.get(1).copied().unwrap_or("");
                check_bind(file, lno, v, &mut diags);
            }
            "server" => {
                // `server NAME host:port [options]`
                let addr = parts.get(2).copied().unwrap_or("");
                if !addr.is_empty() {
                    check_host_port(file, lno, addr, "server", &mut diags);
                }
            }
            "timeout" => {
                // `timeout NAME VALUE` — value like 5s, 50000ms, 1m
                if let Some(v) = parts.get(2) {
                    if !is_valid_haproxy_duration(v) {
                        diags.push(Diagnostic::new(
                            file,
                            lno,
                            1,
                            Severity::Warning,
                            "HAP030",
                            format!(
                                "`timeout {}` value `{}` doesn't look like a duration",
                                parts.get(1).unwrap_or(&""),
                                v
                            ),
                        ));
                    }
                }
            }
            "default_backend" => {
                if let Some(name) = parts.get(1) {
                    backend_refs.push((lno, (*name).to_string()));
                }
                if let Some(idx) = current_frontend {
                    frontends[idx].2 = true;
                }
            }
            "use_backend" => {
                // `use_backend NAME [if|unless ACL...]`
                if let Some(name) = parts.get(1) {
                    backend_refs.push((lno, (*name).to_string()));
                }
                if let Some(idx) = current_frontend {
                    frontends[idx].2 = true;
                }
            }
            // Frontends that terminate requests themselves don't need a backend:
            // stats pages, monitor URIs, immediate return/deny rules.
            "stats" | "monitor-uri" | "monitor-net" => {
                if let Some(idx) = current_frontend {
                    frontends[idx].2 = true;
                }
            }
            "http-request" | "tcp-request" => {
                // `http-request return ...`, `http-request deny ...`, `http-request redirect ...`
                if let Some(verb) = parts.get(1) {
                    if matches!(*verb, "return" | "deny" | "redirect" | "tarpit" | "reject") {
                        if let Some(idx) = current_frontend {
                            frontends[idx].2 = true;
                        }
                    }
                }
            }
            "acl" => {
                if let Some(name) = parts.get(1) {
                    defined_acls.insert((*name).to_string());
                }
            }
            _ => {}
        }

        let _ = section;
    }

    for (lno, name) in &backend_refs {
        // Dynamic expressions like `%[path,map_beg(...)]` resolve at runtime — skip.
        if name.starts_with('%') {
            continue;
        }
        if !defined_backends.contains_key(name) {
            diags.push(Diagnostic::new(
                file,
                *lno,
                1,
                Severity::Error,
                "HAP050",
                format!(
                    "`{}` references backend `{}` which is not defined in this file",
                    "use_backend/default_backend", name
                ),
            ));
        }
    }
    // HAproxy built-in ACLs (subset; HAproxy docs §7.4 has the full list).
    const BUILTIN_ACLS: &[&str] = &[
        "TRUE",
        "FALSE",
        "HTTP",
        "HTTP_1.0",
        "HTTP_1.1",
        "HTTP_CONTENT",
        "HTTP_URL_ABS",
        "HTTP_URL_SLASH",
        "HTTP_URL_STAR",
        "LOCALHOST",
        "METH_CONNECT",
        "METH_DELETE",
        "METH_GET",
        "METH_HEAD",
        "METH_OPTIONS",
        "METH_POST",
        "METH_PUT",
        "METH_TRACE",
        "RDP_COOKIE",
        "REQ_CONTENT",
        "WAIT_END",
    ];
    for (lno, name) in &acl_refs {
        if defined_acls.contains(name) || BUILTIN_ACLS.contains(&name.as_str()) {
            continue;
        }
        diags.push(Diagnostic::new(
            file,
            *lno,
            1,
            Severity::Warning,
            "HAP070",
            format!(
                "`{}` referenced via if/unless but not defined as an `acl` in this file",
                name
            ),
        ));
    }

    for (lno, name, has_route) in &frontends {
        if !*has_route {
            diags.push(Diagnostic::new(
                file,
                *lno,
                1,
                Severity::Warning,
                "HAP060",
                format!(
                    "frontend `{}` has no `default_backend` or `use_backend` (traffic dead-ends)",
                    name
                ),
            ));
        }
    }
    diags
}

fn collect_acl_refs(parts: &[&str], lno: usize, out: &mut Vec<(usize, String)>) {
    // Find `if` or `unless` and treat following identifiers (until end / operator) as ACL names.
    // `if ACL1 ACL2` = AND, `if ACL1 || ACL2` = OR, `unless ACL` = negate. `!ACL` = negate.
    let mut i = 0;
    while i < parts.len() {
        if parts[i] == "if" || parts[i] == "unless" {
            for tok in &parts[i + 1..] {
                let t = tok.trim_start_matches('!');
                if t == "||" || t == "&&" || t == "or" || t == "and" || t.is_empty() {
                    continue;
                }
                // Stop at the next keyword that wouldn't be an ACL name.
                if t.starts_with('{') {
                    break;
                }
                out.push((lno, t.to_string()));
            }
            break;
        }
        i += 1;
    }
}

fn check_bind(file: &str, lno: usize, v: &str, diags: &mut Vec<Diagnostic>) {
    if v.is_empty() {
        return;
    }
    // `*:80`, `0.0.0.0:80`, `[::]:443`, `/run/haproxy.sock`, `A:80,B:80,...`
    if v.starts_with('/') {
        return;
    } // unix socket
    for piece in split_bind_list(v) {
        let p = piece.trim();
        if p.is_empty() || p.starts_with('/') {
            continue;
        }
        check_host_port(file, lno, p, "bind", diags);
    }
}

fn split_bind_list(v: &str) -> Vec<&str> {
    // Split on `,` but only when not inside `[...]` (IPv6 brackets).
    let mut out = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    for (i, c) in v.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth = (depth - 1).max(0),
            ',' if depth == 0 => {
                out.push(&v[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&v[start..]);
    out
}

fn check_host_port(file: &str, lno: usize, v: &str, key: &str, diags: &mut Vec<Diagnostic>) {
    let (host, port) = if let Some(rest) = v.strip_prefix('[') {
        match rest.split_once("]:") {
            Some((h, p)) => (h.to_string(), p.to_string()),
            None => {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    1,
                    Severity::Error,
                    "HAP040",
                    format!("malformed bracketed IPv6 in `{} {}`", key, v),
                ));
                return;
            }
        }
    } else {
        match v.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.to_string()),
            None => {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    1,
                    Severity::Error,
                    "HAP041",
                    format!("`{} {}` missing `:port`", key, v),
                ));
                return;
            }
        }
    };
    // port may be a single port, range a-b, or `+offset`
    let first_port = port.split([',', '-', '+']).next().unwrap_or("");
    match first_port.parse::<u16>() {
        Ok(0) | Err(_) => diags.push(Diagnostic::new(
            file,
            lno,
            1,
            Severity::Error,
            "HAP042",
            format!("invalid port `{}` in `{} {}`", port, key, v),
        )),
        Ok(_) => {}
    }
    if host != "*" && !host.is_empty() && !is_valid_ipv4(&host) && !is_valid_ipv6(&host) {
        let looks_hostname = host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
        if !looks_hostname {
            diags.push(Diagnostic::new(
                file,
                lno,
                1,
                Severity::Error,
                "HAP043",
                format!("invalid host `{}` in `{} {}`", host, key, v),
            ));
        }
    }
}

fn is_valid_haproxy_duration(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let suffix_len = if s.ends_with("ms") {
        2
    } else if s.ends_with(['s', 'm', 'h', 'd']) {
        1
    } else {
        0
    };
    let num = &s[..s.len() - suffix_len];
    !num.is_empty() && num.chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::lint;
    use crate::diag::tests::{assert_clean, assert_emits, assert_silent};

    #[test]
    fn hap010_unknown_section() {
        assert_emits(&lint("f", "bogus_section\n    foo bar\n"), "HAP010");
        assert_silent(&lint("f", "global\n    daemon\n"), "HAP010");
    }

    #[test]
    fn hap020_invalid_mode() {
        let bad = "defaults\n    mode bogus\n";
        assert_emits(&lint("f", bad), "HAP020");
        let ok = "defaults\n    mode http\n";
        assert_silent(&lint("f", ok), "HAP020");
    }

    #[test]
    fn hap042_invalid_port() {
        let bad = "frontend f\n    bind *:99999\n";
        assert_emits(&lint("f", bad), "HAP042");
        let ok = "frontend f\n    bind *:80\n";
        assert_silent(&lint("f", ok), "HAP042");
    }

    #[test]
    fn hap041_bind_missing_port() {
        let bad = "frontend f\n    bind 0.0.0.0\n";
        assert_emits(&lint("f", bad), "HAP041");
        let ok = "frontend f\n    bind 0.0.0.0:80\n";
        assert_silent(&lint("f", ok), "HAP041");
    }

    #[test]
    fn hap050_default_backend_undefined() {
        let bad = "frontend f\n    bind *:80\n    default_backend missing\n";
        assert_emits(&lint("f", bad), "HAP050");
        let ok = "frontend f\n    bind *:80\n    default_backend b\nbackend b\n    server s1 192.168.1.1:80\n";
        assert_silent(&lint("f", ok), "HAP050");
    }

    #[test]
    fn hap050_use_backend_undefined() {
        let bad = "frontend f\n    bind *:80\n    acl is_api hdr(host) -i api.example.com\n    use_backend api_be if is_api\n";
        assert_emits(&lint("f", bad), "HAP050");
        let ok = "frontend f\n    bind *:80\n    acl is_api hdr(host) -i api.example.com\n    use_backend api_be if is_api\nbackend api_be\n    server s1 1.2.3.4:80\n";
        assert_silent(&lint("f", ok), "HAP050");
    }

    #[test]
    fn hap050_dynamic_backend_expression_not_flagged() {
        // HAproxy `use_backend %[path,map(...)]` resolves at runtime via maps.
        let ok = "frontend f\n    bind *:80\n    use_backend %[path,map_beg(/opt/haproxy/maps/svc.map)]\n";
        assert_silent(&lint("f", ok), "HAP050");
    }

    #[test]
    fn hap060_frontend_no_backend_route() {
        let bad = "frontend dead\n    bind *:80\n";
        assert_emits(&lint("f", bad), "HAP060");
        let ok = "frontend f\n    bind *:80\n    default_backend b\nbackend b\n    server s1 1.2.3.4:80\n";
        assert_silent(&lint("f", ok), "HAP060");
    }

    #[test]
    fn hap070_acl_referenced_but_undefined() {
        let bad = "frontend f\n    bind *:80\n    use_backend api_be if MISSING_ACL\nbackend api_be\n    server s1 1.2.3.4:80\n";
        assert_emits(&lint("f", bad), "HAP070");
        let ok = "frontend f\n    bind *:80\n    acl is_api hdr(host) -i api.example.com\n    use_backend api_be if is_api\nbackend api_be\n    server s1 1.2.3.4:80\n";
        assert_silent(&lint("f", ok), "HAP070");
    }

    #[test]
    fn hap070_builtin_acls_not_flagged() {
        // `if TRUE`, `if METH_GET` etc. are HAproxy built-in ACLs.
        let ok = "frontend f\n    bind *:80\n    redirect prefix https://example.com if TRUE\n    http-request deny if METH_TRACE\n";
        assert_silent(&lint("f", ok), "HAP070");
    }

    #[test]
    fn hap060_stats_frontend_not_flagged() {
        // `stats enable` makes the frontend serve responses itself.
        let ok = "frontend stats\n    bind *:8404\n    stats enable\n    stats uri /stats\n";
        assert_silent(&lint("f", ok), "HAP060");
    }

    #[test]
    fn hap060_http_request_return_not_flagged() {
        let ok = "frontend f\n    bind *:80\n    http-request return status 200 content-type text/plain string \"ok\"\n";
        assert_silent(&lint("f", ok), "HAP060");
    }

    #[test]
    fn comma_separated_bind_list_not_flagged() {
        // HAproxy allows `bind A:80,B:80,[v6]:80,...` as one directive.
        let ok = "frontend f\n    bind 1.2.3.4:80,5.6.7.8:80,[2001:db8::1]:80\n";
        assert_silent(&lint("f", ok), "HAP043");
        assert_silent(&lint("f", ok), "HAP042");
    }

    #[test]
    fn clean_minimal() {
        let src = "global\n    daemon\ndefaults\n    mode http\n    timeout connect 5s\nfrontend f\n    bind *:80\n    default_backend b\nbackend b\n    server s1 192.168.1.1:80 check\n";
        assert_clean(&lint("f", src));
    }
}
