use crate::diag::{is_valid_ipv4_cidr, is_valid_ipv6_cidr, Diagnostic, Severity};

const ROOT_NODES: &[&str] = &[
    "interfaces",
    "protocols",
    "firewall",
    "system",
    "service",
    "policy",
    "nat",
    "nat66",
    "vpn",
    "qos-policy",
    "traffic-policy",
    "high-availability",
    "pki",
    "container",
    "load-balancing",
    "vrf",
];

pub fn lint(file: &str, src: &str) -> Vec<Diagnostic> {
    if detect_curly(src) {
        lint_curly(file, src)
    } else {
        lint_set(file, src)
    }
}

fn detect_curly(src: &str) -> bool {
    // Curly form has `{` on lines; set form starts every line with a command verb.
    let mut sample = 0;
    for line in src.lines().take(200) {
        let t = line.trim();
        if t.is_empty() || t.starts_with('/') || t.starts_with('#') {
            continue;
        }
        sample += 1;
        if t.ends_with('{') || t == "}" {
            return true;
        }
        if t.starts_with("set ") || t.starts_with("delete ") {
            return false;
        }
        if sample > 20 {
            break;
        }
    }
    false
}

fn lint_set(file: &str, src: &str) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for (i, raw) in src.lines().enumerate() {
        let lno = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if !quotes_balanced(line) {
            diags.push(Diagnostic::new(
                file,
                lno,
                1,
                Severity::Error,
                "VYO010",
                "unbalanced quotes",
            ));
            continue;
        }

        let mut parts = tokenize(line);
        let verb = parts.first().cloned().unwrap_or_default();
        match verb.as_str() {
            "set" | "delete" | "comment" => {
                parts.remove(0);
                if parts.is_empty() {
                    diags.push(Diagnostic::new(
                        file,
                        lno,
                        1,
                        Severity::Error,
                        "VYO011",
                        format!("`{}` with no path", verb),
                    ));
                    continue;
                }
                let root = &parts[0];
                if !ROOT_NODES.contains(&root.as_str()) {
                    diags.push(Diagnostic::new(
                        file,
                        lno,
                        verb.len() + 2,
                        Severity::Warning,
                        "VYO012",
                        format!("unknown root node `{}`", root),
                    ));
                }
                check_ip_leaves(file, lno, &parts, &mut diags);
            }
            "edit" | "top" | "up" | "exit" | "save" | "commit" | "load" | "show" | "discard"
            | "compare" | "run" => {
                // permissive
            }
            _ => {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    1,
                    Severity::Error,
                    "VYO013",
                    format!("unknown verb `{}`", verb),
                ));
            }
        }
    }
    diags
}

fn check_ip_leaves(file: &str, lno: usize, parts: &[String], diags: &mut Vec<Diagnostic>) {
    // common shapes:
    //   set interfaces ethernet ethX address <v4cidr|v6cidr>
    //   set protocols static route <v4cidr> next-hop <v4>
    //   set protocols bgp neighbor <v4> ...
    let iter = parts.iter().enumerate();
    for (i, tok) in iter {
        let is_addr_leaf =
            tok == "address" || tok == "route" || tok == "route6" || tok == "network";
        if is_addr_leaf {
            if let Some(val) = parts.get(i + 1) {
                let v = val.trim_matches('\'').trim_matches('"');
                if v.contains('/') && !is_valid_ipv4_cidr(v) && !is_valid_ipv6_cidr(v) {
                    diags.push(Diagnostic::new(
                        file,
                        lno,
                        1,
                        Severity::Error,
                        "VYO020",
                        format!("invalid prefix `{}`", v),
                    ));
                }
            }
        }
    }
}

fn lint_curly(file: &str, src: &str) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let mut depth: i64 = 0;
    let mut path_stack: Vec<String> = Vec::new();

    for (i, raw) in src.lines().enumerate() {
        let lno = i + 1;
        let line = raw.trim_end();
        let stripped = line.trim_start();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }

        if !quotes_balanced(stripped) {
            diags.push(Diagnostic::new(
                file,
                lno,
                1,
                Severity::Error,
                "VYO030",
                "unbalanced quotes",
            ));
        }

        if stripped == "}" {
            depth -= 1;
            path_stack.pop();
            if depth < 0 {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    1,
                    Severity::Error,
                    "VYO031",
                    "unexpected `}`",
                ));
                depth = 0;
            }
            continue;
        }

        if let Some(head) = stripped.strip_suffix('{').map(str::trim) {
            // opening: `interfaces {` or `ethernet eth0 {`
            depth += 1;
            let first = head.split_whitespace().next().unwrap_or("").to_string();
            if depth == 1 && !first.is_empty() && !ROOT_NODES.contains(&first.as_str()) {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    1,
                    Severity::Warning,
                    "VYO032",
                    format!("unknown root node `{}`", first),
                ));
            }
            path_stack.push(first);
            continue;
        }

        // leaf assignment line: `address 10.0.0.1/24`
        let mut parts = tokenize(stripped);
        if let Some(k) = parts.first().cloned() {
            if (k == "address" || k == "route" || k == "route6" || k == "network")
                && parts.len() >= 2
            {
                let v = parts.remove(1);
                let v = v.trim_matches('\'').trim_matches('"');
                if v.contains('/') && !is_valid_ipv4_cidr(v) && !is_valid_ipv6_cidr(v) {
                    diags.push(Diagnostic::new(
                        file,
                        lno,
                        1,
                        Severity::Error,
                        "VYO033",
                        format!("invalid prefix `{}`", v),
                    ));
                }
            }
        }
    }

    if depth != 0 {
        diags.push(Diagnostic::new(
            file,
            0,
            1,
            Severity::Error,
            "VYO034",
            format!("{} unclosed `{{` block(s)", depth),
        ));
    }
    diags
}

fn quotes_balanced(s: &str) -> bool {
    let mut single = false;
    let mut double = false;
    let mut prev = '\0';
    for c in s.chars() {
        match c {
            '\'' if !double && prev != '\\' => single = !single,
            '"' if !single && prev != '\\' => double = !double,
            _ => {}
        }
        prev = c;
    }
    !single && !double
}

fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for c in s.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => {
                cur.push(c);
                quote = None;
            }
            (Some(_), c) => cur.push(c),
            (None, '\'') | (None, '"') => {
                quote = Some(c);
                cur.push(c);
            }
            (None, ws) if ws.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::lint;
    use crate::diag::tests::{assert_clean, assert_emits, assert_silent};

    #[test]
    fn vyo012_unknown_root_node() {
        assert_emits(&lint("f", "set bogus-root foo\n"), "VYO012");
        assert_silent(
            &lint("f", "set interfaces ethernet eth0 mtu 1500\n"),
            "VYO012",
        );
    }

    #[test]
    fn vyo020_invalid_address_prefix() {
        let bad = "set interfaces ethernet eth0 address '10.0.0.300/24'\n";
        assert_emits(&lint("f", bad), "VYO020");
        let ok = "set interfaces ethernet eth0 address '10.0.0.1/24'\n";
        assert_silent(&lint("f", ok), "VYO020");
    }

    #[test]
    fn vyo034_unclosed_brace() {
        let bad = "interfaces {\n  ethernet eth0 {\n    address 10.0.0.1/24\n  }\n";
        assert_emits(&lint("f", bad), "VYO034");
        let ok = "interfaces {\n  ethernet eth0 {\n    address 10.0.0.1/24\n  }\n}\n";
        assert_silent(&lint("f", ok), "VYO034");
    }

    #[test]
    fn clean_set_style() {
        let src = "set interfaces ethernet eth0 address '10.0.0.1/24'\nset system host-name r1\n";
        assert_clean(&lint("f", src));
    }
}
