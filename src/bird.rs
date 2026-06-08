use crate::diag::{is_valid_asn, is_valid_ipv4_cidr, is_valid_ipv6_cidr, Diagnostic, Severity};

const PROTOCOL_KINDS: &[&str] = &[
    "bgp", "ospf", "ospf v2", "ospf v3", "rip", "rip ng", "static", "direct", "device", "kernel",
    "pipe", "babel", "radv", "bfd", "mrt", "perf", "rpki", "l3vpn",
];

pub fn lint(file: &str, src: &str) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let mut brace_depth: i64 = 0;
    let mut brace_stack_lines: Vec<usize> = Vec::new();
    let mut in_comment_block = false;
    let mut bracket_depth: i64 = 0;
    let mut defined_symbols: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (i, raw) in src.lines().enumerate() {
        let lno = i + 1;
        let mut line = strip_line_comments(raw);

        // Handle /* ... */ across lines.
        let mut effective = String::new();
        let mut idx = 0;
        while idx < line.len() {
            if in_comment_block {
                if let Some(end) = line[idx..].find("*/") {
                    idx += end + 2;
                    in_comment_block = false;
                } else {
                    idx = line.len();
                }
            } else if let Some(start) = line[idx..].find("/*") {
                effective.push_str(&line[idx..idx + start]);
                idx += start + 2;
                in_comment_block = true;
            } else {
                effective.push_str(&line[idx..]);
                idx = line.len();
            }
        }
        line = effective;

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Brace + bracket tracking
        for c in trimmed.chars() {
            match c {
                '{' => {
                    brace_depth += 1;
                    brace_stack_lines.push(lno);
                }
                '}' => {
                    brace_depth -= 1;
                    brace_stack_lines.pop();
                    if brace_depth < 0 {
                        diags.push(Diagnostic::new(
                            file,
                            lno,
                            1,
                            Severity::Error,
                            "BIR010",
                            "unexpected `}`",
                        ));
                        brace_depth = 0;
                    }
                }
                '[' => bracket_depth += 1,
                ']' => bracket_depth = (bracket_depth - 1).max(0),
                _ => {}
            }
        }

        // Track `define NAME = ...;` so we can recognise SYMBOL routes.
        if let Some(rest) = trimmed.strip_prefix("define ") {
            if let Some(name) = rest.split_whitespace().next() {
                defined_symbols.insert(name.trim_end_matches('=').to_string());
            }
        }

        // protocol opener: `protocol bgp uplink { ... }`
        if let Some(rest) = trimmed.strip_prefix("protocol ") {
            let kind = rest.split_whitespace().next().unwrap_or("");
            if !PROTOCOL_KINDS.contains(&kind) {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    10,
                    Severity::Warning,
                    "BIR020",
                    format!("unknown protocol kind `{}`", kind),
                ));
            }
        }

        // `local as N;` and `neighbor IP as N;` ASN sanity.
        // BIRD also accepts a `define`d symbol here (e.g. `local as LOCAL_AS;`).
        if let Some(rest) = trimmed.strip_prefix("local as ") {
            let asn = rest
                .trim_end_matches(';')
                .split_whitespace()
                .next()
                .unwrap_or("");
            if !asn.is_empty() && looks_like_number(asn) && !is_valid_asn(asn) {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    10,
                    Severity::Error,
                    "BIR050",
                    format!("invalid `local as` ASN `{}`", asn),
                ));
            }
        }
        if trimmed.starts_with("neighbor ") && trimmed.contains(" as ") {
            let after_as = trimmed.split(" as ").nth(1).unwrap_or("");
            let asn = after_as.split([';', ' ']).next().unwrap_or("");
            if !asn.is_empty() && looks_like_number(asn) && !is_valid_asn(asn) {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    1,
                    Severity::Error,
                    "BIR051",
                    format!("invalid `neighbor ... as` ASN `{}`", asn),
                ));
            }
        }

        // route prefix in static or filter context: lines like `route 10.0.0.0/24 via "iface";`
        // BIRD also accepts a defined symbol here: `route PUBLIC_NET4 via ...;`.
        if let Some(rest) = trimmed.strip_prefix("route ") {
            let tok = rest
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_end_matches(';');
            if !tok.is_empty() && looks_like_prefix(tok) {
                if !is_valid_ipv4_cidr(tok) && !is_valid_ipv6_cidr(tok) {
                    diags.push(Diagnostic::new(
                        file,
                        lno,
                        7,
                        Severity::Error,
                        "BIR030",
                        format!("invalid route prefix `{}`", tok),
                    ));
                }
            } else if !tok.is_empty() && !defined_symbols.contains(tok) {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    7,
                    Severity::Hint,
                    "BIR031",
                    format!(
                        "`route {}` references an undefined symbol (or missed include)",
                        tok
                    ),
                ));
            }
        }

        // Statement at brace_depth > 0 should normally end with `;` or be a block opener/closer.
        // Skip the check when we're inside `[...]` (set/array literal — `,` separated).
        let last = trimmed.chars().last().unwrap();
        let opens_or_closes_block = last == '{' || last == '}' || trimmed.ends_with("};");
        let is_label = trimmed.ends_with(':');
        let is_directive_line = trimmed.starts_with("define ") || trimmed.starts_with("include ");
        if brace_depth > 0
            && bracket_depth == 0
            && !opens_or_closes_block
            && !is_label
            && !is_directive_line
            && !trimmed.ends_with(';')
            && !trimmed.ends_with(',')
        {
            // Only warn for lines that look like statements (contain alnum + space).
            if trimmed.contains(' ') || trimmed.contains('=') {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    trimmed.len().max(1),
                    Severity::Warning,
                    "BIR040",
                    "statement missing trailing `;`",
                ));
            }
        }
    }

    if brace_depth > 0 {
        for ln in brace_stack_lines {
            diags.push(Diagnostic::new(
                file,
                ln,
                1,
                Severity::Error,
                "BIR011",
                "unclosed `{` block",
            ));
        }
    }
    diags
}

fn looks_like_prefix(s: &str) -> bool {
    // Real prefixes contain a `/` and at least one `.` (IPv4) or `:` (IPv6).
    s.contains('/') && (s.contains('.') || s.contains(':'))
}

fn looks_like_number(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

fn strip_line_comments(s: &str) -> String {
    // BIRD supports `#` and `//` line comments. Respect strings.
    let mut out = String::with_capacity(s.len());
    let mut in_str = false;
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_str {
            out.push(c);
            if c == '"' && (i == 0 || chars[i - 1] != '\\') {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_str = true;
            out.push(c);
            i += 1;
            continue;
        }
        if c == '#' {
            break;
        }
        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            break;
        }
        out.push(c);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::lint;
    use crate::diag::tests::{assert_clean, assert_emits, assert_silent};

    #[test]
    fn bir020_unknown_protocol() {
        assert_emits(&lint("f", "protocol bogus uplink {}\n"), "BIR020");
        assert_silent(&lint("f", "protocol bgp uplink {}\n"), "BIR020");
    }

    #[test]
    fn bir030_invalid_route_prefix() {
        // 1.2.3.4/40 is invalid IPv4 prefix length
        assert_emits(
            &lint(
                "f",
                "protocol static {\n  route 1.2.3.4/40 via \"eth0\";\n}\n",
            ),
            "BIR030",
        );
        assert_silent(
            &lint(
                "f",
                "protocol static {\n  route 10.0.0.0/8 via \"eth0\";\n}\n",
            ),
            "BIR030",
        );
    }

    #[test]
    fn route_symbol_not_flagged() {
        // BIRD allows `route SYMBOL unreachable;` when SYMBOL is `define`d.
        let ok = "define PUBLIC_NET4 = 192.0.2.0/24;\nprotocol static {\n  route PUBLIC_NET4 unreachable;\n}\n";
        assert_silent(&lint("f", ok), "BIR030");
    }

    #[test]
    fn missing_semicolon_inside_set_literal_not_flagged() {
        // Lines inside `[ ... ]` set literals end in `,` not `;` — must not flag BIR040.
        let ok = "filter f {\n  return net ~ [\n    0.0.0.0/8+,\n    10.0.0.0/8+,\n  ];\n}\n";
        assert_silent(&lint("f", ok), "BIR040");
    }

    #[test]
    fn bir050_invalid_local_as() {
        let bad = "protocol bgp x {\n  local as 4294967296;\n}\n";
        assert_emits(&lint("f", bad), "BIR050");
        let ok = "protocol bgp x {\n  local as 65001;\n}\n";
        assert_silent(&lint("f", ok), "BIR050");
    }

    #[test]
    fn bir051_invalid_neighbor_as() {
        let bad = "protocol bgp x {\n  neighbor 10.0.0.2 as 4294967296;\n}\n";
        assert_emits(&lint("f", bad), "BIR051");
        let ok = "protocol bgp x {\n  neighbor 10.0.0.2 as 65002;\n}\n";
        assert_silent(&lint("f", ok), "BIR051");
    }

    #[test]
    fn defined_symbol_as_is_not_flagged() {
        // Common pattern: `define LOCAL_AS = 65001;` then `local as LOCAL_AS;`
        let ok = "define LOCAL_AS = 65001;\nprotocol bgp x {\n  local as LOCAL_AS;\n  neighbor 10.0.0.2 as LOCAL_AS;\n}\n";
        assert_silent(&lint("f", ok), "BIR050");
        assert_silent(&lint("f", ok), "BIR051");
    }

    #[test]
    fn clean_minimal() {
        let src = "router id 10.0.0.1;\nprotocol device {\n}\nprotocol kernel {\n  ipv4 { export all; };\n}\n";
        assert_clean(&lint("f", src));
    }
}
