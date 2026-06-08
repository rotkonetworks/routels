use crate::diag::{Diagnostic, Severity};

const NFT_FAMILIES: &[&str] = &["ip", "ip6", "inet", "arp", "bridge", "netdev"];
const NFT_HOOKS: &[&str] = &[
    "prerouting",
    "input",
    "forward",
    "output",
    "postrouting",
    "ingress",
    "egress",
];
const IPT_TARGETS_OK: &[&str] = &[
    "ACCEPT",
    "DROP",
    "REJECT",
    "RETURN",
    "QUEUE",
    "LOG",
    "MARK",
    "DNAT",
    "SNAT",
    "MASQUERADE",
    "REDIRECT",
    "TCPMSS",
    "CT",
    "NFLOG",
    "NOTRACK",
    "SET",
];

pub fn lint(file: &str, src: &str) -> Vec<Diagnostic> {
    if is_iptables_save(src) {
        lint_iptables(file, src)
    } else {
        lint_nft(file, src)
    }
}

fn is_iptables_save(src: &str) -> bool {
    src.lines().take(50).any(|l| {
        let t = l.trim_start();
        t.starts_with("*filter")
            || t.starts_with("*nat")
            || t.starts_with("*mangle")
            || t.starts_with("*raw")
    })
}

fn lint_nft(file: &str, src: &str) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let mut depth: i64 = 0;
    let mut open_lines: Vec<usize> = Vec::new();

    for (i, raw) in src.lines().enumerate() {
        let lno = i + 1;
        let line = strip_comment(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        for c in trimmed.chars() {
            match c {
                '{' => {
                    depth += 1;
                    open_lines.push(lno);
                }
                '}' => {
                    depth -= 1;
                    open_lines.pop();
                    if depth < 0 {
                        diags.push(Diagnostic::new(
                            file,
                            lno,
                            1,
                            Severity::Error,
                            "NFT010",
                            "unexpected `}`",
                        ));
                        depth = 0;
                    }
                }
                _ => {}
            }
        }

        if let Some(rest) = trimmed.strip_prefix("table ") {
            let mut parts = rest.split_whitespace();
            let family = parts.next().unwrap_or("");
            if !NFT_FAMILIES.contains(&family) {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    7,
                    Severity::Warning,
                    "NFT020",
                    format!("unknown nftables family `{}`", family),
                ));
            }
        }

        // `type filter hook input priority 0; policy drop;` — find `hook` anywhere.
        if let Some(idx) = trimmed.find(" hook ") {
            let after = &trimmed[idx + 6..];
            let hook = after.split_whitespace().next().unwrap_or("");
            if !NFT_HOOKS.contains(&hook) {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    idx + 7,
                    Severity::Warning,
                    "NFT021",
                    format!("unknown hook `{}`", hook),
                ));
            }
        }
    }

    if depth > 0 {
        for ln in open_lines {
            diags.push(Diagnostic::new(
                file,
                ln,
                1,
                Severity::Error,
                "NFT011",
                "unclosed `{` block",
            ));
        }
    }
    diags
}

fn lint_iptables(file: &str, src: &str) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let mut current_table: Option<String> = None;
    let mut committed = true;

    for (i, raw) in src.lines().enumerate() {
        let lno = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(name) = line.strip_prefix('*') {
            if !committed {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    1,
                    Severity::Error,
                    "IPT010",
                    format!(
                        "table `{}` opened before previous COMMIT",
                        current_table.as_deref().unwrap_or("?")
                    ),
                ));
            }
            current_table = Some(name.trim().to_string());
            committed = false;
            continue;
        }

        if line == "COMMIT" {
            if committed {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    1,
                    Severity::Warning,
                    "IPT011",
                    "COMMIT with no open table",
                ));
            }
            committed = true;
            current_table = None;
            continue;
        }

        if line.starts_with(':') {
            // chain decl: `:CHAIN POLICY [pkts:bytes]`
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    1,
                    Severity::Error,
                    "IPT020",
                    "chain declaration missing policy",
                ));
            } else {
                let pol = parts[1];
                if !["ACCEPT", "DROP", "-"].contains(&pol) {
                    diags.push(Diagnostic::new(
                        file,
                        lno,
                        1,
                        Severity::Warning,
                        "IPT021",
                        format!("unusual policy `{}` (expected ACCEPT/DROP/-)", pol),
                    ));
                }
            }
            continue;
        }

        if line.starts_with("-A ") || line.starts_with("-I ") || line.starts_with("-N ") {
            // rule lines — best-effort target sanity if `-j X` present
            if let Some(j_pos) = line.find(" -j ") {
                let after = &line[j_pos + 4..];
                let tgt = after.split_whitespace().next().unwrap_or("");
                // User chains are also valid targets, so only warn for uppercase non-listed.
                if tgt.chars().all(|c| c.is_ascii_uppercase() || c == '_')
                    && !IPT_TARGETS_OK.contains(&tgt)
                {
                    diags.push(Diagnostic::new(
                        file,
                        lno,
                        j_pos + 5,
                        Severity::Hint,
                        "IPT030",
                        format!("unknown built-in target `{}` (treating as user chain)", tgt),
                    ));
                }
            }
            continue;
        }
    }

    if !committed {
        diags.push(Diagnostic::new(
            file,
            0,
            1,
            Severity::Error,
            "IPT012",
            format!(
                "table `{}` not closed with COMMIT",
                current_table.unwrap_or_default()
            ),
        ));
    }
    diags
}

fn strip_comment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_str = false;
    for c in s.chars() {
        if c == '"' {
            in_str = !in_str;
        }
        if c == '#' && !in_str {
            break;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::lint;
    use crate::diag::tests::{assert_clean, assert_emits, assert_silent};

    #[test]
    fn nft020_unknown_family() {
        assert_emits(&lint("f", "table foofamily filter {\n}\n"), "NFT020");
        assert_silent(&lint("f", "table inet filter {\n}\n"), "NFT020");
    }

    #[test]
    fn nft021_unknown_hook() {
        let bad = "table inet f {\n  chain c {\n    type filter hook nowhere priority 0;\n  }\n}\n";
        assert_emits(&lint("f", bad), "NFT021");
        let ok = "table inet f {\n  chain c {\n    type filter hook input priority 0;\n  }\n}\n";
        assert_silent(&lint("f", ok), "NFT021");
    }

    #[test]
    fn nft011_unclosed_brace() {
        assert_emits(&lint("f", "table inet f {\n  chain c {\n"), "NFT011");
        assert_silent(&lint("f", "table inet f {\n}\n"), "NFT011");
    }

    #[test]
    fn ipt010_table_open_before_commit() {
        let bad = "*filter\n:INPUT ACCEPT [0:0]\n*nat\n";
        assert_emits(&lint("f", bad), "IPT010");
        let ok = "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n*nat\n:PREROUTING ACCEPT [0:0]\nCOMMIT\n";
        assert_silent(&lint("f", ok), "IPT010");
    }

    #[test]
    fn clean_nft_skeleton() {
        let src = "table inet filter {\n  chain input {\n    type filter hook input priority 0; policy drop;\n  }\n}\n";
        assert_clean(&lint("f", src));
    }
}
