// Linter for sysctl.conf and /etc/sysctl.d/*.conf.
// Format per sysctl.conf(5): `key = value`, optionally prefixed with `-` to ignore errors.

use crate::diag::{Diagnostic, Severity};
use std::collections::HashMap;

const BOOLEAN_SUFFIXES: &[&str] = &[
    // Common net.*.{forwarding,rp_filter,accept_ra,accept_redirects,...}: 0/1.
    "forwarding",
    "rp_filter",
    "accept_ra",
    "accept_redirects",
    "send_redirects",
    "log_martians",
    "accept_source_route",
    "secure_redirects",
    "proxy_arp",
    "ignore_routes_with_linkdown",
    "tcp_tw_reuse",
    "tcp_window_scaling",
    "tcp_sack",
    "tcp_fastopen",
    "ip_forward",
    "ip_no_pmtu_disc",
    "tcp_slow_start_after_idle",
];

pub fn lint(file: &str, src: &str) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();

    for (i, raw) in src.lines().enumerate() {
        let lno = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        let Some((lhs, rhs)) = line.split_once('=') else {
            diags.push(Diagnostic::new(
                file,
                lno,
                1,
                Severity::Error,
                "SYS010",
                "expected `key = value`",
            ));
            continue;
        };
        let raw_key = lhs.trim();
        let value = rhs.trim();
        let key = raw_key.trim_start_matches('-');

        if key.is_empty() {
            diags.push(Diagnostic::new(
                file,
                lno,
                1,
                Severity::Error,
                "SYS011",
                "empty key",
            ));
            continue;
        }

        // Keys are dotted paths under net/kernel/vm/fs/dev/...
        if !key.contains('.') {
            diags.push(Diagnostic::new(
                file,
                lno,
                1,
                Severity::Warning,
                "SYS012",
                format!("key `{}` has no `.` (sysctl keys are usually dotted)", key),
            ));
        }
        if !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' || c == '/')
        {
            diags.push(Diagnostic::new(
                file,
                lno,
                1,
                Severity::Error,
                "SYS013",
                format!("invalid char in key `{}`", key),
            ));
        }

        if let Some(prev) = seen.insert(key.to_string(), lno) {
            diags.push(Diagnostic::new(
                file,
                lno,
                1,
                Severity::Warning,
                "SYS020",
                format!("duplicate key `{}` (first set at line {})", key, prev),
            ));
        }

        // Boolean-ish key value sanity
        let leaf = key.rsplit('.').next().unwrap_or("");
        if BOOLEAN_SUFFIXES.contains(&leaf) {
            // 0/1 for most; rp_filter accepts 0/1/2; tcp_fastopen bitmask 0..=3.
            let allowed: &[&str] = match leaf {
                "rp_filter" => &["0", "1", "2"],
                "tcp_fastopen" => &["0", "1", "2", "3"],
                _ => &["0", "1"],
            };
            if !allowed.contains(&value) {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    1,
                    Severity::Warning,
                    "SYS030",
                    format!("`{}` got `{}` (allowed: {})", key, value, allowed.join("|")),
                ));
            }
        }

        if value.is_empty() {
            diags.push(Diagnostic::new(
                file,
                lno,
                1,
                Severity::Warning,
                "SYS031",
                format!("empty value for `{}`", key),
            ));
        }
    }
    diags
}

#[cfg(test)]
mod tests {
    use super::lint;
    use crate::diag::tests::{assert_clean, assert_emits, assert_silent};

    #[test]
    fn sys010_missing_equals() {
        assert_emits(&lint("f", "net.ipv4.ip_forward 1\n"), "SYS010");
        assert_silent(&lint("f", "net.ipv4.ip_forward = 1\n"), "SYS010");
    }

    #[test]
    fn sys012_undotted_key() {
        assert_emits(&lint("f", "ip_forward = 1\n"), "SYS012");
        assert_silent(&lint("f", "net.ipv4.ip_forward = 1\n"), "SYS012");
    }

    #[test]
    fn sys013_invalid_char_in_key() {
        assert_emits(&lint("f", "bad key = 5\n"), "SYS013");
        assert_silent(&lint("f", "net.ipv4.ip_forward = 1\n"), "SYS013");
    }

    #[test]
    fn sys020_duplicate_key() {
        let bad = "net.ipv4.ip_forward = 0\nnet.ipv4.ip_forward = 1\n";
        assert_emits(&lint("f", bad), "SYS020");
        let ok = "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n";
        assert_silent(&lint("f", ok), "SYS020");
    }

    #[test]
    fn sys030_non_boolean_value_for_boolean_key() {
        assert_emits(&lint("f", "net.ipv4.ip_forward = banana\n"), "SYS030");
        assert_silent(&lint("f", "net.ipv4.ip_forward = 1\n"), "SYS030");
    }

    #[test]
    fn tcp_fastopen_3_is_valid() {
        // TFO bitmask: 1=client, 2=server, 3=both — `3` must not fire SYS030.
        assert_silent(&lint("f", "net.ipv4.tcp_fastopen = 3\n"), "SYS030");
        assert_emits(&lint("f", "net.ipv4.tcp_fastopen = 9\n"), "SYS030");
    }

    #[test]
    fn slash_in_vlan_iface_key_is_valid() {
        // Linux VLAN sub-iface names contain `/`: `enp2s0f0np0/400`
        let ok = "net.ipv6.conf.enp2s0f0np0/400.accept_ra = 0\n";
        assert_silent(&lint("f", ok), "SYS013");
    }

    #[test]
    fn ignore_prefix_allowed() {
        // `-key = value` means "ignore errors" — must not be treated as bad syntax.
        let ok = "-net.ipv4.maybe_missing = 0\n";
        assert_silent(&lint("f", ok), "SYS011");
        assert_silent(&lint("f", ok), "SYS013");
    }

    #[test]
    fn clean_minimal() {
        let src = "net.ipv4.ip_forward = 1\nnet.core.default_qdisc = fq\n";
        assert_clean(&lint("f", src));
    }
}
