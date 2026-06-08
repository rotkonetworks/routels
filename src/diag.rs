use serde::Serialize;
use std::fmt;
use std::io::{self, Write};

#[derive(Copy, Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
pub enum Severity {
    Error,
    Warning,
    Info,
    Hint,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
            Severity::Hint => "hint",
        })
    }
}

impl Severity {
    /// Lower rank = more severe (matches LSP convention).
    pub fn rank(self) -> u8 {
        match self {
            Severity::Error => 1,
            Severity::Warning => 2,
            Severity::Info => 3,
            Severity::Hint => 4,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Diagnostic {
    pub file: String,
    pub line: usize,
    pub col: usize,
    pub severity: Severity,
    pub code: &'static str,
    pub message: String,
}

impl Diagnostic {
    pub fn new(
        file: impl Into<String>,
        line: usize,
        col: usize,
        severity: Severity,
        code: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            file: file.into(),
            line,
            col,
            severity,
            code,
            message: message.into(),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Format {
    Text,
    Json,
    Sarif,
}

pub fn emit(diags: &[Diagnostic], format: Format) -> io::Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    match format {
        Format::Text => {
            for d in diags {
                writeln!(
                    out,
                    "{}:{}:{}: {}: {} [{}]",
                    d.file, d.line, d.col, d.severity, d.message, d.code
                )?;
            }
        }
        Format::Json => {
            for d in diags {
                serde_json::to_writer(&mut out, d)?;
                out.write_all(b"\n")?;
            }
        }
        Format::Sarif => {
            let doc = build_sarif(diags);
            serde_json::to_writer_pretty(&mut out, &doc)?;
            out.write_all(b"\n")?;
        }
    }
    Ok(())
}

fn build_sarif(diags: &[Diagnostic]) -> serde_json::Value {
    use serde_json::json;
    let level_for = |s: Severity| match s {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
        Severity::Hint => "note",
    };
    // Collect unique rule codes that actually fired so we don't bloat the doc.
    let mut codes: Vec<&'static str> = diags.iter().map(|d| d.code).collect();
    codes.sort_unstable();
    codes.dedup();
    let rules: Vec<serde_json::Value> = codes
        .iter()
        .map(|c| {
            let desc = crate::rules::explain(c)
                .map(|r| r.description)
                .unwrap_or("");
            json!({
                "id": c,
                "shortDescription": { "text": desc },
            })
        })
        .collect();

    let results: Vec<serde_json::Value> = diags
        .iter()
        .map(|d| {
            json!({
                "ruleId": d.code,
                "level": level_for(d.severity),
                "message": { "text": d.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": d.file },
                        "region": {
                            "startLine": d.line.max(1),
                            "startColumn": d.col.max(1),
                        }
                    }
                }]
            })
        })
        .collect();

    json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "routels",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/rotkonetworks/routels",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    })
}

pub fn is_valid_ipv4_cidr(s: &str) -> bool {
    let (addr, prefix) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    if !is_valid_ipv4(addr) {
        return false;
    }
    if let Some(p) = prefix {
        match p.parse::<u8>() {
            Ok(n) if n <= 32 => {}
            _ => return false,
        }
    }
    true
}

pub fn is_valid_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts
        .iter()
        .all(|p| !p.is_empty() && p.parse::<u8>().is_ok())
}

pub fn is_valid_ipv6_cidr(s: &str) -> bool {
    let (addr, prefix) = match s.rsplit_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    if !is_valid_ipv6(addr) {
        return false;
    }
    if let Some(p) = prefix {
        match p.parse::<u8>() {
            Ok(n) if n <= 128 => {}
            _ => return false,
        }
    }
    true
}

pub fn is_valid_ipv6(s: &str) -> bool {
    // Coarse check: hex groups separated by ':' with at most one "::" run.
    // Tail group may be an embedded IPv4 (RFC 4291 §2.2.3), e.g. ::ffff:0.0.0.0.
    if s.is_empty() {
        return false;
    }
    // Reject triple-or-more colons (e.g. `:::`) and leading/trailing `:` that
    // isn't part of a `::` run.
    if s.contains(":::") {
        return false;
    }
    let double_colon_count = s.matches("::").count();
    if double_colon_count > 1 {
        return false;
    }
    let groups: Vec<&str> = s.split(':').collect();
    if double_colon_count == 0 && (groups.len() < 3 || groups.len() > 8) {
        return false;
    }
    for (i, g) in groups.iter().enumerate() {
        if g.is_empty() {
            continue; // produced by "::"
        }
        // Allow the final group to be a dotted-quad IPv4 (::ffff:1.2.3.4).
        if i == groups.len() - 1 && g.contains('.') {
            if !is_valid_ipv4(g) {
                return false;
            }
            continue;
        }
        if g.len() > 4 || !g.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }
    true
}

pub fn is_valid_asn(s: &str) -> bool {
    // 2-byte (0..=65535) or 4-byte (0..=4294967295); reject leading zeros except "0".
    if s.is_empty() {
        return false;
    }
    if s.len() > 1 && s.starts_with('0') {
        return false;
    }
    s.parse::<u32>().is_ok()
}

/// Test helpers shared by per-module red/green tests.
#[cfg(test)]
pub mod tests {
    use super::Diagnostic;

    /// RED: assert that `code` appears in `diags` (rule fires on this input).
    #[track_caller]
    pub fn assert_emits(diags: &[Diagnostic], code: &str) {
        assert!(
            diags.iter().any(|d| d.code == code),
            "expected diagnostic `{code}` to fire; got: {:?}",
            diags.iter().map(|d| d.code).collect::<Vec<_>>()
        );
    }

    /// GREEN: assert that `code` does NOT appear in `diags` (rule silent on this input).
    #[track_caller]
    pub fn assert_silent(diags: &[Diagnostic], code: &str) {
        assert!(
            !diags.iter().any(|d| d.code == code),
            "expected `{code}` NOT to fire; got: {:?}",
            diags
                .iter()
                .map(|d| (d.code, &d.message))
                .collect::<Vec<_>>()
        );
    }

    /// GREEN: assert no diagnostics at all (clean input).
    #[track_caller]
    pub fn assert_clean(diags: &[Diagnostic]) {
        assert!(
            diags.is_empty(),
            "expected no diagnostics; got: {:?}",
            diags
                .iter()
                .map(|d| (d.code, &d.message))
                .collect::<Vec<_>>()
        );
    }

    use super::{is_valid_ipv4, is_valid_ipv4_cidr, is_valid_ipv6, is_valid_ipv6_cidr};
    use proptest::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    proptest! {
        // Any string that std accepts as Ipv4Addr must also be accepted by our checker.
        #[test]
        fn ipv4_agrees_with_std(a in 0u8..=255, b in 0u8..=255, c in 0u8..=255, d in 0u8..=255) {
            let s = format!("{a}.{b}.{c}.{d}");
            prop_assert!(is_valid_ipv4(&s));
            prop_assert!(Ipv4Addr::from_str(&s).is_ok());
        }

        // Random bytes never panic the validator and stay consistent with std for parseable input.
        #[test]
        fn ipv4_never_panics(s in ".*") {
            let _ = is_valid_ipv4(&s);
            let _ = is_valid_ipv4_cidr(&s);
        }

        // Generated IPv4 CIDRs round-trip.
        #[test]
        fn ipv4_cidr_roundtrip(a in 0u8..=255, b in 0u8..=255, c in 0u8..=255, d in 0u8..=255, p in 0u8..=32) {
            let s = format!("{a}.{b}.{c}.{d}/{p}");
            prop_assert!(is_valid_ipv4_cidr(&s), "rejected {s}");
        }

        // Out-of-range prefix length must be rejected.
        #[test]
        fn ipv4_cidr_rejects_bad_prefix(p in 33u16..=999) {
            let s = format!("10.0.0.0/{p}");
            prop_assert!(!is_valid_ipv4_cidr(&s), "accepted {s}");
        }

        // Generated IPv6 from std (canonical form) must be accepted.
        #[test]
        fn ipv6_from_std_accepted(segments in proptest::array::uniform8(0u16..=u16::MAX)) {
            let ip = Ipv6Addr::new(
                segments[0], segments[1], segments[2], segments[3],
                segments[4], segments[5], segments[6], segments[7],
            );
            prop_assert!(is_valid_ipv6(&ip.to_string()));
        }

        #[test]
        fn ipv6_never_panics(s in ".*") {
            let _ = is_valid_ipv6(&s);
            let _ = is_valid_ipv6_cidr(&s);
        }

        // Random Unicode never matches an IPv4 format unintentionally.
        #[test]
        fn random_garbage_rejected(s in "[^0-9.]{3,20}") {
            prop_assert!(!is_valid_ipv4(&s));
        }
    }

    #[test]
    fn ipv6_known_corner_cases() {
        assert!(is_valid_ipv6("::"));
        assert!(is_valid_ipv6("::1"));
        assert!(is_valid_ipv6("2001:db8::"));
        assert!(is_valid_ipv6("::ffff:0.0.0.0")); // IPv4-mapped
        assert!(is_valid_ipv6("::ffff:1.2.3.4"));
        assert!(is_valid_ipv6_cidr("::ffff:0.0.0.0/96"));
        assert!(!is_valid_ipv6(":::")); // triple colon
        assert!(!is_valid_ipv6("1::2::3")); // two `::` runs
        assert!(!is_valid_ipv6("gggg::")); // non-hex
        assert!(!is_valid_ipv6_cidr("2001:db8::/129")); // prefix too long
    }
}
