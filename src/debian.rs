// Linter for Debian /etc/network/interfaces.
//
// Reference: ifupdown(8) / interfaces(5).
// Stanzas are introduced by keywords at column 0; option lines that follow
// belong to the most recent iface stanza.

use crate::diag::{
    is_valid_ipv4, is_valid_ipv4_cidr, is_valid_ipv6, is_valid_ipv6_cidr, Diagnostic, Severity,
};

const FAMILIES: &[&str] = &["inet", "inet6", "ipx", "can"];
const METHODS: &[&str] = &[
    "static",
    "dhcp",
    "manual",
    "loopback",
    "auto",
    "bootp",
    "ppp",
    "tunnel",
    "wvdial",
    "ipv4ll",
    "v4tunnel",
    "6to4",
    "wireguard",
];
const TOP_KEYWORDS: &[&str] = &[
    "auto",
    "allow-auto",
    "allow-hotplug",
    "no-auto-down",
    "no-scripts",
    "iface",
    "mapping",
    "source",
    "source-directory",
    "rename",
];

pub fn lint(file: &str, src: &str) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let mut current_family: Option<String> = None;
    let mut autos: Vec<String> = Vec::new();
    let mut declared_ifaces: Vec<String> = Vec::new();

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

        let head = trimmed.split_whitespace().next().unwrap_or("");
        let is_top = line.starts_with(|c: char| !c.is_whitespace()) && TOP_KEYWORDS.contains(&head);

        if is_top {
            match head {
                "auto" | "allow-auto" | "allow-hotplug" => {
                    for name in trimmed.split_whitespace().skip(1) {
                        autos.push(name.to_string());
                    }
                }
                "iface" => {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() < 4 {
                        diags.push(Diagnostic::new(
                            file,
                            lno,
                            1,
                            Severity::Error,
                            "DEB010",
                            "`iface` needs NAME FAMILY METHOD",
                        ));
                        current_family = None;
                        continue;
                    }
                    let (name, family, method) = (parts[1], parts[2], parts[3]);
                    declared_ifaces.push(name.to_string());
                    if !FAMILIES.contains(&family) {
                        diags.push(Diagnostic::new(
                            file,
                            lno,
                            1,
                            Severity::Warning,
                            "DEB011",
                            format!("unknown address family `{}`", family),
                        ));
                    }
                    if !METHODS.contains(&method) {
                        diags.push(Diagnostic::new(
                            file,
                            lno,
                            1,
                            Severity::Warning,
                            "DEB012",
                            format!("unknown method `{}`", method),
                        ));
                    }
                    current_family = Some(family.to_string());
                }
                "source" | "source-directory" => {
                    let arg = trimmed.split_whitespace().nth(1).unwrap_or("");
                    if arg.is_empty() {
                        diags.push(Diagnostic::new(
                            file,
                            lno,
                            1,
                            Severity::Error,
                            "DEB013",
                            "`source`/`source-directory` needs a path",
                        ));
                    }
                }
                _ => {}
            }
        } else {
            // option line within current iface
            check_option(file, lno, trimmed, current_family.as_deref(), &mut diags);
        }
    }

    // auto NAME without matching iface stanza
    for name in &autos {
        if !declared_ifaces.contains(name) && name != "lo" {
            diags.push(Diagnostic::new(
                file,
                0,
                1,
                Severity::Hint,
                "DEB030",
                format!(
                    "`auto {}` has no matching `iface` stanza (probably defined under source)",
                    name
                ),
            ));
        }
    }
    diags
}

fn check_option(
    file: &str,
    lno: usize,
    line: &str,
    family: Option<&str>,
    diags: &mut Vec<Diagnostic>,
) {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let Some(key) = parts.first() else { return };
    let value_parts = &parts[1..];
    match *key {
        "address" => {
            let v = value_parts.first().copied().unwrap_or("");
            let expects_v6 = family == Some("inet6");
            let ok = if v.contains('/') {
                if expects_v6 {
                    is_valid_ipv6_cidr(v)
                } else {
                    is_valid_ipv4_cidr(v) || is_valid_ipv6_cidr(v)
                }
            } else if expects_v6 {
                is_valid_ipv6(v)
            } else {
                is_valid_ipv4(v) || is_valid_ipv6(v)
            };
            if !v.is_empty() && !ok {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    1,
                    Severity::Error,
                    "DEB020",
                    format!("invalid address `{}`", v),
                ));
            }
        }
        "gateway" => {
            let v = value_parts.first().copied().unwrap_or("");
            let expects_v6 = family == Some("inet6");
            let ok = if expects_v6 {
                is_valid_ipv6(v)
            } else {
                is_valid_ipv4(v) || is_valid_ipv6(v)
            };
            if !v.is_empty() && !ok {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    1,
                    Severity::Error,
                    "DEB021",
                    format!("invalid gateway `{}`", v),
                ));
            }
        }
        "netmask" => {
            let v = value_parts.first().copied().unwrap_or("");
            if !v.is_empty() && !is_valid_ipv4(v) {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    1,
                    Severity::Error,
                    "DEB022",
                    format!("invalid netmask `{}`", v),
                ));
            }
        }
        "dns-nameservers" => {
            for v in value_parts {
                if !is_valid_ipv4(v) && !is_valid_ipv6(v) {
                    diags.push(Diagnostic::new(
                        file,
                        lno,
                        1,
                        Severity::Error,
                        "DEB023",
                        format!("invalid DNS server `{}`", v),
                    ));
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::lint;
    use crate::diag::tests::{assert_clean, assert_emits, assert_silent};

    #[test]
    fn deb010_iface_missing_args() {
        assert_emits(&lint("f", "iface eth0 inet\n"), "DEB010");
        assert_silent(&lint("f", "iface eth0 inet dhcp\n"), "DEB010");
    }

    #[test]
    fn deb011_unknown_family() {
        assert_emits(&lint("f", "iface eth0 ipx-magic static\n"), "DEB011");
        assert_silent(&lint("f", "iface eth0 inet static\n"), "DEB011");
    }

    #[test]
    fn deb020_invalid_address() {
        let bad = "iface eth0 inet static\n    address 10.0.0.300/24\n";
        assert_emits(&lint("f", bad), "DEB020");
        let ok = "iface eth0 inet static\n    address 10.0.0.1/24\n";
        assert_silent(&lint("f", ok), "DEB020");
    }

    #[test]
    fn deb023_invalid_dns_server() {
        let bad = "iface eth0 inet static\n    dns-nameservers 1.1.1.1 999.999.999.999\n";
        assert_emits(&lint("f", bad), "DEB023");
        let ok = "iface eth0 inet static\n    dns-nameservers 1.1.1.1 8.8.8.8\n";
        assert_silent(&lint("f", ok), "DEB023");
    }

    #[test]
    fn clean_minimal() {
        let src =
            "auto eth0\niface eth0 inet static\n    address 10.0.0.1/24\n    gateway 10.0.0.254\n";
        assert_clean(&lint("f", src));
    }
}
