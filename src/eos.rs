use crate::diag::{is_valid_asn, is_valid_ipv4_cidr, is_valid_ipv6_cidr, Diagnostic, Severity};

const VALID_IFACE_KINDS: &[&str] = &[
    "Ethernet",
    "Management",
    "Loopback",
    "Vlan",
    "Port-Channel",
    "Tunnel",
    "Vxlan",
    "Recirc-Channel",
    "Fabric",
];

pub fn lint(file: &str, src: &str) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let mut mode_stack: Vec<(usize, String)> = Vec::new(); // (indent, mode-name)
    let mut seen_ifaces: Vec<(String, usize)> = Vec::new();

    for (i, raw_line) in src.lines().enumerate() {
        let lno = i + 1;
        let line = raw_line.trim_end();
        let stripped = line.trim_start();
        if stripped.is_empty() || stripped.starts_with('!') {
            continue;
        }
        let indent = line.len() - stripped.len();

        // Tabs are unusual in EOS output — flag once per line.
        if line[..indent].contains('\t') {
            diags.push(Diagnostic::new(
                file,
                lno,
                1,
                Severity::Warning,
                "EOS001",
                "tab indentation (EOS uses spaces)",
            ));
        }

        while mode_stack.last().is_some_and(|(ind, _)| *ind >= indent) {
            mode_stack.pop();
        }

        // Section openers
        if let Some(rest) = stripped.strip_prefix("interface ") {
            let name = rest.trim();
            check_interface_name(file, lno, indent + 11, name, &mut diags);
            if let Some((_, prev)) = seen_ifaces.iter().find(|(n, _)| n == name) {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    indent + 11,
                    Severity::Warning,
                    "EOS010",
                    format!(
                        "duplicate `interface {}` block (first at line {})",
                        name, prev
                    ),
                ));
            } else {
                seen_ifaces.push((name.to_string(), lno));
            }
            mode_stack.push((indent, format!("interface:{}", name)));
            continue;
        }

        if let Some(rest) = stripped.strip_prefix("router bgp ") {
            let asn = rest.trim();
            if !is_valid_asn(asn) {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    indent + 11,
                    Severity::Error,
                    "EOS020",
                    format!("invalid BGP ASN `{}`", asn),
                ));
            }
            mode_stack.push((indent, format!("router-bgp:{}", asn)));
            continue;
        }

        if stripped.starts_with("vrf ") || stripped == "vrf instance" {
            mode_stack.push((
                indent,
                stripped
                    .split_whitespace()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" "),
            ));
            continue;
        }

        // Statements within sections
        let current_mode = mode_stack.last().map(|(_, m)| m.as_str()).unwrap_or("");

        if let Some(rest) = stripped.strip_prefix("ip address ") {
            let cidr = rest.split_whitespace().next().unwrap_or("");
            if !cidr.is_empty() && !is_valid_ipv4_cidr(cidr) {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    indent + 11,
                    Severity::Error,
                    "EOS030",
                    format!("invalid IPv4 address `{}`", cidr),
                ));
            }
        } else if let Some(rest) = stripped.strip_prefix("ipv6 address ") {
            let cidr = rest.split_whitespace().next().unwrap_or("");
            if !cidr.is_empty() && !is_valid_ipv6_cidr(cidr) {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    indent + 13,
                    Severity::Error,
                    "EOS031",
                    format!("invalid IPv6 address `{}`", cidr),
                ));
            }
        } else if let Some(rest) = stripped.strip_prefix("neighbor ") {
            check_neighbor(file, lno, indent + 9, rest, current_mode, &mut diags);
        } else if let Some(rest) = stripped.strip_prefix("vlan ") {
            // top-level `vlan N` or `vlan N description ...`
            let id = rest.split_whitespace().next().unwrap_or("");
            if let Ok(n) = id.parse::<u32>() {
                if !(1..=4094).contains(&n) {
                    diags.push(Diagnostic::new(
                        file,
                        lno,
                        indent + 6,
                        Severity::Error,
                        "EOS060",
                        format!("VLAN id `{}` out of range [1, 4094]", n),
                    ));
                }
            }
        } else if let Some(rest) = stripped.strip_prefix("mtu ") {
            let v = rest.split_whitespace().next().unwrap_or("");
            if let Ok(n) = v.parse::<u32>() {
                if !(68..=9216).contains(&n) {
                    diags.push(Diagnostic::new(
                        file,
                        lno,
                        indent + 5,
                        Severity::Warning,
                        "EOS070",
                        format!("MTU `{}` outside typical range [68, 9216]", n),
                    ));
                }
            }
        } else if let Some(rest) = stripped.strip_prefix("switchport access vlan ") {
            let id = rest.split_whitespace().next().unwrap_or("");
            if let Ok(n) = id.parse::<u32>() {
                if !(1..=4094).contains(&n) {
                    diags.push(Diagnostic::new(
                        file,
                        lno,
                        indent + 24,
                        Severity::Error,
                        "EOS061",
                        format!("access VLAN `{}` out of range [1, 4094]", n),
                    ));
                }
            }
        }
    }

    diags
}

fn check_interface_name(
    file: &str,
    lno: usize,
    col: usize,
    name: &str,
    diags: &mut Vec<Diagnostic>,
) {
    if name.is_empty() {
        diags.push(Diagnostic::new(
            file,
            lno,
            col,
            Severity::Error,
            "EOS002",
            "missing interface name",
        ));
        return;
    }
    let kind = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '/' || c == '.');
    if !VALID_IFACE_KINDS.contains(&kind) {
        diags.push(Diagnostic::new(
            file,
            lno,
            col,
            Severity::Warning,
            "EOS003",
            format!("unknown interface kind in `{}`", name),
        ));
    }
}

fn check_neighbor(
    file: &str,
    lno: usize,
    col: usize,
    rest: &str,
    mode: &str,
    diags: &mut Vec<Diagnostic>,
) {
    if !mode.starts_with("router-bgp") {
        diags.push(Diagnostic::new(
            file,
            lno,
            col,
            Severity::Warning,
            "EOS040",
            "`neighbor` outside of `router bgp` block",
        ));
    }
    let mut parts = rest.split_whitespace();
    let peer = parts.next().unwrap_or("");
    let kw = parts.next().unwrap_or("");
    if kw == "remote-as" {
        let asn = parts.next().unwrap_or("");
        if !is_valid_asn(asn) {
            diags.push(Diagnostic::new(
                file,
                lno,
                col,
                Severity::Error,
                "EOS041",
                format!("invalid remote-as `{}` for neighbor {}", asn, peer),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::lint;
    use crate::diag::tests::{assert_clean, assert_emits, assert_silent};

    #[test]
    fn eos003_unknown_interface_kind() {
        assert_emits(&lint("f", "interface Bogus1\n"), "EOS003");
        assert_silent(&lint("f", "interface Ethernet1\n"), "EOS003");
    }

    #[test]
    fn eos010_duplicate_interface() {
        let src = "interface Ethernet1\n description x\n!\ninterface Ethernet1\n";
        assert_emits(&lint("f", src), "EOS010");
        let ok = "interface Ethernet1\n!\ninterface Ethernet2\n";
        assert_silent(&lint("f", ok), "EOS010");
    }

    #[test]
    fn eos020_invalid_bgp_asn() {
        assert_emits(&lint("f", "router bgp 4294967296\n"), "EOS020");
        assert_silent(&lint("f", "router bgp 65001\n"), "EOS020");
    }

    #[test]
    fn eos030_invalid_ip_address() {
        let bad = "interface Ethernet1\n   ip address 10.0.0.300/24\n";
        assert_emits(&lint("f", bad), "EOS030");
        let ok = "interface Ethernet1\n   ip address 10.0.0.1/24\n";
        assert_silent(&lint("f", ok), "EOS030");
    }

    #[test]
    fn eos040_neighbor_outside_bgp() {
        assert_emits(&lint("f", "neighbor 10.0.0.2 remote-as 65000\n"), "EOS040");
        let ok = "router bgp 65001\n   neighbor 10.0.0.2 remote-as 65000\n";
        assert_silent(&lint("f", ok), "EOS040");
    }

    #[test]
    fn eos060_vlan_out_of_range() {
        assert_emits(&lint("f", "vlan 5000 name x\n"), "EOS060");
        assert_silent(&lint("f", "vlan 100 name x\n"), "EOS060");
    }

    #[test]
    fn eos061_access_vlan_out_of_range() {
        let bad = "interface Ethernet1\n   switchport access vlan 5000\n";
        assert_emits(&lint("f", bad), "EOS061");
        let ok = "interface Ethernet1\n   switchport access vlan 100\n";
        assert_silent(&lint("f", ok), "EOS061");
    }

    #[test]
    fn eos070_mtu_out_of_range() {
        let bad = "interface Ethernet1\n   mtu 50\n";
        assert_emits(&lint("f", bad), "EOS070");
        let ok = "interface Ethernet1\n   mtu 9000\n";
        assert_silent(&lint("f", ok), "EOS070");
    }

    #[test]
    fn clean_real_world_shape() {
        let src = "hostname spine1\n!\ninterface Ethernet1\n   ip address 10.0.0.1/31\n!\nrouter bgp 65001\n   neighbor 10.0.0.0 remote-as 65002\n";
        assert_clean(&lint("f", src));
    }
}
