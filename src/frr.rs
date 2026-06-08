use crate::diag::{is_valid_asn, is_valid_ipv4_cidr, is_valid_ipv6_cidr, Diagnostic, Severity};

pub fn lint(file: &str, src: &str) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let mut mode_stack: Vec<(usize, String)> = Vec::new();
    let mut af_open: Option<usize> = None; // line where address-family was opened
                                           // Cross-reference tracking.
    let mut defined_route_maps: std::collections::HashSet<String> = Default::default();
    let mut defined_prefix_lists: std::collections::HashSet<String> = Default::default();
    let mut route_map_refs: Vec<(usize, String)> = Vec::new();
    let mut prefix_list_refs: Vec<(usize, String)> = Vec::new();

    for (i, raw_line) in src.lines().enumerate() {
        let lno = i + 1;
        let line = raw_line.trim_end();
        let stripped = line.trim_start();
        if stripped.is_empty() || stripped.starts_with('!') || stripped.starts_with('#') {
            continue;
        }
        let indent = line.len() - stripped.len();

        while mode_stack.last().is_some_and(|(ind, _)| *ind >= indent) {
            mode_stack.pop();
        }

        // Definitions: `route-map NAME ...` and `[ip|ipv6] prefix-list NAME ...`
        // Use token splitting so extra whitespace (e.g. column-aligned configs) parses correctly.
        let toks: Vec<&str> = stripped.split_whitespace().collect();
        match toks.as_slice() {
            ["route-map", name, ..] => {
                defined_route_maps.insert((*name).to_string());
            }
            ["ip" | "ipv6", "prefix-list", name, ..] => {
                defined_prefix_lists.insert((*name).to_string());
            }
            _ => {}
        }

        // References inside `neighbor` / `match` lines.
        if let Some(rest) = stripped.strip_prefix("neighbor ") {
            let toks: Vec<&str> = rest.split_whitespace().collect();
            // `neighbor X route-map NAME in|out`
            if let Some(idx) = toks.iter().position(|t| *t == "route-map") {
                if let Some(name) = toks.get(idx + 1) {
                    route_map_refs.push((lno, (*name).to_string()));
                }
            }
            // `neighbor X prefix-list NAME in|out`
            if let Some(idx) = toks.iter().position(|t| *t == "prefix-list") {
                if let Some(name) = toks.get(idx + 1) {
                    prefix_list_refs.push((lno, (*name).to_string()));
                }
            }
        }
        if let Some(rest) = stripped.strip_prefix("match ip address prefix-list ") {
            if let Some(name) = rest.split_whitespace().next() {
                prefix_list_refs.push((lno, name.to_string()));
            }
        }
        if let Some(rest) = stripped.strip_prefix("match ipv6 address prefix-list ") {
            if let Some(name) = rest.split_whitespace().next() {
                prefix_list_refs.push((lno, name.to_string()));
            }
        }

        if let Some(rest) = stripped.strip_prefix("router bgp ") {
            let asn = rest.split_whitespace().next().unwrap_or("");
            if !is_valid_asn(asn) {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    indent + 11,
                    Severity::Error,
                    "FRR020",
                    format!("invalid BGP ASN `{}`", asn),
                ));
            }
            mode_stack.push((indent, format!("router-bgp:{}", asn)));
            continue;
        }

        if stripped.starts_with("router ospf")
            || stripped.starts_with("router ospf6")
            || stripped.starts_with("router rip")
            || stripped.starts_with("router isis")
        {
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

        if let Some(rest) = stripped.strip_prefix("interface ") {
            mode_stack.push((indent, format!("interface:{}", rest.trim())));
            continue;
        }

        let current_mode = mode_stack.last().map(|(_, m)| m.as_str()).unwrap_or("");

        if let Some(rest) = stripped.strip_prefix("address-family ") {
            if !current_mode.starts_with("router-") {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    indent + 1,
                    Severity::Error,
                    "FRR050",
                    "`address-family` outside a routing protocol block",
                ));
            }
            if af_open.is_some() {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    indent + 1,
                    Severity::Error,
                    "FRR051",
                    "nested `address-family` without matching `exit-address-family`",
                ));
            }
            af_open = Some(lno);
            let _ = rest;
            continue;
        }
        if stripped == "exit-address-family" {
            if af_open.is_none() {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    indent + 1,
                    Severity::Error,
                    "FRR052",
                    "`exit-address-family` with no matching opener",
                ));
            }
            af_open = None;
            continue;
        }

        if let Some(rest) = stripped.strip_prefix("neighbor ") {
            check_neighbor(file, lno, indent + 9, rest, current_mode, &mut diags);
        } else if let Some(rest) = stripped.strip_prefix("network ") {
            let cidr = rest.split_whitespace().next().unwrap_or("");
            if !cidr.is_empty() && !is_valid_ipv4_cidr(cidr) && !is_valid_ipv6_cidr(cidr) {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    indent + 8,
                    Severity::Error,
                    "FRR060",
                    format!("invalid network prefix `{}`", cidr),
                ));
            }
        } else if let Some(rest) = stripped.strip_prefix("ip address ") {
            let cidr = rest.split_whitespace().next().unwrap_or("");
            if !cidr.is_empty() && !is_valid_ipv4_cidr(cidr) {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    indent + 11,
                    Severity::Error,
                    "FRR030",
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
                    "FRR031",
                    format!("invalid IPv6 address `{}`", cidr),
                ));
            }
        } else if let Some(rest) = stripped.strip_prefix("ip route ") {
            let cidr = rest.split_whitespace().next().unwrap_or("");
            if !cidr.is_empty() && !is_valid_ipv4_cidr(cidr) {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    indent + 9,
                    Severity::Error,
                    "FRR032",
                    format!("invalid IPv4 route prefix `{}`", cidr),
                ));
            }
        } else if let Some(rest) = stripped.strip_prefix("ipv6 route ") {
            let cidr = rest.split_whitespace().next().unwrap_or("");
            if !cidr.is_empty() && !is_valid_ipv6_cidr(cidr) {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    indent + 11,
                    Severity::Error,
                    "FRR033",
                    format!("invalid IPv6 route prefix `{}`", cidr),
                ));
            }
        } else if let Some(rest) = stripped.strip_prefix("ip prefix-list ") {
            // `ip prefix-list NAME seq N permit|deny PREFIX [le N] [ge N]`
            if let Some(prefix) = rest.split_whitespace().find(|t| t.contains('/')) {
                if !is_valid_ipv4_cidr(prefix) {
                    diags.push(Diagnostic::new(
                        file,
                        lno,
                        indent + 15,
                        Severity::Error,
                        "FRR034",
                        format!("invalid IPv4 prefix `{}` in prefix-list", prefix),
                    ));
                }
            }
        } else if let Some(rest) = stripped.strip_prefix("ipv6 prefix-list ") {
            if let Some(prefix) = rest.split_whitespace().find(|t| t.contains('/')) {
                if !is_valid_ipv6_cidr(prefix) {
                    diags.push(Diagnostic::new(
                        file,
                        lno,
                        indent + 17,
                        Severity::Error,
                        "FRR035",
                        format!("invalid IPv6 prefix `{}` in prefix-list", prefix),
                    ));
                }
            }
        }
    }

    if let Some(open_line) = af_open {
        diags.push(Diagnostic::new(
            file,
            open_line,
            1,
            Severity::Error,
            "FRR053",
            "`address-family` block not closed with `exit-address-family`",
        ));
    }

    // Cross-file refs are common (definitions in included files or VyOS frr.conf.d).
    // Emit as Hint so they're discoverable but don't break exit codes by default.
    for (lno, name) in &route_map_refs {
        if !defined_route_maps.contains(name) {
            diags.push(Diagnostic::new(
                file,
                *lno,
                1,
                Severity::Hint,
                "FRR070",
                format!(
                    "`route-map {}` referenced but not defined in this file (defined elsewhere?)",
                    name
                ),
            ));
        }
    }
    for (lno, name) in &prefix_list_refs {
        if !defined_prefix_lists.contains(name) {
            diags.push(Diagnostic::new(
                file,
                *lno,
                1,
                Severity::Hint,
                "FRR071",
                format!(
                    "`prefix-list {}` referenced but not defined in this file (defined elsewhere?)",
                    name
                ),
            ));
        }
    }

    diags
}

fn check_neighbor(
    file: &str,
    lno: usize,
    col: usize,
    rest: &str,
    mode: &str,
    diags: &mut Vec<Diagnostic>,
) {
    if !mode.starts_with("router-") {
        diags.push(Diagnostic::new(
            file,
            lno,
            col,
            Severity::Warning,
            "FRR040",
            "`neighbor` outside of a routing protocol block",
        ));
    }
    let mut parts = rest.split_whitespace();
    let peer = parts.next().unwrap_or("");
    let kw = parts.next().unwrap_or("");
    if kw == "remote-as" {
        let asn = parts.next().unwrap_or("");
        // remote-as accepts "internal" / "external" too in FRR
        if asn != "internal" && asn != "external" && !is_valid_asn(asn) {
            diags.push(Diagnostic::new(
                file,
                lno,
                col,
                Severity::Error,
                "FRR041",
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
    fn frr020_invalid_asn() {
        assert_emits(&lint("f", "router bgp NaN\n"), "FRR020");
        assert_silent(&lint("f", "router bgp 65001\n"), "FRR020");
    }

    #[test]
    fn frr030_invalid_ip_address() {
        assert_emits(
            &lint("f", "interface eth0\n ip address 10.0.0.300/24\n"),
            "FRR030",
        );
        assert_silent(
            &lint("f", "interface eth0\n ip address 10.0.0.1/24\n"),
            "FRR030",
        );
    }

    #[test]
    fn frr031_invalid_ipv6_address() {
        assert_emits(
            &lint("f", "interface eth0\n ipv6 address 2001:db8:xx::/64\n"),
            "FRR031",
        );
        assert_silent(
            &lint("f", "interface eth0\n ipv6 address 2001:db8::1/64\n"),
            "FRR031",
        );
    }

    #[test]
    fn frr032_invalid_ip_route_prefix() {
        assert_emits(&lint("f", "ip route 1.2.3.4/40 Null0\n"), "FRR032");
        assert_silent(&lint("f", "ip route 10.0.0.0/8 Null0\n"), "FRR032");
    }

    #[test]
    fn frr033_invalid_ipv6_route_prefix() {
        assert_emits(
            &lint("f", "ipv6 route 2001:db8:dexd::/48 Null0\n"),
            "FRR033",
        );
        assert_silent(
            &lint("f", "ipv6 route 2001:db8:dead::/48 Null0\n"),
            "FRR033",
        );
    }

    #[test]
    fn frr034_invalid_ipv4_prefix_list() {
        assert_emits(
            &lint("f", "ip prefix-list FOO seq 10 permit 999.0.0.0/8\n"),
            "FRR034",
        );
        assert_silent(
            &lint("f", "ip prefix-list FOO seq 10 permit 10.0.0.0/8\n"),
            "FRR034",
        );
    }

    #[test]
    fn frr035_invalid_ipv6_prefix_list() {
        assert_emits(
            &lint("f", "ipv6 prefix-list V6 seq 10 permit 2001:db8:zz::/48\n"),
            "FRR035",
        );
        assert_silent(
            &lint("f", "ipv6 prefix-list V6 seq 10 permit 2001:db8::/48\n"),
            "FRR035",
        );
    }

    #[test]
    fn frr041_invalid_remote_as() {
        let src = "router bgp 65001\n neighbor 10.0.0.2 remote-as junk\n";
        assert_emits(&lint("f", src), "FRR041");
        let ok = "router bgp 65001\n neighbor 10.0.0.2 remote-as 65002\n";
        assert_silent(&lint("f", ok), "FRR041");
        let internal = "router bgp 65001\n neighbor 10.0.0.2 remote-as internal\n";
        assert_silent(&lint("f", internal), "FRR041");
    }

    #[test]
    fn frr050_address_family_outside_router() {
        assert_emits(&lint("f", "address-family ipv4 unicast\n"), "FRR050");
        let ok = "router bgp 65001\n address-family ipv4 unicast\n exit-address-family\n";
        assert_silent(&lint("f", ok), "FRR050");
    }

    #[test]
    fn frr053_unclosed_address_family() {
        let bad = "router bgp 65001\n address-family ipv4 unicast\n  network 10.0.0.0/8\n";
        assert_emits(&lint("f", bad), "FRR053");
        let ok = "router bgp 65001\n address-family ipv4 unicast\n exit-address-family\n";
        assert_silent(&lint("f", ok), "FRR053");
    }

    #[test]
    fn frr070_route_map_referenced_but_undefined() {
        let bad = "router bgp 65001\n neighbor 10.0.0.2 remote-as 65002\n neighbor 10.0.0.2 route-map MISSING in\n";
        assert_emits(&lint("f", bad), "FRR070");
        let ok = "route-map IN permit 10\n!\nrouter bgp 65001\n neighbor 10.0.0.2 remote-as 65002\n neighbor 10.0.0.2 route-map IN in\n";
        assert_silent(&lint("f", ok), "FRR070");
    }

    #[test]
    fn frr071_prefix_list_referenced_but_undefined() {
        let bad = "route-map IN permit 10\n match ip address prefix-list MISSING\n";
        assert_emits(&lint("f", bad), "FRR071");
        let ok = "ip prefix-list BOGON seq 10 permit 0.0.0.0/8\n!\nroute-map IN permit 10\n match ip address prefix-list BOGON\n";
        assert_silent(&lint("f", ok), "FRR071");
    }

    #[test]
    fn prefix_list_def_with_extra_whitespace_recognised() {
        // Column-aligned configs use multiple spaces between tokens.
        let ok = "ip   prefix-list  AMSIX    seq 10 permit 80.249.208.0/21 le 32\n!\nroute-map IN permit 10\n match ip address prefix-list AMSIX\n";
        assert_silent(&lint("f", ok), "FRR071");
    }

    #[test]
    fn clean_real_world_shape() {
        let src = "frr version 10.2\nhostname r1\n!\nrouter bgp 65001\n neighbor 192.0.2.2 remote-as 65002\n address-family ipv4 unicast\n  network 198.51.100.0/24\n exit-address-family\nend\n";
        assert_clean(&lint("f", src));
    }
}
