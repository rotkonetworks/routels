// Linter for WireGuard (wg-quick) configs.
//
// INI-like: `[Interface]` and `[Peer]` sections. Keys are case-sensitive in
// wg-quick (`Address` not `address`). `wg(8)` itself is case-insensitive for
// the kernel keys, but wg-quick parses these literal capitalised names.

use crate::diag::{
    is_valid_ipv4, is_valid_ipv4_cidr, is_valid_ipv6, is_valid_ipv6_cidr, Diagnostic, Severity,
};

const INTERFACE_KEYS: &[&str] = &[
    "PrivateKey",
    "ListenPort",
    "FwMark",
    "Address",
    "DNS",
    "MTU",
    "Table",
    "PreUp",
    "PostUp",
    "PreDown",
    "PostDown",
    "SaveConfig",
];
const PEER_KEYS: &[&str] = &[
    "PublicKey",
    "PresharedKey",
    "AllowedIPs",
    "Endpoint",
    "PersistentKeepalive",
];

#[derive(Copy, Clone, PartialEq, Eq)]
enum Section {
    None,
    Interface,
    Peer,
}

pub fn lint(file: &str, src: &str) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let mut section = Section::None;
    let mut iface_seen = false;
    let mut iface_has_privatekey = false;
    let mut iface_has_address = false;
    let mut peer_idx = 0usize;
    let mut peer_has_pubkey = false;
    let mut peer_has_allowedips = false;
    let mut peer_open_line = 0usize;
    // Cross-reference: detect peer duplicates.
    let mut seen_pubkeys: std::collections::HashMap<String, (usize, usize)> = Default::default();
    let mut seen_allowed: std::collections::HashMap<String, (usize, usize)> = Default::default();

    let finish_peer = |peer_idx: usize,
                       peer_open_line: usize,
                       peer_has_pubkey: bool,
                       peer_has_allowedips: bool,
                       diags: &mut Vec<Diagnostic>| {
        if peer_idx == 0 {
            return;
        }
        if !peer_has_pubkey {
            diags.push(Diagnostic::new(
                file.to_string(),
                peer_open_line,
                1,
                Severity::Error,
                "WG010",
                format!("[Peer] block #{} is missing required `PublicKey`", peer_idx),
            ));
        }
        if !peer_has_allowedips {
            diags.push(Diagnostic::new(
                file.to_string(),
                peer_open_line,
                1,
                Severity::Warning,
                "WG011",
                format!(
                    "[Peer] block #{} has no `AllowedIPs` (peer can't route traffic)",
                    peer_idx
                ),
            ));
        }
    };

    for (i, raw) in src.lines().enumerate() {
        let lno = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            // Close out the previous peer
            if section == Section::Peer {
                finish_peer(
                    peer_idx,
                    peer_open_line,
                    peer_has_pubkey,
                    peer_has_allowedips,
                    &mut diags,
                );
            }
            match name {
                "Interface" => {
                    if iface_seen {
                        diags.push(Diagnostic::new(
                            file,
                            lno,
                            1,
                            Severity::Error,
                            "WG001",
                            "duplicate [Interface] section",
                        ));
                    }
                    iface_seen = true;
                    section = Section::Interface;
                }
                "Peer" => {
                    section = Section::Peer;
                    peer_idx += 1;
                    peer_open_line = lno;
                    peer_has_pubkey = false;
                    peer_has_allowedips = false;
                }
                _ => {
                    diags.push(Diagnostic::new(
                        file,
                        lno,
                        1,
                        Severity::Error,
                        "WG002",
                        format!(
                            "unknown section `[{}]` (expected [Interface] or [Peer])",
                            name
                        ),
                    ));
                    section = Section::None;
                }
            }
            continue;
        }

        // key = value
        let Some((key, val)) = line.split_once('=') else {
            diags.push(Diagnostic::new(
                file,
                lno,
                1,
                Severity::Error,
                "WG020",
                "expected `Key = value`",
            ));
            continue;
        };
        let key = key.trim();
        let val = val.trim();

        match section {
            Section::None => {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    1,
                    Severity::Error,
                    "WG003",
                    format!("`{}` outside any section", key),
                ));
            }
            Section::Interface => {
                if !INTERFACE_KEYS.contains(&key) {
                    diags.push(Diagnostic::new(
                        file,
                        lno,
                        1,
                        Severity::Warning,
                        "WG030",
                        format!("unknown [Interface] key `{}`", key),
                    ));
                }
                if key == "PrivateKey" {
                    iface_has_privatekey = true;
                    check_b64key(file, lno, val, "PrivateKey", &mut diags);
                }
                if key == "Address" {
                    iface_has_address = true;
                    check_cidr_list(file, lno, val, "Address", &mut diags);
                }
                if key == "DNS" {
                    check_ip_list(file, lno, val, "DNS", &mut diags);
                }
                if key == "ListenPort" {
                    check_port(file, lno, val, "ListenPort", &mut diags);
                }
                if key == "MTU" {
                    check_int_range(file, lno, val, 576, 9216, "MTU", &mut diags);
                }
            }
            Section::Peer => {
                if !PEER_KEYS.contains(&key) {
                    diags.push(Diagnostic::new(
                        file,
                        lno,
                        1,
                        Severity::Warning,
                        "WG031",
                        format!("unknown [Peer] key `{}`", key),
                    ));
                }
                if key == "PublicKey" {
                    peer_has_pubkey = true;
                    check_b64key(file, lno, val, "PublicKey", &mut diags);
                    if let Some((prev_idx, prev_line)) = seen_pubkeys.get(val) {
                        diags.push(Diagnostic::new(
                            file,
                            lno,
                            1,
                            Severity::Error,
                            "WG090",
                            format!(
                                "duplicate `PublicKey` in peer #{} (first in peer #{} at line {})",
                                peer_idx, prev_idx, prev_line
                            ),
                        ));
                    } else {
                        seen_pubkeys.insert(val.to_string(), (peer_idx, lno));
                    }
                }
                if key == "PresharedKey" {
                    check_b64key(file, lno, val, "PresharedKey", &mut diags);
                }
                if key == "AllowedIPs" {
                    peer_has_allowedips = true;
                    check_cidr_list(file, lno, val, "AllowedIPs", &mut diags);
                    for raw in val.split(',') {
                        let cidr = raw.trim();
                        if cidr.is_empty() {
                            continue;
                        }
                        if let Some((prev_idx, prev_line)) = seen_allowed.get(cidr) {
                            diags.push(Diagnostic::new(
                                file,
                                lno,
                                1,
                                Severity::Warning,
                                "WG091",
                                format!(
                                    "AllowedIP `{}` already claimed by peer #{} (line {}) — routes will conflict",
                                    cidr, prev_idx, prev_line
                                ),
                            ));
                        } else {
                            seen_allowed.insert(cidr.to_string(), (peer_idx, lno));
                        }
                    }
                }
                if key == "Endpoint" {
                    check_endpoint(file, lno, val, &mut diags);
                }
                if key == "PersistentKeepalive" {
                    check_int_range(file, lno, val, 1, 65535, "PersistentKeepalive", &mut diags);
                }
            }
        }
    }

    // Close the trailing peer
    if section == Section::Peer {
        finish_peer(
            peer_idx,
            peer_open_line,
            peer_has_pubkey,
            peer_has_allowedips,
            &mut diags,
        );
    }

    if iface_seen && !iface_has_privatekey {
        diags.push(Diagnostic::new(
            file,
            0,
            1,
            Severity::Error,
            "WG040",
            "[Interface] is missing required `PrivateKey`",
        ));
    }
    if iface_seen && !iface_has_address {
        diags.push(Diagnostic::new(
            file,
            0,
            1,
            Severity::Warning,
            "WG041",
            "[Interface] has no `Address` (tunnel will have no L3 endpoint)",
        ));
    }
    if !iface_seen {
        diags.push(Diagnostic::new(
            file,
            0,
            1,
            Severity::Error,
            "WG042",
            "no [Interface] section",
        ));
    }
    diags
}

fn check_b64key(file: &str, lno: usize, val: &str, kind: &str, diags: &mut Vec<Diagnostic>) {
    // Tolerate placeholder values that obviously aren't keys.
    if val.starts_with('<') && val.ends_with('>') {
        return;
    }
    // wg keys: 32 bytes base64 → 44 chars, trailing '='.
    let bad = val.len() != 44
        || !val.ends_with('=')
        || !val
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    if bad {
        diags.push(Diagnostic::new(
            file,
            lno,
            1,
            Severity::Error,
            "WG050",
            format!("`{}` is not a valid 44-char base64 wg key", kind),
        ));
    }
}

fn check_cidr_list(file: &str, lno: usize, val: &str, key: &str, diags: &mut Vec<Diagnostic>) {
    for raw in val.split(',') {
        let v = raw.trim();
        if v.is_empty() {
            continue;
        }
        if !is_valid_ipv4_cidr(v) && !is_valid_ipv6_cidr(v) {
            diags.push(Diagnostic::new(
                file,
                lno,
                1,
                Severity::Error,
                "WG060",
                format!("invalid CIDR `{}` in `{}`", v, key),
            ));
        }
    }
}

fn check_ip_list(file: &str, lno: usize, val: &str, key: &str, diags: &mut Vec<Diagnostic>) {
    for raw in val.split(',') {
        let v = raw.trim();
        if v.is_empty() {
            continue;
        }
        if !is_valid_ipv4(v) && !is_valid_ipv6(v) {
            diags.push(Diagnostic::new(
                file,
                lno,
                1,
                Severity::Error,
                "WG061",
                format!("invalid IP `{}` in `{}`", v, key),
            ));
        }
    }
}

fn check_endpoint(file: &str, lno: usize, val: &str, diags: &mut Vec<Diagnostic>) {
    // host:port — host may be hostname, IPv4, or [IPv6]
    let (host, port) = if let Some(rest) = val.strip_prefix('[') {
        match rest.split_once("]:") {
            Some((h, p)) => (h.to_string(), p.to_string()),
            None => {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    1,
                    Severity::Error,
                    "WG070",
                    "malformed bracketed IPv6 endpoint, expected `[v6]:port`",
                ));
                return;
            }
        }
    } else {
        match val.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.to_string()),
            None => {
                diags.push(Diagnostic::new(
                    file,
                    lno,
                    1,
                    Severity::Error,
                    "WG071",
                    "endpoint missing `:port`",
                ));
                return;
            }
        }
    };
    match port.parse::<u16>() {
        Ok(0) | Err(_) => diags.push(Diagnostic::new(
            file,
            lno,
            1,
            Severity::Error,
            "WG072",
            format!("invalid port `{}` in Endpoint", port),
        )),
        Ok(_) => {}
    }
    // Host: accept IPv4, IPv6, or hostname (alnum + - + . , at least one .).
    if !is_valid_ipv4(&host) && !is_valid_ipv6(&host) {
        let looks_hostname = !host.is_empty()
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
        if !looks_hostname {
            diags.push(Diagnostic::new(
                file,
                lno,
                1,
                Severity::Error,
                "WG073",
                format!("invalid host `{}` in Endpoint", host),
            ));
        }
    }
}

fn check_port(file: &str, lno: usize, val: &str, key: &str, diags: &mut Vec<Diagnostic>) {
    match val.parse::<u16>() {
        Ok(0) | Err(_) => diags.push(Diagnostic::new(
            file,
            lno,
            1,
            Severity::Error,
            "WG080",
            format!("invalid port `{}` for `{}`", val, key),
        )),
        Ok(_) => {}
    }
}

fn check_int_range(
    file: &str,
    lno: usize,
    val: &str,
    min: u32,
    max: u32,
    key: &str,
    diags: &mut Vec<Diagnostic>,
) {
    match val.parse::<u32>() {
        Ok(n) if (min..=max).contains(&n) => {}
        _ => diags.push(Diagnostic::new(
            file,
            lno,
            1,
            Severity::Error,
            "WG081",
            format!("`{}`={} out of range [{}, {}]", key, val, min, max),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::lint;
    use crate::diag::tests::{assert_clean, assert_emits, assert_silent};

    const GOOD: &str = "[Interface]\nAddress = 10.0.0.1/24\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nListenPort = 51820\n\n[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\nEndpoint = peer.example.com:51820\nAllowedIPs = 10.0.0.2/32\n";

    #[test]
    fn wg002_unknown_section() {
        assert_emits(&lint("f", "[Bogus]\nAddress = 10.0.0.1/24\n"), "WG002");
        assert_silent(&lint("f", GOOD), "WG002");
    }

    #[test]
    fn wg010_peer_missing_pubkey() {
        let bad = "[Interface]\nAddress = 10.0.0.1/24\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n[Peer]\nAllowedIPs = 10.0.0.2/32\n";
        assert_emits(&lint("f", bad), "WG010");
        assert_silent(&lint("f", GOOD), "WG010");
    }

    #[test]
    fn wg042_no_interface_section() {
        assert_emits(&lint("f", "[Peer]\nPublicKey = AAA\n"), "WG042");
        assert_silent(&lint("f", GOOD), "WG042");
    }

    #[test]
    fn wg050_invalid_b64_key() {
        let bad = "[Interface]\nAddress = 10.0.0.1/24\nPrivateKey = nope-not-b64\n";
        assert_emits(&lint("f", bad), "WG050");
        assert_silent(&lint("f", GOOD), "WG050");
    }

    #[test]
    fn wg060_invalid_allowedips_cidr() {
        let bad = "[Interface]\nAddress = 10.0.0.1/24\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\nAllowedIPs = not-a-cidr\n";
        assert_emits(&lint("f", bad), "WG060");
        assert_silent(&lint("f", GOOD), "WG060");
    }

    #[test]
    fn wg071_endpoint_missing_port() {
        let bad = "[Interface]\nAddress = 10.0.0.1/24\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\nAllowedIPs = 10.0.0.2/32\nEndpoint = peer.example.com\n";
        assert_emits(&lint("f", bad), "WG071");
        assert_silent(&lint("f", GOOD), "WG071");
    }

    #[test]
    fn wg090_duplicate_pubkey() {
        let bad = "[Interface]\nAddress = 10.0.0.1/24\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\nAllowedIPs = 10.0.0.2/32\n[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\nAllowedIPs = 10.0.0.3/32\n";
        assert_emits(&lint("f", bad), "WG090");
        assert_silent(&lint("f", GOOD), "WG090");
    }

    #[test]
    fn wg091_duplicate_allowedip() {
        let bad = "[Interface]\nAddress = 10.0.0.1/24\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\nAllowedIPs = 10.0.0.2/32\n[Peer]\nPublicKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=\nAllowedIPs = 10.0.0.2/32\n";
        assert_emits(&lint("f", bad), "WG091");
        assert_silent(&lint("f", GOOD), "WG091");
    }

    #[test]
    fn clean_minimal() {
        assert_clean(&lint("f", GOOD));
    }
}
