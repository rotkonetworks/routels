// Registry of all diagnostic codes routels can emit.
//
// One row per code with a one-line description. Kept here (rather than scattered
// across linter modules) so users can `routels --list-rules` to discover what
// the linter actually checks.

pub struct Rule {
    pub code: &'static str,
    pub platform: &'static str,
    pub description: &'static str,
}

pub const RULES: &[Rule] = &[
    // ---- EOS ----
    Rule {
        code: "EOS001",
        platform: "eos",
        description: "tab indentation (EOS uses spaces)",
    },
    Rule {
        code: "EOS002",
        platform: "eos",
        description: "missing interface name",
    },
    Rule {
        code: "EOS003",
        platform: "eos",
        description: "unknown interface kind",
    },
    Rule {
        code: "EOS010",
        platform: "eos",
        description: "duplicate `interface` block",
    },
    Rule {
        code: "EOS020",
        platform: "eos",
        description: "invalid BGP ASN",
    },
    Rule {
        code: "EOS030",
        platform: "eos",
        description: "invalid IPv4 address",
    },
    Rule {
        code: "EOS031",
        platform: "eos",
        description: "invalid IPv6 address",
    },
    Rule {
        code: "EOS040",
        platform: "eos",
        description: "`neighbor` outside of `router bgp` block",
    },
    Rule {
        code: "EOS041",
        platform: "eos",
        description: "invalid remote-as for neighbor",
    },
    Rule {
        code: "EOS060",
        platform: "eos",
        description: "VLAN id out of [1,4094] range",
    },
    Rule {
        code: "EOS061",
        platform: "eos",
        description: "access VLAN out of [1,4094] range",
    },
    Rule {
        code: "EOS070",
        platform: "eos",
        description: "MTU outside typical [68,9216] range",
    },
    // ---- FRR ----
    Rule {
        code: "FRR020",
        platform: "frr",
        description: "invalid BGP ASN",
    },
    Rule {
        code: "FRR030",
        platform: "frr",
        description: "invalid IPv4 address",
    },
    Rule {
        code: "FRR031",
        platform: "frr",
        description: "invalid IPv6 address",
    },
    Rule {
        code: "FRR032",
        platform: "frr",
        description: "invalid IPv4 route prefix",
    },
    Rule {
        code: "FRR033",
        platform: "frr",
        description: "invalid IPv6 route prefix",
    },
    Rule {
        code: "FRR034",
        platform: "frr",
        description: "invalid IPv4 prefix in prefix-list",
    },
    Rule {
        code: "FRR035",
        platform: "frr",
        description: "invalid IPv6 prefix in prefix-list",
    },
    Rule {
        code: "FRR040",
        platform: "frr",
        description: "`neighbor` outside a routing protocol block",
    },
    Rule {
        code: "FRR041",
        platform: "frr",
        description: "invalid remote-as for neighbor",
    },
    Rule {
        code: "FRR050",
        platform: "frr",
        description: "`address-family` outside a routing protocol block",
    },
    Rule {
        code: "FRR051",
        platform: "frr",
        description: "nested `address-family` without `exit-address-family`",
    },
    Rule {
        code: "FRR052",
        platform: "frr",
        description: "`exit-address-family` with no matching opener",
    },
    Rule {
        code: "FRR053",
        platform: "frr",
        description: "`address-family` block not closed",
    },
    Rule {
        code: "FRR060",
        platform: "frr",
        description: "invalid network prefix",
    },
    Rule {
        code: "FRR070",
        platform: "frr",
        description: "route-map referenced but not defined in this file",
    },
    Rule {
        code: "FRR071",
        platform: "frr",
        description: "prefix-list referenced but not defined in this file",
    },
    // ---- VyOS ----
    Rule {
        code: "VYO010",
        platform: "vyos",
        description: "unbalanced quotes (set form)",
    },
    Rule {
        code: "VYO011",
        platform: "vyos",
        description: "verb with no path (set form)",
    },
    Rule {
        code: "VYO012",
        platform: "vyos",
        description: "unknown root node",
    },
    Rule {
        code: "VYO013",
        platform: "vyos",
        description: "unknown verb (set form)",
    },
    Rule {
        code: "VYO020",
        platform: "vyos",
        description: "invalid prefix in set-form leaf",
    },
    Rule {
        code: "VYO030",
        platform: "vyos",
        description: "unbalanced quotes (curly form)",
    },
    Rule {
        code: "VYO031",
        platform: "vyos",
        description: "unexpected `}` (curly form)",
    },
    Rule {
        code: "VYO032",
        platform: "vyos",
        description: "unknown root node (curly form)",
    },
    Rule {
        code: "VYO033",
        platform: "vyos",
        description: "invalid prefix in curly-form leaf",
    },
    Rule {
        code: "VYO034",
        platform: "vyos",
        description: "unclosed `{` block (curly form)",
    },
    // ---- MikroTik / RouterOS ----
    Rule {
        code: "ROS010",
        platform: "mikrotik",
        description: "unbalanced brackets/braces/quotes",
    },
    Rule {
        code: "ROS011",
        platform: "mikrotik",
        description: "unknown root path",
    },
    Rule {
        code: "ROS020",
        platform: "mikrotik",
        description: "unknown verb",
    },
    Rule {
        code: "ROS030",
        platform: "mikrotik",
        description: "invalid prefix in address-bearing key",
    },
    Rule {
        code: "ROS031",
        platform: "mikrotik",
        description: "invalid address in address-bearing key",
    },
    Rule {
        code: "ROS040",
        platform: "mikrotik",
        description: "invalid MAC address",
    },
    Rule {
        code: "ROS041",
        platform: "mikrotik",
        description: "invalid port spec in dst-port/src-port/port",
    },
    // ---- BIRD ----
    Rule {
        code: "BIR010",
        platform: "bird",
        description: "unexpected `}`",
    },
    Rule {
        code: "BIR011",
        platform: "bird",
        description: "unclosed `{` block",
    },
    Rule {
        code: "BIR020",
        platform: "bird",
        description: "unknown protocol kind",
    },
    Rule {
        code: "BIR030",
        platform: "bird",
        description: "invalid route prefix",
    },
    Rule {
        code: "BIR031",
        platform: "bird",
        description: "route references undefined symbol (or missed include)",
    },
    Rule {
        code: "BIR040",
        platform: "bird",
        description: "statement missing trailing `;`",
    },
    Rule {
        code: "BIR050",
        platform: "bird",
        description: "invalid `local as` ASN",
    },
    Rule {
        code: "BIR051",
        platform: "bird",
        description: "invalid `neighbor ... as` ASN",
    },
    // ---- nftables / iptables ----
    Rule {
        code: "NFT010",
        platform: "nft",
        description: "unexpected `}`",
    },
    Rule {
        code: "NFT011",
        platform: "nft",
        description: "unclosed `{` block",
    },
    Rule {
        code: "NFT020",
        platform: "nft",
        description: "unknown nftables family",
    },
    Rule {
        code: "NFT021",
        platform: "nft",
        description: "unknown hook",
    },
    Rule {
        code: "IPT010",
        platform: "nft",
        description: "iptables table opened before previous COMMIT",
    },
    Rule {
        code: "IPT011",
        platform: "nft",
        description: "iptables COMMIT with no open table",
    },
    Rule {
        code: "IPT012",
        platform: "nft",
        description: "iptables table not closed with COMMIT",
    },
    Rule {
        code: "IPT020",
        platform: "nft",
        description: "iptables chain declaration missing policy",
    },
    Rule {
        code: "IPT021",
        platform: "nft",
        description: "iptables unusual chain policy",
    },
    Rule {
        code: "IPT030",
        platform: "nft",
        description: "iptables unknown built-in target",
    },
    // ---- Debian /etc/network/interfaces ----
    Rule {
        code: "DEB010",
        platform: "debian",
        description: "`iface` missing NAME FAMILY METHOD",
    },
    Rule {
        code: "DEB011",
        platform: "debian",
        description: "unknown address family",
    },
    Rule {
        code: "DEB012",
        platform: "debian",
        description: "unknown method",
    },
    Rule {
        code: "DEB013",
        platform: "debian",
        description: "source/source-directory needs a path",
    },
    Rule {
        code: "DEB020",
        platform: "debian",
        description: "invalid address",
    },
    Rule {
        code: "DEB021",
        platform: "debian",
        description: "invalid gateway",
    },
    Rule {
        code: "DEB022",
        platform: "debian",
        description: "invalid netmask",
    },
    Rule {
        code: "DEB023",
        platform: "debian",
        description: "invalid DNS server",
    },
    Rule {
        code: "DEB030",
        platform: "debian",
        description: "`auto NAME` has no matching `iface` stanza",
    },
    // ---- WireGuard ----
    Rule {
        code: "WG001",
        platform: "wireguard",
        description: "duplicate [Interface] section",
    },
    Rule {
        code: "WG002",
        platform: "wireguard",
        description: "unknown section (expected [Interface] or [Peer])",
    },
    Rule {
        code: "WG003",
        platform: "wireguard",
        description: "key outside any section",
    },
    Rule {
        code: "WG010",
        platform: "wireguard",
        description: "[Peer] missing required `PublicKey`",
    },
    Rule {
        code: "WG011",
        platform: "wireguard",
        description: "[Peer] missing `AllowedIPs`",
    },
    Rule {
        code: "WG020",
        platform: "wireguard",
        description: "expected `Key = value`",
    },
    Rule {
        code: "WG030",
        platform: "wireguard",
        description: "unknown [Interface] key",
    },
    Rule {
        code: "WG031",
        platform: "wireguard",
        description: "unknown [Peer] key",
    },
    Rule {
        code: "WG040",
        platform: "wireguard",
        description: "[Interface] missing required `PrivateKey`",
    },
    Rule {
        code: "WG041",
        platform: "wireguard",
        description: "[Interface] has no `Address`",
    },
    Rule {
        code: "WG042",
        platform: "wireguard",
        description: "no [Interface] section",
    },
    Rule {
        code: "WG050",
        platform: "wireguard",
        description: "invalid 44-char base64 wg key",
    },
    Rule {
        code: "WG060",
        platform: "wireguard",
        description: "invalid CIDR",
    },
    Rule {
        code: "WG061",
        platform: "wireguard",
        description: "invalid IP",
    },
    Rule {
        code: "WG070",
        platform: "wireguard",
        description: "malformed bracketed IPv6 endpoint",
    },
    Rule {
        code: "WG071",
        platform: "wireguard",
        description: "endpoint missing `:port`",
    },
    Rule {
        code: "WG072",
        platform: "wireguard",
        description: "invalid port in endpoint",
    },
    Rule {
        code: "WG073",
        platform: "wireguard",
        description: "invalid host in endpoint",
    },
    Rule {
        code: "WG080",
        platform: "wireguard",
        description: "invalid port",
    },
    Rule {
        code: "WG081",
        platform: "wireguard",
        description: "integer value out of range",
    },
    Rule {
        code: "WG090",
        platform: "wireguard",
        description: "duplicate PublicKey across peers",
    },
    Rule {
        code: "WG091",
        platform: "wireguard",
        description: "duplicate AllowedIP across peers (route conflict)",
    },
    // ---- HAproxy ----
    Rule {
        code: "HAP010",
        platform: "haproxy",
        description: "unknown section keyword",
    },
    Rule {
        code: "HAP020",
        platform: "haproxy",
        description: "invalid `mode` (expected http|tcp|health)",
    },
    Rule {
        code: "HAP030",
        platform: "haproxy",
        description: "timeout value doesn't look like a duration",
    },
    Rule {
        code: "HAP040",
        platform: "haproxy",
        description: "malformed bracketed IPv6",
    },
    Rule {
        code: "HAP041",
        platform: "haproxy",
        description: "host:port missing `:port`",
    },
    Rule {
        code: "HAP042",
        platform: "haproxy",
        description: "invalid port",
    },
    Rule {
        code: "HAP043",
        platform: "haproxy",
        description: "invalid host",
    },
    Rule {
        code: "HAP050",
        platform: "haproxy",
        description: "use_backend/default_backend references undefined backend",
    },
    Rule {
        code: "HAP060",
        platform: "haproxy",
        description: "frontend has no default_backend or use_backend (dead-end)",
    },
    Rule {
        code: "HAP070",
        platform: "haproxy",
        description: "ACL referenced via if/unless but not defined",
    },
    // ---- sysctl ----
    Rule {
        code: "SYS010",
        platform: "sysctl",
        description: "expected `key = value`",
    },
    Rule {
        code: "SYS011",
        platform: "sysctl",
        description: "empty key",
    },
    Rule {
        code: "SYS012",
        platform: "sysctl",
        description: "key has no `.` (sysctl keys are dotted)",
    },
    Rule {
        code: "SYS013",
        platform: "sysctl",
        description: "invalid char in key",
    },
    Rule {
        code: "SYS020",
        platform: "sysctl",
        description: "duplicate key",
    },
    Rule {
        code: "SYS030",
        platform: "sysctl",
        description: "boolean key with non-boolean value",
    },
    Rule {
        code: "SYS031",
        platform: "sysctl",
        description: "empty value",
    },
    // ---- Deep mode ----
    Rule {
        code: "DEEP000",
        platform: "deep",
        description: "--deep requires a file path (stdin not supported)",
    },
    Rule {
        code: "DEEP403",
        platform: "deep",
        description: "nft -c requires CAP_NET_ADMIN",
    },
    Rule {
        code: "DEEP404",
        platform: "deep",
        description: "validator not on PATH (skipping deep check)",
    },
    Rule {
        code: "DEEP900",
        platform: "deep",
        description: "deep check requires a running container",
    },
    Rule {
        code: "DEEP901",
        platform: "deep",
        description: "no offline validator exists for this platform",
    },
    Rule {
        code: "DEEP-FRR",
        platform: "deep",
        description: "diagnostic from vtysh -C -f",
    },
    Rule {
        code: "DEEP-NFT",
        platform: "deep",
        description: "diagnostic from nft -c -f",
    },
    Rule {
        code: "DEEP-IPT",
        platform: "deep",
        description: "diagnostic from iptables-restore --test",
    },
    Rule {
        code: "DEEP-BIRD",
        platform: "deep",
        description: "diagnostic from bird -p -c",
    },
    Rule {
        code: "DEEP-HAP",
        platform: "deep",
        description: "diagnostic from haproxy -c -f",
    },
    Rule {
        code: "DEEP-WG",
        platform: "deep",
        description: "diagnostic from wg-quick strip",
    },
];

pub fn list_rules() {
    let mut sorted: Vec<&Rule> = RULES.iter().collect();
    sorted.sort_by_key(|r| (r.platform, r.code));
    let mut current_platform = "";
    for r in sorted {
        if r.platform != current_platform {
            if !current_platform.is_empty() {
                println!();
            }
            println!("=== {} ===", r.platform);
            current_platform = r.platform;
        }
        println!("  {:9}  {}", r.code, r.description);
    }
}

pub fn explain(code: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.code.eq_ignore_ascii_case(code))
}
