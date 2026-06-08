// Static per-platform reference content for LSP hover and completion.
//
// Kept as plain `&[(&str, &str)]` so it costs nothing at startup and is
// easy to extend without touching the LSP plumbing.

#[derive(Copy, Clone)]
pub enum Kind {
    Eos,
    Frr,
    Vyos,
    Mikrotik,
    Bird,
    Nft,
    Debian,
    Wireguard,
    Haproxy,
    Sysctl,
}

pub fn hover_lookup(kind: Kind, token: &str) -> Option<&'static str> {
    table(kind)
        .iter()
        .find(|(k, _)| *k == token)
        .map(|(_, v)| *v)
}

pub fn completion_keywords(kind: Kind) -> &'static [(&'static str, &'static str)] {
    table(kind)
}

fn table(kind: Kind) -> &'static [(&'static str, &'static str)] {
    match kind {
        Kind::Eos => EOS,
        Kind::Frr => FRR,
        Kind::Vyos => VYOS,
        Kind::Mikrotik => MIKROTIK,
        Kind::Bird => BIRD,
        Kind::Nft => NFT,
        Kind::Debian => DEBIAN,
        Kind::Wireguard => WIREGUARD,
        Kind::Haproxy => HAPROXY,
        Kind::Sysctl => SYSCTL,
    }
}

// (keyword, one-line docs). Docs render as the hover body and as the
// completion `detail` slot.
const EOS: &[(&str, &str)] = &[
    (
        "interface",
        "Enter interface configuration mode (Ethernet, Loopback, Vlan, Port-Channel, ...).",
    ),
    (
        "router",
        "Enter routing-protocol configuration: `router bgp <asn>`, `router ospf <id>`, ...",
    ),
    (
        "vrf",
        "Define or enter a VRF (Virtual Routing and Forwarding) instance.",
    ),
    (
        "neighbor",
        "BGP neighbor configuration: `neighbor <ip> remote-as <asn>`.",
    ),
    (
        "ip",
        "IPv4 configuration: `ip address <cidr>`, `ip route <prefix> <next-hop>`.",
    ),
    (
        "ipv6",
        "IPv6 configuration: `ipv6 address <cidr>`, `ipv6 route ...`.",
    ),
    ("hostname", "Set the device hostname."),
    (
        "description",
        "Free-text description on the current interface or neighbor.",
    ),
    (
        "Ethernet",
        "Physical Ethernet interface (e.g. `interface Ethernet1`).",
    ),
    (
        "Loopback",
        "Software loopback interface (e.g. `interface Loopback0`).",
    ),
    ("Port-Channel", "LAG / link aggregation group interface."),
    ("Vlan", "SVI / VLAN interface."),
    ("Management", "Out-of-band management interface."),
];

const FRR: &[(&str, &str)] = &[
    (
        "router",
        "Routing-protocol block: `router bgp <asn>`, `router ospf`, `router isis`, ...",
    ),
    ("bgp", "BGP-4 routing process."),
    ("ospf", "OSPFv2 routing process."),
    ("ospf6", "OSPFv3 routing process."),
    ("isis", "IS-IS routing process."),
    (
        "address-family",
        "Enter an AF sub-block inside `router bgp`. Close with `exit-address-family`.",
    ),
    (
        "exit-address-family",
        "Close the current `address-family` sub-block.",
    ),
    (
        "neighbor",
        "BGP neighbor declaration: `neighbor <ip|peer-group> remote-as <asn|internal|external>`.",
    ),
    (
        "network",
        "Originate a prefix into the current address-family.",
    ),
    ("interface", "Per-interface configuration mode."),
    ("ip", "IPv4 statement (address, prefix-list, route, ...)."),
    ("ipv6", "IPv6 statement (address, prefix-list, route, ...)."),
    ("hostname", "Set the FRR hostname."),
    (
        "frr",
        "FRR meta-directive (e.g. `frr version 10.2`, `frr defaults traditional`).",
    ),
    (
        "route-map",
        "Define a route-map: `route-map NAME permit|deny <seq>`.",
    ),
    (
        "prefix-list",
        "Define a prefix-list entry: `ip prefix-list NAME seq N permit|deny PREFIX`.",
    ),
];

const VYOS: &[(&str, &str)] = &[
    ("set", "Add/modify a configuration node."),
    ("delete", "Remove a configuration node."),
    ("commit", "Apply pending changes."),
    ("save", "Persist running config to disk."),
    ("show", "Display configuration."),
    ("interfaces", "Root node for interface configuration."),
    (
        "protocols",
        "Root node for routing protocols (bgp, ospf, static, ...).",
    ),
    (
        "firewall",
        "Root node for firewall rule-sets, groups, and global options.",
    ),
    (
        "system",
        "Root node for system-wide options (hostname, ntp, syslog, ...).",
    ),
    (
        "service",
        "Root node for services (ssh, https-api, dhcp-server, ...).",
    ),
    ("nat", "Root node for source/destination NAT rules."),
    (
        "vpn",
        "Root node for VPN configuration (ipsec, openvpn, wireguard).",
    ),
    ("vrf", "Root node for VRF definitions."),
    ("container", "Root node for system containers."),
    (
        "address",
        "Leaf: assign an IPv4/IPv6 address (CIDR notation).",
    ),
];

const MIKROTIK: &[(&str, &str)] = &[
    ("add", "Add a new entry under the current path."),
    ("set", "Modify an existing entry."),
    ("remove", "Remove entry/entries."),
    ("print", "Display entries."),
    ("export", "Export current path as RouterOS script."),
    ("find", "Filter expression: `[find name=foo]`."),
    ("/interface", "Root path for interface configuration."),
    (
        "/ip",
        "Root path for IPv4 (address, route, firewall, dhcp-server, ...).",
    ),
    ("/ipv6", "Root path for IPv6."),
    (
        "/routing",
        "Root path for routing protocols (bgp, ospf, rip, ...).",
    ),
    ("/system", "Root path for system options."),
    ("/queue", "Root path for QoS queues."),
    (
        "/container",
        "Root path for RouterOS containers (RouterOS 7+).",
    ),
    (
        "address",
        "Property: IPv4/IPv6 address (CIDR for /ip address, /ipv6 address).",
    ),
    ("gateway", "Property: next-hop address for /ip route."),
];

const BIRD: &[(&str, &str)] = &[
    (
        "protocol",
        "Define a protocol instance: `protocol <kind> [name] { ... }`.",
    ),
    (
        "filter",
        "Define a named filter expression: `filter NAME { ... }`.",
    ),
    (
        "function",
        "Define a reusable function used inside filters.",
    ),
    (
        "define",
        "Declare a named constant: `define NAME = value;`.",
    ),
    ("include", "Include another config file."),
    (
        "router",
        "Router identification, typically `router id <ipv4>;`.",
    ),
    ("bgp", "BGP protocol instance kind."),
    ("ospf", "OSPF protocol instance kind."),
    ("kernel", "Sync routes to/from the kernel routing table."),
    ("device", "Track interface state from the kernel."),
    ("static", "Statically configured routes."),
    (
        "pipe",
        "Connect two routing tables and filter between them.",
    ),
    ("babel", "Babel routing protocol."),
    ("rpki", "RPKI ROA validation."),
    ("ipv4", "IPv4 channel block inside a protocol."),
    ("ipv6", "IPv6 channel block inside a protocol."),
    (
        "import",
        "Channel direction: routes received from this protocol.",
    ),
    ("export", "Channel direction: routes sent to this protocol."),
    (
        "route",
        "Static route line: `route <prefix> via <next-hop>;`.",
    ),
];

const NFT: &[(&str, &str)] = &[
    (
        "table",
        "Top-level container: `table <family> <name> { ... }`.",
    ),
    (
        "chain",
        "Rule chain inside a table; can be a base chain with `type ... hook ...`.",
    ),
    ("rule", "Rule line; appended in order."),
    (
        "set",
        "Named set of values (atoms, intervals, concatenations).",
    ),
    (
        "map",
        "Named map: key -> value lookups for verdict or data.",
    ),
    ("type", "Chain base-type: filter, route, nat."),
    (
        "hook",
        "Netfilter hook: prerouting, input, forward, output, postrouting, ingress, egress.",
    ),
    (
        "priority",
        "Numeric priority; lower runs earlier within a hook.",
    ),
    (
        "policy",
        "Default verdict if no rule matches: accept | drop.",
    ),
    ("inet", "Family covering both ip and ip6."),
    ("ip", "IPv4 family."),
    ("ip6", "IPv6 family."),
    ("bridge", "Bridge family (L2 filtering)."),
    ("netdev", "Per-interface (egress/ingress) family."),
    ("accept", "Verdict: accept the packet."),
    ("drop", "Verdict: silently drop the packet."),
    ("reject", "Verdict: send ICMP reject."),
    ("ct", "Conntrack helper expression."),
    ("iifname", "Match on input interface name."),
    ("oifname", "Match on output interface name."),
];

const DEBIAN: &[(&str, &str)] = &[
    (
        "auto",
        "Bring this interface up at boot (`auto NAME [NAME...]`).",
    ),
    (
        "allow-hotplug",
        "Bring this interface up when the kernel detects a hotplug event.",
    ),
    (
        "iface",
        "Stanza header: `iface NAME FAMILY METHOD` (inet|inet6, static|dhcp|manual|loopback).",
    ),
    ("source", "Include another interfaces file or glob."),
    (
        "source-directory",
        "Include all files in the given directory.",
    ),
    (
        "address",
        "Static address for this iface (`address 10.0.0.1/24`).",
    ),
    ("gateway", "Default gateway for this iface."),
    (
        "netmask",
        "Legacy: dotted netmask. Prefer CIDR notation on `address`.",
    ),
    (
        "dns-nameservers",
        "Space-separated list of DNS servers (requires resolvconf).",
    ),
    ("pre-up", "Shell command run before bringing the iface up."),
    ("up", "Shell command run when bringing the iface up."),
    ("post-up", "Shell command run after the iface is up."),
    (
        "pre-down",
        "Shell command run before bringing the iface down.",
    ),
    ("down", "Shell command run when bringing the iface down."),
    ("post-down", "Shell command run after the iface is down."),
    ("mtu", "Link MTU in bytes."),
    ("inet", "Family: IPv4."),
    ("inet6", "Family: IPv6."),
    ("static", "Method: static configuration."),
    ("dhcp", "Method: DHCP."),
    (
        "manual",
        "Method: do not configure — useful as a placeholder.",
    ),
    ("loopback", "Method: loopback interface."),
];

const WIREGUARD: &[(&str, &str)] = &[
    ("Interface", "Local tunnel-interface settings."),
    ("Peer", "A remote peer (one block per peer)."),
    (
        "Address",
        "Address(es) assigned to this tunnel interface (CIDR list).",
    ),
    ("PrivateKey", "Base64 wg key (32 bytes → 44 chars)."),
    ("PublicKey", "Peer's base64 wg public key."),
    (
        "PresharedKey",
        "Optional shared secret added to the handshake.",
    ),
    ("ListenPort", "UDP port the interface listens on (1-65535)."),
    ("Endpoint", "Peer endpoint: `host:port` or `[v6]:port`."),
    (
        "AllowedIPs",
        "Comma-separated CIDR list of prefixes routed via this peer.",
    ),
    (
        "PersistentKeepalive",
        "Send a keepalive every N seconds (1-65535).",
    ),
    (
        "DNS",
        "DNS server(s) the wg-quick `up` script writes to resolv.conf.",
    ),
    ("MTU", "Optional link MTU; defaults to 1420."),
    (
        "Table",
        "Routing table to install routes into (`off` to skip).",
    ),
    (
        "PreUp",
        "Shell command run before bringing the interface up.",
    ),
    ("PostUp", "Shell command run after the interface is up."),
    (
        "PreDown",
        "Shell command run before bringing the interface down.",
    ),
    ("PostDown", "Shell command run after the interface is down."),
];

const HAPROXY: &[(&str, &str)] = &[
    (
        "global",
        "Process-wide settings (chroot, daemon, ssl defaults, tune.*).",
    ),
    (
        "defaults",
        "Defaults inherited by following frontend/backend/listen sections.",
    ),
    (
        "frontend",
        "Listening section: `frontend NAME { bind ..., default_backend ... }`.",
    ),
    ("backend", "Pool of `server` lines and routing rules."),
    ("listen", "Combined frontend + backend in one section."),
    ("peers", "Stick-table replication peers."),
    ("resolvers", "DNS resolver definitions."),
    (
        "bind",
        "Bind a listen address: `bind *:80`, `bind [::]:443 ssl crt ...`.",
    ),
    (
        "server",
        "Backend server: `server NAME host:port [options]`.",
    ),
    ("mode", "Proxy mode: http | tcp | health."),
    (
        "balance",
        "Load balancing algorithm (roundrobin, leastconn, source, ...).",
    ),
    (
        "timeout",
        "Per-stage timeout: `timeout connect 5s`, `timeout client 50s`, `timeout server 50s`.",
    ),
    (
        "option",
        "Toggle a named option (httplog, dontlognull, forwardfor, ...).",
    ),
    (
        "http-request",
        "Action on HTTP request (set-header, deny, redirect, ...).",
    ),
    ("http-response", "Action on HTTP response."),
    ("acl", "Define a named condition: `acl NAME criterion ...`."),
    ("use_backend", "Pick a backend when an ACL matches."),
    ("default_backend", "Fallback backend if no acl matches."),
    ("stats", "Stats page / unix socket configuration."),
    ("log", "Log target: `log host:port facility level`."),
];

const SYSCTL: &[(&str, &str)] = &[
    (
        "net.ipv4.ip_forward",
        "Enable IPv4 packet forwarding (0|1).",
    ),
    (
        "net.ipv6.conf.all.forwarding",
        "Enable IPv6 packet forwarding for all interfaces (0|1).",
    ),
    (
        "net.ipv4.conf.all.rp_filter",
        "Reverse-path filter mode: 0=off, 1=strict, 2=loose.",
    ),
    (
        "net.ipv4.tcp_congestion_control",
        "TCP CC algorithm: reno, cubic, bbr, ...",
    ),
    (
        "net.core.default_qdisc",
        "Default queueing discipline (e.g. fq, fq_codel, pfifo_fast).",
    ),
    (
        "net.core.rmem_max",
        "Maximum socket receive buffer size in bytes.",
    ),
    (
        "net.core.wmem_max",
        "Maximum socket send buffer size in bytes.",
    ),
    ("net.core.somaxconn", "Listen() backlog cap."),
    (
        "net.ipv4.tcp_fastopen",
        "TFO mode bitmask: 1=client, 2=server, 3=both.",
    ),
    (
        "net.ipv4.fib_multipath_hash_policy",
        "ECMP hash policy: 0=L3, 1=L3+L4, 2=L3+L4+inner.",
    ),
    (
        "net.ipv4.fib_multipath_use_neigh",
        "Use neighbour state for ECMP next-hop selection.",
    ),
    (
        "net.ipv4.tcp_rmem",
        "TCP recv buffer triplet: min default max.",
    ),
    (
        "net.ipv4.tcp_wmem",
        "TCP send buffer triplet: min default max.",
    ),
    (
        "kernel.panic",
        "Reboot after N seconds on kernel panic (0=never).",
    ),
];
