// Tree-sitter grammar for FRR (vtysh) configs.
//
// FRR is line-oriented with implicit nesting via indentation, plus explicit
// closers (`exit-address-family`, `exit`, `end`). This grammar treats the
// file as a sequence of lines and classifies each line so highlighting picks
// out the right tokens. It does NOT try to build a deep semantic tree —
// routels already does that.

const KEYWORDS = [
  'router', 'interface', 'vrf', 'address-family', 'exit-address-family',
  'exit', 'end', 'neighbor', 'network', 'redistribute',
  'route-map', 'prefix-list', 'as-path-access-list', 'community-list',
  'extcommunity-list', 'large-community-list',
  'frr', 'hostname', 'log', 'service', 'password', 'enable',
  'version', 'defaults', 'integrated-vtysh-config',
  'ip', 'ipv6', 'no', 'shutdown', 'description',
  'remote-as', 'peer-group', 'activate', 'next-hop-self',
  'soft-reconfiguration', 'update-source', 'ebgp-multihop',
  'send-community', 'route-reflector-client', 'allowas-in',
  'maximum-prefix', 'advertisement-interval', 'timers',
  'fall-over', 'permit', 'deny', 'match', 'set', 'call',
  'continue', 'goto', 'on-match', 'unicast', 'multicast', 'vpn',
  'evpn', 'flowspec', 'labeled-unicast', 'l2vpn',
  'bgp', 'ospf', 'ospf6', 'isis', 'rip', 'ripng',
  'babel', 'pim', 'ldp', 'eigrp', 'nhrp',
  'seq', 'le', 'ge', 'address', 'route', 'route6',
];

module.exports = grammar({
  name: 'frr',
  extras: $ => [/[ \t]+/],
  word: $ => $.identifier,

  rules: {
    source_file: $ => repeat(choice($._line, $._eol)),
    _eol: _ => /\n/,
    _line: $ => choice(
      $.comment,
      seq($._tokens, /\n/),
    ),
    _tokens: $ => repeat1(choice(
      $.keyword,
      $.ipv4_cidr,
      $.ipv4,
      $.ipv6_cidr,
      $.ipv6,
      $.number,
      $.string,
      $.identifier,
      $.punct,
    )),
    comment: _ => /[!#][^\n]*/,
    string: _ => /"[^"\n]*"/,
    // Order matters: more-specific patterns before more-generic ones.
    ipv4_cidr: _ => /\d{1,3}(\.\d{1,3}){3}\/\d{1,3}/,
    ipv4: _ => /\d{1,3}(\.\d{1,3}){3}/,
    ipv6_cidr: _ => /[0-9a-fA-F:]+:[0-9a-fA-F:]*\/\d{1,3}/,
    ipv6: _ => /[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}/,
    number: _ => /-?\d+/,
    punct: _ => /[\/,;]/,
    keyword: _ => choice(...KEYWORDS),
    identifier: _ => /[A-Za-z_][A-Za-z0-9_\-]*/,
  },
});
