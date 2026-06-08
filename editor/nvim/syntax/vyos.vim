if exists("b:current_syntax") | finish | endif

syn match  vyosComment /^\s*#.*$/
syn region vyosString  start=/'/ end=/'/ skip=/\\\\\\'/
syn region vyosString  start=/"/ end=/"/ skip=/\\\\\\"/

syn match  vyosNumber  /\<\d\+\>/
syn match  vyosPrefix  /\<\d\{1,3\}\(\.\d\{1,3\}\)\{3\}\/\d\{1,2\}\>/
syn match  vyosIp4     /\<\d\{1,3\}\(\.\d\{1,3\}\)\{3\}\>/
syn match  vyosIp6     /\<\([0-9a-fA-F]\{1,4\}\:\)\+[0-9a-fA-F:]\+\(\/\d\{1,3\}\)\?/

" Top-level verbs (set-style)
syn keyword vyosVerb set delete commit save show comment edit top up exit load discard compare run

" Root nodes
syn keyword vyosRoot interfaces protocols firewall system service nat nat66 vpn
syn keyword vyosRoot policy qos-policy traffic-policy high-availability pki
syn keyword vyosRoot container load-balancing vrf

" Common subnodes / properties
syn keyword vyosKey ethernet bridge vlan loopback dummy wireguard openvpn pppoe
syn keyword vyosKey address description mtu hw-id ip ipv6 route route6 next-hop
syn keyword vyosKey bgp ospf ospfv3 rip static system-as neighbor remote-as
syn keyword vyosKey peer-group source-address ebgp-multihop update-source
syn keyword vyosKey host-name name-server domain-name time-zone ntp

" Braces (curly form)
syn match vyosBrace /[{}]/

hi def link vyosComment Comment
hi def link vyosString  String
hi def link vyosNumber  Number
hi def link vyosPrefix  Constant
hi def link vyosIp4     Constant
hi def link vyosIp6     Constant
hi def link vyosVerb    Statement
hi def link vyosRoot    Type
hi def link vyosKey     Keyword
hi def link vyosBrace   Delimiter

let b:current_syntax = "vyos"
