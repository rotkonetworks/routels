if exists("b:current_syntax") | finish | endif

syn match  eosComment /^\s*!.*$/
syn region eosString  start=/"/ end=/"/

syn match  eosNumber  /\<\d\+\>/
syn match  eosPrefix  /\<\d\{1,3\}\(\.\d\{1,3\}\)\{3\}\/\d\{1,2\}\>/
syn match  eosIp4     /\<\d\{1,3\}\(\.\d\{1,3\}\)\{3\}\>/
syn match  eosIp6     /\<\([0-9a-fA-F]\{1,4\}\:\)\+[0-9a-fA-F:]\+\(\/\d\{1,3\}\)\?/

" Section openers / context-changing keywords
syn keyword eosSection interface router vrf line vlan management
syn keyword eosSection address-family exit-address-family policy-map class-map

" Interface kinds (often start the iface name on `interface X`)
syn match   eosIfaceKind /\<Ethernet\d/
syn match   eosIfaceKind /\<Loopback\d/
syn match   eosIfaceKind /\<Management\d/
syn match   eosIfaceKind /\<Port-Channel\d/
syn match   eosIfaceKind /\<Vlan\d/
syn match   eosIfaceKind /\<Tunnel\d/
syn match   eosIfaceKind /\<Vxlan\d/
syn match   eosIfaceKind /\<Recirc-Channel\d/
syn match   eosIfaceKind /\<Fabric\d/

" Top-level directives
syn keyword eosDirective hostname daemon transceiver no spanning-tree
syn keyword eosDirective service username role aaa logging dot1x ntp
syn keyword eosDirective snmp-server clock-period boot-config event-handler

" BGP / routing
syn keyword eosProtocol bgp ospf ospfv3 isis rip
syn keyword eosBgp neighbor network remote-as peer-group activate
syn keyword eosBgp redistribute next-hop-self route-map ebgp-multihop
syn keyword eosBgp send-community soft-reconfiguration update-source
syn keyword eosBgp maximum-routes timers

" Modifiers / verbs
syn keyword eosVerb permit deny match set redistribute no shutdown
syn keyword eosVerb description switchport mode access trunk
syn keyword eosFamily ipv4 ipv6 unicast multicast evpn vpn-ipv4

hi def link eosComment   Comment
hi def link eosString    String
hi def link eosNumber    Number
hi def link eosPrefix    Constant
hi def link eosIp4       Constant
hi def link eosIp6       Constant
hi def link eosSection   Statement
hi def link eosIfaceKind Type
hi def link eosDirective PreProc
hi def link eosProtocol  Type
hi def link eosBgp       Keyword
hi def link eosVerb      Operator
hi def link eosFamily    Identifier

let b:current_syntax = "eos"
