if exists("b:current_syntax") | finish | endif

" Comments
syn match frrComment /^\s*!.*$/
syn match frrComment /^\s*#.*$/

" Strings
syn region frrString start=/"/ end=/"/ contains=@Spell

" Numbers
syn match frrNumber /\<\d\+\>/

" Order matters: IP4 must be defined before Prefix so the longer prefix
" pattern (defined later) wins. See `:help syn-priority`.
syn match frrIp4 /\<\d\{1,3\}\(\.\d\{1,3\}\)\{3\}\>/
" IPv6 (coarse): hex groups with `:`, optional `/N`
syn match frrIp6 /\<\([0-9a-fA-F]\{1,4\}\:\)\+[0-9a-fA-F:]\+\(\/\d\{1,3\}\)\?/
syn match frrPrefix /\<\d\{1,3\}\(\.\d\{1,3\}\)\{3\}\/\d\{1,2\}\>/

" Top-level / section openers
syn keyword frrSection router interface vrf address-family exit-address-family
syn keyword frrSection route-map prefix-list ip-prefix-list as-path-access-list
syn keyword frrSection community-list extcommunity-list large-community-list
syn keyword frrSection bfd line vty

" Directives
syn keyword frrDirective frr hostname log service password enable
syn keyword frrDirective version defaults integrated-vtysh-config

" Routing-protocol kinds
syn keyword frrProtocol bgp ospf ospf6 isis rip ripng babel pim ldp eigrp nhrp

" BGP statements / keywords
syn keyword frrBgp neighbor network remote-as peer-group description
syn keyword frrBgp activate next-hop-self soft-reconfiguration update-source
syn keyword frrBgp route-map prefix-list distribute-list ebgp-multihop
syn keyword frrBgp send-community route-reflector-client multihop allowas-in
syn keyword frrBgp maximum-prefix advertisement-interval timers fall-over

" Verbs
syn keyword frrVerb permit deny match set redistribute import export
syn keyword frrVerb call continue exit goto on-match next

" Address-family modifiers
syn keyword frrFamily ipv4 ipv6 unicast multicast vpn evpn flowspec labeled-unicast l2vpn

hi def link frrComment   Comment
hi def link frrString    String
hi def link frrNumber    Number
hi def link frrPrefix    Constant
hi def link frrIp4       Constant
hi def link frrIp6       Constant
hi def link frrSection   Statement
hi def link frrDirective PreProc
hi def link frrProtocol  Type
hi def link frrBgp       Keyword
hi def link frrVerb      Operator
hi def link frrFamily    Identifier

let b:current_syntax = "frr"
