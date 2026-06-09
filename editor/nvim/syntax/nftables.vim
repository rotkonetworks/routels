if exists("b:current_syntax") | finish | endif

syn region nftComment start=/#/ end=/$/ contains=@Spell
syn region nftString  start=/"/ end=/"/

" Order matters: IP4 must be defined before Prefix so the longer prefix
" pattern (defined later) wins. See `:help syn-priority`.
syn match  nftNumber  /\<\d\+\>/
syn match  nftIp4     /\<\d\{1,3\}\(\.\d\{1,3\}\)\{3\}\>/
syn match  nftIp6     /\<\([0-9a-fA-F]\{1,4\}\:\)\+[0-9a-fA-F:]\+\(\/\d\{1,3\}\)\?/
syn match  nftMac     /\<\([0-9a-fA-F]\{2\}\:\)\{5\}[0-9a-fA-F]\{2\}\>/
syn match  nftPrefix  /\<\d\{1,3\}\(\.\d\{1,3\}\)\{3\}\/\d\{1,2\}\>/

" Section/structural keywords
syn keyword nftStructure table chain set map flowtable include define
syn keyword nftStructure type hook priority policy device flags handle

" Families
syn keyword nftFamily inet ip ip6 arp bridge netdev

" Hooks
syn keyword nftHook prerouting input forward output postrouting ingress egress

" Verdicts
syn keyword nftVerdict accept drop reject return queue continue jump goto

" Common match keywords
syn keyword nftMatch iif iifname oif oifname meta mark ct state status saddr daddr
syn keyword nftMatch sport dport protocol tcp udp icmp icmpv6 tcp option fib
syn keyword nftMatch counter log limit numgen update timeout iiftype oiftype

" Operators
syn keyword nftOp and or xor not in vmap

hi def link nftComment   Comment
hi def link nftString    String
hi def link nftNumber    Number
hi def link nftPrefix    Constant
hi def link nftIp4       Constant
hi def link nftIp6       Constant
hi def link nftMac       Constant
hi def link nftStructure Statement
hi def link nftFamily    Type
hi def link nftHook      Identifier
hi def link nftVerdict   Keyword
hi def link nftMatch     Function
hi def link nftOp        Operator

let b:current_syntax = "nftables"
