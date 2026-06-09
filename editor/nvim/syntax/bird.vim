if exists("b:current_syntax") | finish | endif

syn region birdComment start=+/\*+ end=+\*/+
syn match  birdComment /#.*$/
syn match  birdComment /\/\/.*$/

syn region birdString  start=/"/ end=/"/ skip=/\\"/

" Order matters: later definitions override earlier when starting at the same
" column (`:help syn-priority`). Define the bare number first, then IPs,
" then the prefix form so `1.2.3.4/24` lands as birdPrefix, not birdIp4.
syn match  birdNumber  /\<\d\+\>/
syn match  birdIp4     /\<\d\{1,3\}\(\.\d\{1,3\}\)\{3\}\>/
syn match  birdIp6     /\<\([0-9a-fA-F]\{1,4\}\:\)\+[0-9a-fA-F:]\+\(\/\d\{1,3\}+\=\)\?/
" BIRD allows `prefix+` to mean "this prefix and longer"; treat the trailing `+` as optional literal.
syn match  birdPrefix  /\<\d\{1,3\}\(\.\d\{1,3\}\)\{3\}\/\d\{1,2\}+\=/

" Top-level keywords
syn keyword birdKeyword protocol filter function define include router table
syn keyword birdKeyword template attribute roa4 roa6 timeformat log
syn keyword birdKeyword debug latency interpret port

" Protocol kinds
syn keyword birdProtocol bgp ospf rip static direct device kernel pipe babel
syn keyword birdProtocol radv bfd mrt perf rpki l3vpn

" Channels / families
syn keyword birdFamily ipv4 ipv6 vpn4 vpn6 roa4 roa6 flow4 flow6 mpls

" Statements
syn keyword birdStmt local neighbor as import export route via unreachable
syn keyword birdStmt blackhole prohibit recursive multipath weight from
syn keyword birdStmt accept reject return print case if then else for do

" Filter operators
syn keyword birdOp all none in not and or eq ne lt le gt ge

" Punctuation
syn match birdDelim /[;{}]/

hi def link birdComment  Comment
hi def link birdString   String
hi def link birdNumber   Number
hi def link birdPrefix   Constant
hi def link birdIp4      Constant
hi def link birdIp6      Constant
hi def link birdKeyword  Statement
hi def link birdProtocol Type
hi def link birdFamily   Identifier
hi def link birdStmt     Keyword
hi def link birdOp       Operator
hi def link birdDelim    Delimiter

let b:current_syntax = "bird"
