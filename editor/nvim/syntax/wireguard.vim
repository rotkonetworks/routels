if exists("b:current_syntax") | finish | endif

syn match  wgComment /^\s*[#;].*$/
syn match  wgSection /^\s*\[\(Interface\|Peer\)\].*$/

syn match  wgKey /^\s*\w\+\ze\s*=/
syn match  wgEq  /=/

" Order matters: IP4 must be defined before Prefix so the longer prefix
" pattern (defined later) wins. See `:help syn-priority`.
syn match  wgNumber  /\<\d\+\>/
syn match  wgIp4     /\<\d\{1,3\}\(\.\d\{1,3\}\)\{3\}\>/
syn match  wgIp6     /\<\([0-9a-fA-F]\{1,4\}\:\)\+[0-9a-fA-F:]\+\(\/\d\{1,3\}\)\?/
syn match  wgPrefix  /\<\d\{1,3\}\(\.\d\{1,3\}\)\{3\}\/\d\{1,2\}\>/
" base64 wg key heuristic: 43+ base64 chars then `=`
syn match  wgB64     /\<[A-Za-z0-9+\/]\{42,43\}=/

hi def link wgComment Comment
hi def link wgSection Statement
hi def link wgKey     Identifier
hi def link wgEq      Operator
hi def link wgNumber  Number
hi def link wgPrefix  Constant
hi def link wgIp4     Constant
hi def link wgIp6     Constant
hi def link wgB64     Special

let b:current_syntax = "wireguard"
