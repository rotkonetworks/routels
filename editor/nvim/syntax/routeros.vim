if exists("b:current_syntax") | finish | endif

syn match  rosComment /^\s*#.*$/
syn region rosString  start=/"/ end=/"/ skip=/\\"/

" Numbers / time-spans like 30s, 5m, 1h, 2d
syn match  rosNumber  /\<\d\+\(\.\d\+\)\?\(s\|m\|h\|d\|w\)\?\>/
syn match  rosPrefix  /\<\d\{1,3\}\(\.\d\{1,3\}\)\{3\}\/\d\{1,2\}\>/
syn match  rosIp4     /\<\d\{1,3\}\(\.\d\{1,3\}\)\{3\}\>/
syn match  rosIp6     /\<\([0-9a-fA-F]\{1,4\}\:\)\+[0-9a-fA-F:]\+\(\/\d\{1,3\}\)\?/
syn match  rosMac     /\<\([0-9a-fA-F]\{2\}\:\)\{5\}[0-9a-fA-F]\{2\}\>/

" Path lines start with `/`
syn match  rosPath    /^\s*\/[A-Za-z][A-Za-z0-9 \-/]*/

" Verbs
syn keyword rosVerb add set remove print export import find comment enable disable move

" key=value highlighting (key part)
syn match  rosKey     /\<[a-z][a-z0-9-]*\>\ze=/

" Common RouterOS keywords
syn keyword rosBool yes no true false default disabled enabled
syn keyword rosKeyword interface bridge ip ipv6 routing firewall queue address gateway
syn keyword rosKeyword distance dst-address src-address from-pool comment name
syn keyword rosKeyword interface-list interface-list-member chain action

" Find expression
syn region rosFind start=/\[/ end=/\]/

hi def link rosComment Comment
hi def link rosString  String
hi def link rosNumber  Number
hi def link rosPrefix  Constant
hi def link rosIp4     Constant
hi def link rosIp6     Constant
hi def link rosMac     Constant
hi def link rosPath    Statement
hi def link rosVerb    Operator
hi def link rosKey     Identifier
hi def link rosBool    Boolean
hi def link rosKeyword Keyword
hi def link rosFind    PreProc

let b:current_syntax = "routeros"
