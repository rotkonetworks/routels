if exists("b:current_syntax") | finish | endif

syn match  sysctlComment /^\s*[#;].*$/

" key (dotted), optional leading `-`
syn match  sysctlKey /^\s*-\?[a-zA-Z][a-zA-Z0-9._-]*\ze\s*=/
syn match  sysctlEq  /=/

syn match  sysctlNumber /\<-\?\d\+\>/
syn match  sysctlBool   /\<\(true\|false\|yes\|no\)\>/

" Common subsystem prefixes get an accent
syn match  sysctlSys /\<\(net\|kernel\|vm\|fs\|dev\|user\|abi\|debug\|crypto\)\ze\./

hi def link sysctlComment Comment
hi def link sysctlKey     Identifier
hi def link sysctlEq      Operator
hi def link sysctlNumber  Number
hi def link sysctlBool    Boolean
hi def link sysctlSys     Type

let b:current_syntax = "sysctl"
