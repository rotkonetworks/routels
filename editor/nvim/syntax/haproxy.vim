if exists("b:current_syntax") | finish | endif

syn match  hapComment /^\s*#.*$/
syn region hapString  start=/"/ end=/"/

syn match  hapNumber  /\<\d\+\(ms\|s\|m\|h\|d\)\?\>/
syn match  hapPrefix  /\<\d\{1,3\}\(\.\d\{1,3\}\)\{3\}\/\d\{1,2\}\>/
syn match  hapIp4     /\<\d\{1,3\}\(\.\d\{1,3\}\)\{3\}\>/
syn match  hapIp6     /\<\([0-9a-fA-F]\{1,4\}\:\)\+[0-9a-fA-F:]\+\(\/\d\{1,3\}\)\?/

" Section keywords (column 0)
syn keyword hapSection global defaults frontend backend listen peers resolvers
syn keyword hapSection cache program userlist ring http-errors mailers fcgi-app

" Common directives
syn keyword hapDirective bind server use_backend default_backend acl mode
syn keyword hapDirective option timeout balance http-request http-response
syn keyword hapDirective tcp-request tcp-response capture log redirect rewrite
syn keyword hapDirective stick-table stick rate-limit retries maxconn
syn keyword hapDirective monitor-uri monitor-fail monitor-net description
syn keyword hapDirective stats no chroot pidfile user group daemon
syn keyword hapDirective ssl-default-bind-ciphers ssl-default-bind-options
syn keyword hapDirective ssl-default-server-ciphers ssl-default-server-options
syn keyword hapDirective nbthread nbproc cpu-map tune tune.bufsize

" Modes / options
syn keyword hapMode http tcp health
syn keyword hapBalance roundrobin static-rr leastconn first source uri url_param hdr random

" Verbs / actions
syn keyword hapVerb if unless allow deny tarpit reject auth redirect
syn keyword hapVerb check inter rise fall backup disabled enabled

hi def link hapComment   Comment
hi def link hapString    String
hi def link hapNumber    Number
hi def link hapPrefix    Constant
hi def link hapIp4       Constant
hi def link hapIp6       Constant
hi def link hapSection   Statement
hi def link hapDirective Keyword
hi def link hapMode      Type
hi def link hapBalance   Identifier
hi def link hapVerb      Operator

let b:current_syntax = "haproxy"
