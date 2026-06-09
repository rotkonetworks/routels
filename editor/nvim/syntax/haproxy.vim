if exists("b:current_syntax") | finish | endif

syn match  hapComment /^\s*#.*$/
syn region hapString  start=/"/ end=/"/

" Order matters: IP4 must be defined before Prefix so the longer prefix
" pattern (defined later) wins. See `:help syn-priority`.
syn match  hapNumber  /\<\d\+\(ms\|s\|m\|h\|d\)\?\>/
syn match  hapIp4     /\<\d\{1,3\}\(\.\d\{1,3\}\)\{3\}\>/
syn match  hapIp6     /\<\([0-9a-fA-F]\{1,4\}\:\)\+[0-9a-fA-F:]\+\(\/\d\{1,3\}\)\?/
syn match  hapPrefix  /\<\d\{1,3\}\(\.\d\{1,3\}\)\{3\}\/\d\{1,2\}\>/

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
syn keyword hapDirective nbthread nbproc cpu-map tune compression
syn keyword hapDirective errorfile errorfiles default-server resolvers nameserver
syn keyword hapDirective http-reuse http-check tcp-check http-send-name-header
" tune.* and other dotted directives need a match
syn match   hapDirective /\<tune\.[a-z0-9._-]\+\>/

" Modes / options
syn keyword hapMode http tcp health
syn keyword hapBalance roundrobin static-rr leastconn first source uri url_param hdr random

" Verbs / actions
syn keyword hapVerb if unless allow deny tarpit reject auth redirect return
syn keyword hapVerb check inter rise fall backup disabled enabled
syn keyword hapVerb set-header del-header add-header replace-header set-var
syn keyword hapVerb set-uri set-path set-query track-sc0 track-sc1 track-sc2
syn keyword hapVerb send-proxy send-proxy-v2 ssl crt alpn verify ca-file

" ACL / fetch sample functions (common ones)
syn keyword hapAcl src dst path url method host status var sc_http_req_rate
syn keyword hapAcl hdr hdr_beg hdr_end hdr_dom hdr_sub hdr_reg hdr_dir
syn keyword hapAcl path_beg path_end path_dir path_sub path_reg
syn keyword hapAcl url_beg url_end url_dir url_sub url_reg
syn keyword hapAcl req.hdr res.hdr base query nbsrv srv_conn srv_queue
syn keyword hapAcl algo content-type lf-string scheme code

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
hi def link hapAcl       Function

let b:current_syntax = "haproxy"
