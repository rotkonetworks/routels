if exists("b:current_syntax") | finish | endif

syn match  difComment /^\s*#.*$/
syn region difString  start=/"/ end=/"/

syn match  difNumber  /\<\d\+\>/
syn match  difPrefix  /\<\d\{1,3\}\(\.\d\{1,3\}\)\{3\}\/\d\{1,2\}\>/
syn match  difIp4     /\<\d\{1,3\}\(\.\d\{1,3\}\)\{3\}\>/
syn match  difIp6     /\<\([0-9a-fA-F]\{1,4\}\:\)\+[0-9a-fA-F:]\+\(\/\d\{1,3\}\)\?/

" Top-level stanza keywords (column 0)
syn keyword difStanza auto allow-auto allow-hotplug no-auto-down no-scripts
syn keyword difStanza iface mapping source source-directory rename

" Families / methods
syn keyword difFamily inet inet6 ipx can
syn keyword difMethod static dhcp manual loopback bootp ppp tunnel
syn keyword difMethod wvdial ipv4ll v4tunnel 6to4 wireguard

" Common option keys
syn keyword difOption address gateway netmask network broadcast pointopoint
syn keyword difOption hwaddress dns-nameservers dns-search dns-domain
syn keyword difOption pre-up post-up pre-down post-down up down
syn keyword difOption vlan-raw-device bond-master bond-mode bond-slaves
syn keyword difOption bridge-ports bridge-stp bridge-fd bridge-maxwait
syn keyword difOption mtu metric scope table

hi def link difComment Comment
hi def link difString  String
hi def link difNumber  Number
hi def link difPrefix  Constant
hi def link difIp4     Constant
hi def link difIp6     Constant
hi def link difStanza  Statement
hi def link difFamily  Type
hi def link difMethod  Type
hi def link difOption  Keyword

let b:current_syntax = "debinterfaces"
