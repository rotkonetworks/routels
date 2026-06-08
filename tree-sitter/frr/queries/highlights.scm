; Tree-sitter highlight queries for FRR.

(comment) @comment
(string) @string
(number) @number
(ipv4) @constant
(ipv4_cidr) @constant
(ipv6) @constant
(ipv6_cidr) @constant
(punct) @punctuation.delimiter

(keyword) @keyword

; More specific roles than plain keyword: highlight section openers + sub-keywords differently.
((keyword) @keyword.directive
  (#any-of? @keyword.directive "router" "interface" "vrf" "address-family"
                                "route-map" "prefix-list" "as-path-access-list"))

((keyword) @keyword.return
  (#any-of? @keyword.return "exit" "exit-address-family" "end"))

((keyword) @type
  (#any-of? @type "bgp" "ospf" "ospf6" "isis" "rip" "ripng" "babel" "pim"))

((keyword) @attribute
  (#any-of? @attribute "ipv4" "ipv6" "unicast" "multicast" "vpn" "evpn"
                       "flowspec" "labeled-unicast" "l2vpn"))

((keyword) @function
  (#any-of? @function "neighbor" "network" "redistribute" "match" "set"
                      "permit" "deny" "address"))

((keyword) @preproc
  (#any-of? @preproc "frr" "hostname" "log" "service" "version" "defaults"))

(identifier) @variable
