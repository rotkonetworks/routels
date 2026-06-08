# jul/17/2025 by RouterOS 7.15
/interface bridge
add name=br-lan
/ip address
add address=10.0.0.1/24 interface=br-lan network=10.0.0.0
/ip route
add dst-address=0.0.0.0/0 gateway=10.0.0.254
/routing bgp connection
add as=65001 name=peer1 remote.address=10.0.0.2 remote.as=65002
