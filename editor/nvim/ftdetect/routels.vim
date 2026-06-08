" Filetype detection for routels-supported config formats.
" Loaded automatically when the routels editor runtime is on &runtimepath.

" --- WireGuard ---
au BufRead,BufNewFile wg?.conf,wg??.conf  setfiletype wireguard
au BufRead,BufNewFile */wireguard/*.conf  setfiletype wireguard

" --- HAproxy ---
au BufRead,BufNewFile haproxy.cfg,*-haproxy.cfg setfiletype haproxy
au BufRead,BufNewFile */haproxy/*.cfg          setfiletype haproxy

" --- sysctl ---
au BufRead,BufNewFile sysctl.conf,*/sysctl.d/*.conf setfiletype sysctl

" --- Debian /etc/network/interfaces ---
au BufRead,BufNewFile interfaces,*/interfaces.d/*       setfiletype debinterfaces
au BufRead,BufNewFile */backup/interfaces/*.conf        setfiletype debinterfaces
au BufRead,BufNewFile */generated/*-interfaces.conf     setfiletype debinterfaces

" --- BIRD ---
au BufRead,BufNewFile bird.conf,bird2.conf       setfiletype bird
au BufRead,BufNewFile */bird/*.conf,*-bird.conf  setfiletype bird

" --- FRR / vtysh ---
au BufRead,BufNewFile vtysh.conf,frr.conf        setfiletype frr

" --- nftables ---
au BufRead,BufNewFile *.nft,nftables.conf,*/nftables.d/*.nft setfiletype nftables

" --- MikroTik RouterOS ---
au BufRead,BufNewFile *.rsc  setfiletype routeros
