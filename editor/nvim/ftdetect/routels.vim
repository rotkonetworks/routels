" Filetype detection for routels-supported config formats.
" Loaded automatically when the routels editor runtime is on &runtimepath.
"
" Note: we use `set filetype=` (not `setfiletype`) where neovim's built-in
" filetype.lua would otherwise win and assign generic `cfg`/`conf`.

" --- WireGuard ---
au BufRead,BufNewFile wg?.conf,wg??.conf  set filetype=wireguard
au BufRead,BufNewFile */wireguard/*.conf  set filetype=wireguard

" --- HAproxy ---
" .cfg gets `cfg` by default in nvim, so we must use `set filetype=` to override.
au BufRead,BufNewFile haproxy.cfg,*-haproxy.cfg set filetype=haproxy
au BufRead,BufNewFile */haproxy/*.cfg          set filetype=haproxy
au BufRead,BufNewFile haproxy.conf,*-haproxy.conf set filetype=haproxy
au BufRead,BufNewFile */haproxy/*.conf         set filetype=haproxy

" --- sysctl ---
au BufRead,BufNewFile sysctl.conf,*/sysctl.d/*.conf set filetype=sysctl

" --- Debian /etc/network/interfaces ---
au BufRead,BufNewFile interfaces,*/interfaces.d/*       set filetype=debinterfaces
au BufRead,BufNewFile */backup/interfaces/*.conf        set filetype=debinterfaces
au BufRead,BufNewFile */generated/*-interfaces.conf     set filetype=debinterfaces

" --- BIRD ---
au BufRead,BufNewFile bird.conf,bird2.conf       set filetype=bird
au BufRead,BufNewFile */bird/*.conf,*-bird.conf  set filetype=bird

" --- FRR / vtysh ---
au BufRead,BufNewFile vtysh.conf,frr.conf        set filetype=frr
" common containerlab / upstream layout: /upstream/<peer>.conf is FRR
au BufRead,BufNewFile */upstream/*.conf          set filetype=frr
" containerlab vyos directory holds vtysh-style configs we treat as FRR
au BufRead,BufNewFile */vyos/vyos*.conf          set filetype=frr

" --- nftables ---
au BufRead,BufNewFile *.nft,nftables.conf,*/nftables.d/*.nft set filetype=nftables

" --- MikroTik RouterOS ---
au BufRead,BufNewFile *.rsc  set filetype=routeros

" --- Arista EOS ---
" *.cfg gets `cfg` by default; treat known EOS-shaped paths as eos.
au BufRead,BufNewFile */ceos/*.cfg,*/arista/*.cfg,*/eos/*.cfg set filetype=eos

" --- VyOS (set-style or curly-style flat configs) ---
au BufRead,BufNewFile */vyos/*.set,*.vyos        set filetype=vyos

" --- Content-based fallback for .conf files: sniff for FRR / EOS markers ---
function! s:RoutelsSniffConf() abort
  if did_filetype() | return | endif
  let l:lines = getline(1, 50)
  for l:ln in l:lines
    if l:ln =~# '^\s*frr version' || l:ln =~# '^\s*frr defaults'
      setfiletype frr
      return
    endif
    if l:ln =~# '^\s*!\s*Command:' || l:ln =~# 'daemon TerminAttr'
      setfiletype eos
      return
    endif
  endfor
endfunction
au BufRead *.conf,*.cfg call s:RoutelsSniffConf()
