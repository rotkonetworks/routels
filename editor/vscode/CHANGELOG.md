# Changelog

All notable changes to the `routels` VS Code extension are documented here.
The extension version tracks the `routels` binary version.

## 0.1.0 (2026-06-10)

Initial public release.

- LSP client wrapping `routels lsp` for 10 network configuration formats:
  Arista EOS, FRR (vtysh), VyOS, MikroTik RouterOS, BIRD, nftables, HAproxy,
  WireGuard, sysctl, Debian `/etc/network/interfaces`.
- Filename-pattern detection for the usual paths (`frr.conf`, `bird.conf`,
  `haproxy.cfg`, `wg*.conf`, `sysctl.d/*.conf`, RouterOS `.rsc`, etc.),
  including `.tpl` template variants (`*.cfg.tpl`, `*.conf.tpl`, …).
- TextMate syntax highlighting for all 10 languages, ported from the nvim
  syntax files.
- Comment / bracket / auto-closing pair configuration per language.
- Settings: `routels.path` (binary location) and `routels.trace.server`
  (LSP trace verbosity).
- Marked `preview` while the rule set and per-platform coverage stabilize.
