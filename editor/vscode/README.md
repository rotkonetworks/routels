# routels: network config linter and LSP

Offline linter and language server for 10 network configuration formats.
One Rust binary serves both the CLI and the LSP. No agent, no daemon, no
network calls.

This extension is a thin client around `routels lsp`. The Rust binary has to
be installed separately (see [Install](#install)).

## Supported formats

| Language id     | Detects                                                  | Comment style        |
|-----------------|----------------------------------------------------------|----------------------|
| `eos`           | Arista EOS / cEOS running-config                         | `!`                  |
| `frr`           | FRR (vtysh.conf, frr.conf)                               | `!` / `#`            |
| `vyos`          | VyOS native (set-style or curly form)                    | `#`                  |
| `routeros`      | MikroTik RouterOS `.rsc` exports                         | `#`                  |
| `bird`          | BIRD 2.x                                                 | `#` / `//` / `/* */` |
| `nftables`      | nftables `.nft` and iptables-save dumps                  | `#`                  |
| `haproxy`       | `haproxy.cfg`                                            | `#`                  |
| `wireguard`     | wg-quick INI (`wg0.conf`, etc.)                          | `#` / `;`            |
| `sysctl`        | `sysctl.conf`, `sysctl.d/*.conf`                         | `#`                  |
| `debinterfaces` | Debian `/etc/network/interfaces`                         | `#`                  |

Filename patterns are wired up in the extension so detection is automatic
for the usual paths (`**/frr.conf`, `**/haproxy/*.cfg`, `**/wg*.conf`, …).
You can also set the language manually in the VS Code language picker.

## What you get

- **Syntax highlighting** for all 10 formats (TextMate grammars, standard
  scopes — works with any theme).
- **Diagnostics** on every keystroke: prefix validity, ASN range, brace and
  section grammar, family/hook validity, cross-references inside the file
  (route-map, prefix-list, ACL, backend, peer names).
- **Hover** docs on platform keywords.
- **Completion** for keywords inside the matching section.
- **Inlay hints**: ASN class (private / public / documentation), well-known
  port names next to numeric ports, IPv4 prefix size in addresses.
- **Quick-fix code actions** where a fix is unambiguous (e.g. insert a
  missing `exit-address-family`, convert leading tabs to spaces in EOS).

## Demo

```
$ routels frr /etc/frr/frr.conf
/etc/frr/frr.conf:68:10: error: invalid network prefix `2001:db8:ix::/48` [FRR060]
/etc/frr/frr.conf:91:1:  warning: route-map `RM-UPSTREAM-IN` referenced but not defined [FRR034]
```

In the editor the same diagnostics show inline with squigglies and appear
in the Problems panel.

> Screenshots will be added in a future release.

## Install

1. **Install the routels binary.** The extension shells out to it.

   ```sh
   # from source
   cargo install --path . --locked   # inside a clone of rotkonetworks/routels
   # or from a release tarball
   # https://github.com/rotkonetworks/routels/releases
   ```

   Confirm it is on `$PATH`:

   ```sh
   routels --version
   ```

2. **Install the extension** from the Marketplace:

   ```sh
   code --install-extension rotko.routels
   ```

   Or grab the `.vsix` from a GitHub release and `code --install-extension routels-<version>.vsix`.

## Configuration

| Setting                  | Default     | Effect                                                              |
|--------------------------|-------------|---------------------------------------------------------------------|
| `routels.path`           | `routels`   | Path to the `routels` binary. Set this if it is not on `$PATH`.     |
| `routels.trace.server`   | `off`       | LSP trace verbosity. `messages` or `verbose` for debugging.          |

## CLI

The same binary works as a standalone linter:

```sh
routels frr file1.conf file2.conf       # lint files (or `-` for stdin)
routels --format sarif frr file.conf    # SARIF 2.1.0 for GitHub code scanning
routels --deep frr file.conf            # also shell out to vtysh -C -f
routels list-rules                      # show every diagnostic code
routels explain HAP060                  # describe one code
```

`--deep` shells out to the platform's own validator where one exists
(`vtysh -C`, `nft -c`, `haproxy -c -f`, `bird -p -c`, `wg-quick strip`).

## Links

- Source, issues, full docs: https://github.com/rotkonetworks/routels
- Diagnostic codes: `routels list-rules` or `routels explain <code>`
- Neovim setup: see the repo README

## License

Dual-licensed under MIT or Apache-2.0, at your option.
