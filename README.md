# routels

Fast offline linter and Language Server for network configuration files.
One binary, ten platforms, zero runtime dependencies on the device under config.

```
$ routels frr /etc/frr/frr.conf
/etc/frr/frr.conf:68:10: error: invalid network prefix `2001:db8:ix::/48` [FRR060]
```

## Supported platforms

| Subcommand     | Config kind                             | Comment style | Deep-check tool      |
|----------------|-----------------------------------------|---------------|----------------------|
| `eos`          | Arista EOS / cEOS running-config        | `!`           | needs cEOS container |
| `frr`          | FRR (vtysh)                             | `!` / `#`     | `vtysh -C -f`        |
| `vyos`         | VyOS native (set-style or curly auto)   | `#`           | needs VyOS container |
| `mikrotik`     | RouterOS `.rsc` export                  | `#`           | needs RouterOS       |
| `bird`         | BIRD 2.x                                | `#` / `//` / `/* */` | `bird -p -c`  |
| `nft`          | nftables `.nft` or iptables-save        | `#`           | `nft -c -f` / `iptables-restore --test` |
| `debian`       | `/etc/network/interfaces`               | `#`           | —                    |
| `wireguard`    | wg-quick INI                            | `#` / `;`     | `wg-quick strip`     |
| `haproxy`      | `haproxy.cfg`                           | `#`           | `haproxy -c -f`      |
| `sysctl`       | `sysctl.conf` and `sysctl.d/*.conf`     | `#`           | —                    |

## Install

```sh
cargo install --path . --locked        # from this repo
# or, once released:
cargo install routels --locked
```

Pre-built binaries: tag a release in this repo and GitHub Actions produces
tarballs for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, and
`aarch64-apple-darwin`. See `.github/workflows/release.yml`.

## CLI

```sh
routels frr file1.conf file2.conf      # lint files (or `-` for stdin)
routels --format json frr file.conf    # machine-readable per-line JSON
routels --format sarif frr file.conf   # SARIF 2.1.0 for GitHub code scanning
routels --deep frr file.conf           # also shell out to vtysh -C -f
routels --severity-min warning ...     # drop hints/info
routels --ignore-code FRR071 ...       # silence specific codes (repeatable)
routels --dedup ...                    # collapse duplicate diagnostics
routels list-rules                     # all 113 diagnostic codes by platform
routels explain HAP060                 # describe a single code
routels lsp                            # speak LSP on stdio (for editors)
```

Exit status: `0` clean, `1` errors/warnings emitted, `2` invocation error.
`--errors-only` makes warnings non-fatal for CI.

## Editors

### Neovim

Drop this into `~/.config/nvim/lua/plugins/routels.lua` (LazyVim users — any
plugin manager works since it returns an empty spec table and registers
autocmds at load time):

```lua
vim.opt.runtimepath:prepend("/path/to/routels/editor/nvim")

-- LSP autostart on routels filetypes
local fts = { "eos","frr","vyos","routeros","bird","nftables",
              "debinterfaces","wireguard","haproxy","sysctl" }
vim.api.nvim_create_autocmd("FileType", {
  pattern = fts,
  callback = function(args)
    if vim.fn.executable("routels") == 0 then return end
    local existing = vim.lsp.get_clients({ name = "routels" })
    if #existing > 0 then
      vim.lsp.buf_attach_client(args.buf, existing[1].id); return
    end
    vim.lsp.start({
      name = "routels",
      cmd = { "routels", "lsp" },
      root_dir = vim.fs.dirname(vim.api.nvim_buf_get_name(args.buf)),
      filetypes = fts,
    })
  end,
})

-- Tree-sitter highlighting for FRR (parser.so shipped at editor/nvim/parser/)
vim.api.nvim_create_autocmd("FileType", {
  pattern = "frr",
  callback = function(args) pcall(vim.treesitter.start, args.buf, "frr") end,
})

return {}
```

What you get:
- Diagnostics on every keystroke (didChange)
- Hover docs (`K`) on platform keywords
- Completion (`<C-x><C-o>` or `nvim-cmp` LSP source) for keywords
- Inlay hints: ASN class (private/public/doc), well-known port names, IPv4 prefix size
- Quick-fix code actions for FRR053 (insert exit-address-family) and EOS001 (tabs → spaces)
- Filetype detection via shipped `ftdetect/` (covers wg0*.conf, sysctl.d/, /haproxy/, etc.)
- Syntax highlighting: tree-sitter for FRR, regex `.vim` for the other 9 platforms

### VS Code

Once published on the Marketplace:

```sh
code --install-extension rotko.routels
```

From a downloaded `.vsix` (GitHub release, or built locally):

```sh
code --install-extension /path/to/routels-0.1.0.vsix
```

Or run from source without packaging:

```sh
code --extensionDevelopmentPath=/path/to/routels/editor/vscode
```

The extension activates on any of the 10 language IDs and spawns
`routels lsp` via `vscode-languageclient`. Set `routels.path` in user settings
if the binary is not on `$PATH`. See `editor/vscode/` for the extension
source and `editor/vscode/PUBLISH.md` for release steps.

## CI integration

### pre-commit

Add to `.pre-commit-config.yaml`:

```yaml
- repo: https://github.com/rotkonetworks/routels
  rev: v0.1.0
  hooks:
    - id: routels-frr
    - id: routels-bird
    - id: routels-haproxy
    # ...etc — see .pre-commit-hooks.yaml for all 10
```

### GitHub Actions code scanning (SARIF)

```yaml
- run: routels --format sarif frr configs/*.conf > routels.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: routels.sarif }
```

## How linting works

Each platform is a self-contained module under `src/` that walks the file
line-by-line and emits `Diagnostic` records. There are three layers a
diagnostic can come from:

1. **Structural** (default) — pure offline checks: prefix validity, ASN
   range, brace/bracket balance, section grammar, cross-references within
   the same file.
2. **Filter pipeline** — diagnostics flow through composable filters
   (`--severity-min`, `--ignore-code`, `--dedup`) before emission.
3. **Deep** (`--deep`) — shells out to the platform's own validator for
   semantic checks (`vtysh -C`, `nft -c`, `haproxy -c -f`, …) and folds
   the output into the diagnostic stream.

The LSP server (`routels lsp`) keeps an open-document store and reuses the
same per-platform linter on every `didChange`. Hover and completion are
backed by static per-platform keyword tables; inlay hints and code actions
are pattern-matched on the same diagnostic stream.

## Adding a new platform

1. `src/<platform>.rs` exporting `pub fn lint(file: &str, src: &str) -> Vec<Diagnostic>`.
2. Wire the subcommand in `src/main.rs` (`Cmd::Foo`), add to `deep::Platform`, `lsp::Platform`, `lsp_docs::Kind`.
3. Add hover/completion table to `src/lsp_docs.rs`.
4. Add rule codes to `src/rules.rs`.
5. Add fixtures in `tests/fixtures/<platform>/{good,bad}.*` plus integration tests.
6. Inline `#[cfg(test)] mod tests` with red-green pairs for every rule.
7. Ship editor pieces: `editor/nvim/syntax/<ft>.vim`, ftdetect pattern, VS Code language contribution in `editor/vscode/package.json`.

## Tests

```sh
cargo test --release --locked
```

98 unit (per-rule red-green + filter pipeline + property tests on IP
validators) + 27 integration (full binary invocation) = 125 tests.

Sweep against real configs:
```sh
for f in path/to/configs/*.conf; do routels frr "$f"; done
```

## Project layout

```
src/                       Rust source
  main.rs                  CLI dispatch
  diag.rs                  Diagnostic type + IP validators + test helpers
  filter.rs                Filter pipeline (severity-min, ignore-code, dedup)
  rules.rs                 Registry of all diagnostic codes (--list-rules / --explain)
  deep.rs                  --deep mode (shells out to vtysh -C / nft -c / ...)
  lsp.rs                   tower-lsp server: didOpen/didChange/diagnostics,
                           hover, completion, inlay hints, code actions
  lsp_docs.rs              Per-platform hover/completion keyword tables
  {eos,frr,vyos,mikrotik,bird,nft,debian,wireguard,haproxy,sysctl}.rs

tests/fixtures/<p>/        Per-platform good.cfg + bad.cfg
tests/integration.rs       Spawns the binary, asserts on output

editor/nvim/               nvim runtime (syntax/, ftdetect/, parser/, queries/)
editor/vscode/             VS Code extension (TypeScript + LSP client)
tree-sitter/frr/           grammar.js + generated parser for FRR

mason/packages/routels/    Mason registry package.yaml stub
.pre-commit-hooks.yaml     pre-commit hook definitions (one per platform)
.github/workflows/         CI (test + clippy) and release (cross-compile)
```

## License

Dual-licensed under MIT (`LICENSE-MIT`) or Apache-2.0 (`LICENSE-APACHE`),
at your option.
