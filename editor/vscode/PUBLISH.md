# Publishing routels to the VS Code Marketplace

These are the exact steps to publish the extension. They are written for a
first-time publish; for republishes skip to [Republish](#republish).

`vsce` is the official Marketplace CLI: https://github.com/microsoft/vscode-vsce

## 0. Prerequisites

- The `routels` binary already released at the same version on GitHub
  (the README points users at the binary release).
- A clean working tree on `master` with the right `version` in
  `editor/vscode/package.json`.
- Node 18+ and `npx` available. `vsce` is invoked through `npx --yes @vscode/vsce`,
  no global install required.

## 1. Pick / create the publisher

The publisher in `package.json` is currently `rotko`. Confirm or change it:

- Browse the Marketplace publisher console: https://marketplace.visualstudio.com/manage
- Sign in with the Microsoft / Entra ID account that will own the listing.
- If `rotko` is not taken, click "New publisher", set:
  - **ID**: `rotko` (must match `publisher` in `package.json`)
  - **Name**: `Rotko Networks`
  - **Website**: `https://rotko.net`

If a different ID is chosen, update `publisher` in `package.json` and
recommit before publishing.

## 2. Mint a Personal Access Token (PAT)

The Marketplace authenticates `vsce` via an Azure DevOps PAT, not a
GitHub token.

1. Go to https://dev.azure.com and sign in with the same Microsoft account.
2. If prompted, create an Azure DevOps organisation. Any name is fine; it
   is only used as the PAT host.
3. Top right user menu, "Personal access tokens", "New Token".
4. Settings:
   - **Name**: `vsce-routels`
   - **Organization**: **All accessible organizations** (important: a
     single-org PAT will not work for Marketplace).
   - **Expiration**: pick the shortest sensible value. 90 days is fine.
   - **Scopes**: "Custom defined", then under **Marketplace** check
     **Manage** (which implies Acquire / Publish). No other scopes needed.
5. Copy the token once. It will not be shown again.



## 3. Log `vsce` in

From `editor/vscode/`:

```sh
npx --yes @vscode/vsce login rotko
# paste the PAT when prompted
```

Use whatever publisher ID matches `package.json`.

## 4. Sanity check the package

```sh
cd editor/vscode
npx tsc -p .
npx --yes @vscode/vsce package
# inspect the listing as it will appear
npx --yes @vscode/vsce ls
```

Expected: a `routels-<version>.vsix` around 400-500 KB, README.md and
CHANGELOG.md present in the listing, no `src/**`, `*.ts`, `*.vsix`, or
`PUBLISH.md` / `ICON-TODO.md` inside the package.

## 5. Publish

For the 0.1.0 release we have `"preview": true` in `package.json`, which
flags the listing as preview on the Marketplace card. That is enough, no
extra flag is needed.

```sh
cd editor/vscode
npx --yes @vscode/vsce publish
```

If you also want the extension to be installable from the **Pre-Release**
channel of VS Code (separate from the `preview` flag), publish with:

```sh
npx --yes @vscode/vsce publish --pre-release
```

Most network engineers will install from the stable channel, so the plain
publish is the right default. The `preview` flag in the manifest already
sets expectations.

The listing appears at:
`https://marketplace.visualstudio.com/items?itemName=rotko.routels`
(or `<publisher>.routels` if the publisher ID differs)

Indexing takes a few minutes; the listing is live immediately.

## Republish

For subsequent releases:

1. Bump `version` in `editor/vscode/package.json` (semver: `0.1.0` to
   `0.1.1` for fixes, `0.2.0` for features). The Marketplace will reject
   a re-upload of the same version.
2. Add a top entry to `editor/vscode/CHANGELOG.md`.
3. Commit, tag if you tag releases:
   ```sh
   git commit -am "vscode: 0.1.1"
   git tag vscode-v0.1.1
   ```
4. Build and publish:
   ```sh
   cd editor/vscode
   npx tsc -p .
   npx --yes @vscode/vsce publish
   ```

`vsce publish patch` / `minor` / `major` will also bump the version for you
and commit, but doing it by hand keeps the commit message style consistent
with the rest of the repo.

## Unpublishing / hiding

If something goes wrong:

```sh
npx --yes @vscode/vsce unpublish rotko.routels         # nuclear, frees the name
# or just hide the version
# (no CLI flag; use the Marketplace web console)
```

Avoid unpublish unless absolutely necessary; installed copies stop receiving
updates and the listing URL 404s.
