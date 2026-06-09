# Icon TODO (before publish)

The Marketplace listing surfaces extensions much more prominently when they
ship a 128x128 icon. We have not commissioned one yet.

## What to add

1. Drop the file at `editor/vscode/icon.png` (PNG, exactly 128x128, opaque).
2. Add `"icon": "icon.png"` to `package.json` (just below `qna`).
3. Make sure `.vscodeignore` does NOT exclude `icon.png` (current ignore
   list does not, so nothing to change there).
4. Bump the `version` in `package.json` (e.g. `0.1.0` to `0.1.1`) and add
   a CHANGELOG entry, then republish.

## Design notes

- Concept: stylized cable / port silhouette, or an `{}` glyph fused with a
  router chassis line. Avoid the generic "globe + magnifying glass" linter
  look.
- Background should match `galleryBanner.color` in `package.json` (`#0b1220`)
  so the icon blends with the listing header.
- Theme: dark. Keep the silhouette light or accent-coloured so it reads on
  both Marketplace cards (light bg) and the VS Code sidebar (dark bg).
- No LLM-generated art. Commission it or draw it.

## Quick verify after adding

```sh
cd editor/vscode
npx --yes @vscode/vsce package
unzip -l routels-*.vsix | grep icon.png   # should list extension/icon.png
```
