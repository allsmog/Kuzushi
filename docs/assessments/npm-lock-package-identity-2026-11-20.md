# The npm SBOM named packages after the directory above them (2026-11-20)

## The defect

`sbom:scan` reads `package-lock.json` / `npm-shrinkwrap.json` twice: once in
`scan/engines/sbom_scan/npm_lock.rs` for the component list, and once in
`scan/engines/sbom_scan/dependency_graph.rs` for the dependency edges. Each
carried its own copy of `package_name_from_lock_key` and `scoped_package_name`,
and both read the lockfile v2/v3 `packages` key as if it spelled a package
name. It does not: the key is the directory the tarball was unpacked into.

Both copies stripped one leading `node_modules/`, then took `@scope/name` from
the front if what remained began with `@`, and otherwise the last `/` segment.
Three readings npm actually writes break that:

- **A nested install.** `node_modules/@babel/core/node_modules/@babel/helper-compilation-targets`
  strips to `@babel/core/node_modules/@babel/helper-compilation-targets`, which
  begins with `@`, so the front-two-segment rule returned **`@babel/core`** —
  the package whose install tree the entry sits *under*. The nested package's
  version was attributed to it, and the nested package vanished from the SBOM.
  Where the outer package is unscoped,
  `node_modules/express/node_modules/@babel/plugin-syntax-jsx` does not begin
  with `@`, so the last-segment rule dropped the scope and returned
  **`plugin-syntax-jsx`**.
- **An alias.** `node_modules/legacy-lodash` with `"name": "lodash"` is how npm
  records `npm:lodash@4.17.21`. The declared name is the only place the
  installed package appears; both readers ignored it and reported the alias.
- **A workspace link.** `packages/app` with `"name": "@my/app"` matched no rule,
  and here the two copies disagreed: the component list reported `app` (last
  segment) while the edge reader reported `packages/app` (the whole key), so
  the graph pointed at a node the component list did not contain.

## What that cost

Against a lockfile holding all four shapes, the components `sbom:scan`
reported were:

```
@babel/core     7.0.0   pkg:npm/%40babel/core@7.0.0
@babel/core     7.1.0   pkg:npm/%40babel/core@7.1.0   <- @babel/helper-compilation-targets
plugin          7.2.0   pkg:npm/plugin@7.2.0          <- @babel/plugin-syntax-jsx
myalias         2.0.0   pkg:npm/myalias@2.0.0         <- real-package
app             0.1.0   pkg:npm/app@0.1.0             <- @my/app
```

The component name is the whole of a component's identity downstream: it is the
purl in `report.components`, in the CycloneDX export, in the SPDX export, and
the node name in `report.dependencies` and the TUI component stack. So the
second row is a coordinate for a version `@babel/core` never published, emitted
as an ordinary component with no marker that it was inferred; `plugin` and
`app` are unscoped names that match no registry package, so a downstream
advisory check against the exported SBOM finds nothing for them; and the
packages actually installed — `@babel/helper-compilation-targets`,
`@babel/plugin-syntax-jsx`, `real-package`, `@my/app` — are absent from an
artifact whose purpose is to be complete. Nested installs are where version
conflicts land, which is exactly where an advisory is most likely to apply.

## Why this ranked first

It is wrong output in a shipped artifact, not a missing feature: an exported
SBOM both omits installed packages and asserts a version for a package that
never had it. Nothing else found this run was both incorrect and user-visible.
It is also the duplicated-parsing guardrail in AGENTS.md biting exactly as that
rule predicts — two copies of one policy, already diverged on workspace keys.

## The fix

`scan/engines/sbom_scan/npm_lock_key.rs` owns the policy once and both readers
call it. A declared `"name"` wins, because npm writes it exactly when the key
does not spell the name. Otherwise the name is everything after the *last*
`node_modules/` — an npm package name is either `name` or `@scope/name`, so
that remainder is the whole name and needs no further splitting — and a key
outside an install tree is a workspace directory, named by its last segment.
The root key `""` still yields no component and still appears as `root` in the
graph.

## Follow-up found in review

Canonicalizing the component name alone left the alias's *incoming* edge
pointing at the alias: `export_graph::resolve_edge` matches a target against
component names within the same manifest, so `root -> legacy-lodash` no longer
reached the component now named `lodash`, and the relationship was disclosed as
omitted instead of exported. The target side is the same read — a spec of
`npm:<name>@<range>` installs `<name>` under the declared key, so there the key
is a directory name and only the spec holds the package — so
`npm_lock_key::dependency_target` now resolves it, keyed off the last `@` so a
scope's leading `@` and a version-less alias both survive. A non-alias spec is a
version range and passes through untouched.

## What is not claimed

- Only the lockfile v2/v3 `packages` map is corrected. The v1 `dependencies`
  map is keyed by name already, and its own alias spelling
  (`"version": "npm:real@1.0.0"`) is untouched.
- `npm_package_json.rs` still names a `package.json` alias dependency after the
  alias, in both its components and its edges. Those agree with each other, so
  the export graph resolves them and nothing is dropped; correcting that name is
  its own change.
- `packages[""].name` is still not used; the root stays `root` in the graph, as
  its existing tests require.
- No other ecosystem's reader was changed. pnpm, yarn and bun keys were read
  while ranking this and none showed the same confusion, but they were not
  re-derived from their format specs.

## Verified

- The three new `sbom_scan` tests fail against the prior code with exactly the
  names in the table above and pass after.
- `cargo test -p kuzushi-core --lib sbom_ --locked`.
- `pnpm verify:quick:summary`.
