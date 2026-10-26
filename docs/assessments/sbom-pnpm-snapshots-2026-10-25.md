# pnpm snapshot graph and Components recovery

`sbom-scan:scan` omitted 350 dependency links from an owned copy of the current
repository's actual dependency metadata. It reported a completed inventory
because it read importer and legacy package links while ignoring pnpm snapshots.
The official [pnpm v9 lockfile specification](https://github.com/pnpm/spec/blob/master/lockfile/9.0.md)
separates package metadata from the installed dependency graph in `snapshots`.

The parser now reads direct and optional snapshot dependencies, removes nested
peer suffixes from parent package names and preserves legacy package edges.
Existing source-qualified edge sorting removes duplicate links. A peer list
alone does not invent a dependency. The graph remains name-level; it does not
resolve installed versions, workspace aliases or version-specific relationships.

Present snapshot entries and dependency sections must be objects. Dependency
names must be nonempty and versions must be nonempty strings. Unsupported
shapes fail with the lockfile and cause, retain available capture inspection,
and publish no packages, graph or SBOM document. Existing stored results remain
unchanged. Source correction and a separate explicit rerun recover the inventory.
Public tool names, options, output schemas and maturity are unchanged.

## Actual metadata comparison

The probe copies only `package.json` and `pnpm-lock.yaml` to an owned temporary
target outside the checkout's ignored artifacts directory. It installs nothing
and executes no target package script. The hashes of both source files remain
unchanged. Shared headless dispatch uses explicit 4 MiB per-file and 8 MiB total
limits; both runs capture the same two files and 83,302 source bytes.

| Result | Before | After |
| --- | ---: | ---: |
| Components | 285 | 285 |
| Source-qualified dependency links | 77 | 427 |
| Missing independently parsed snapshot links | 350 | 0 |
| Previously recorded links lost | 0 | 0 |
| Duplicate SPDX package identifiers | 30 | 30 |

An independent Node YAML parse checks all 372 unique name-level edges across
259 snapshots. The actual graph gains exactly 350 links and retains every prior
link. This is evidence for the captured metadata, not complete repository
coverage or authenticated Git freshness.

## Verification and terminal review

The initial three prepared-dispatch regressions retain two failures and one
passing legacy-link check. After the fix, all nine inventory integration tests
pass. Seven malformed snapshot cases return failed results without package or
export claims. Core all-target Clippy, workspace build and formatting pass.
The CRAP-risk proxy passes over 200 changed production files against the incoming
main snapshot. Final repository summary evidence is recorded with this draft.

Sequential J369 uses an owned inert fixture and the unchanged audit harness.
It records 39 machine passes, zero failures and 32 authenticated live capture
pairs. Thirteen frozen programs and 6,664 source inputs remain unchanged during
execution. Native SHA-256:
`0ae8f76fb7d1fb823a77fc034cece186dc1afbacd0014ca770cf1ae490f972b6`.

Failure, correction and restart preserve exactly two completed results and one
failed result. Each success contains five source-qualified dependency links.
Components removes stale package claims on failure, distinguishes declared
constraints from observed versions after correction, and remains reachable
across 40x12, 60x20, 80x24, 96x89, 120x36 and 160x48. No-color restart contains
no color SGR codes. Narrow paging reaches the cause, recovery commands and all
components. There are no provider reservations, findings, phase attempts,
campaign jobs or executed package-script sentinel.

All three review prompts have agent State, Intent, Honesty and Craft answers.
Ten inspected PNGs replay captured ANSI cells with Menlo and a chosen dark
background; they are not OS screenshots. Raw exit 4 remains `REVIEW_REQUIRED`
with three formal operator judgments pending. Compact paging, subdued error
text, diagnostic chrome, singular-count wording and reference-level UX remain
open. No workflow or module-wide acceptance is inferred from this journey.

## Remaining export defect and evidence

The actual output still has 285 SPDX packages but only 255 distinct package
identifiers. The current identifier derives from sanitized ecosystem and name,
while components can differ by source, scope or version. The name-only lookup
also cannot establish version-specific relationship endpoints. This follow-up
does not qualify SPDX conformance or silently rewrite saved exports. That defect
requires a separate compatibility-aware correction and consumer checks.

Local evidence: `scripts/devex/artifacts/sbom-pnpm-20261025/`. Red and green
tests, actual before/after results, independent graph comparison and resource
checks are retained there. `native-attempt-1/` holds the frozen inputs, terminal
result, provenance checks, agent answers and cell replays. Subsequent audit
documentation is separate from the frozen product inputs.

There are zero new model requests. The existing sixteen-request experiment
allowance remains exhausted. No module is retired or promoted. The separately
sealed 100-file publication packet remains unchanged and this work is unstaged.
